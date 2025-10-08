from pathlib import Path
import os
from typing import Optional
import logging
try:
    # if python-dotenv is installed and not already loaded, this makes .env values available
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

logger = logging.getLogger("logbot.llm")
if not logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(h)
    logger.setLevel(logging.INFO)


class LLMAdapter:
    """Adapter supporting OpenAI, Perplexity (pplx- keys) and transformers fallback.

    Behavior:
    - If `provider` parameter is passed to constructor, prefer it.
    - Otherwise, detect from environment variables: PERPLEXITY_API_KEY, OPENAI_API_KEY, HF_MODEL.
    - If an OpenAI-looking key starts with 'pplx-' we will NOT call OpenAI; instead try Perplexity HTTP call if PERPLEXITY_API_KEY set.
    """

    def __init__(self, provider: Optional[str] = None):
        self.provider = provider or os.getenv("LLM_PROVIDER")
        self._client = None

    def _detect_provider_from_env(self):
        # explicit PERPLEXITY key
        pplx = os.getenv("PERPLEXITY_API_KEY")
        gemini = os.getenv("GEMINI_API_KEY")
        deepseek = os.getenv("DEEPSEEK_API_KEY")
        openai_key = os.getenv("OPENAI_API_KEY")
        if self.provider:
            return self.provider
        # Prefer explicit Gemini/Deepseek keys if present
        if gemini:
            return "gemini"
        if deepseek:
            return "deepseek"
        if pplx:
            return "perplexity"
        if openai_key and openai_key.startswith("pplx-"):
            # user put a Perplexity key into OPENAI_API_KEY by mistake
            logger.info("Detected OPENAI_API_KEY that looks like a Perplexity key (starts with 'pplx-'). Will not call OpenAI.")
            # prefer explicit PERPLEXITY if available
            if pplx:
                return "perplexity"
            return "transformers"
        if openai_key:
            return "openai"
        # fallback to transformers if HF_MODEL set
        if os.getenv("HF_MODEL"):
            return "transformers"
        return "transformers"

    def _init_openai(self):
        try:
            import openai
        except Exception:
            raise RuntimeError("openai package not installed")
        key = os.getenv("OPENAI_API_KEY")
        if not key:
            raise RuntimeError("OPENAI_API_KEY not set")
        # assign key to client
        try:
            # openai library v2+ uses openai.api_key, older still accepts
            openai.api_key = key
        except Exception:
            pass
        self._client = openai

    def _init_perplexity(self):
        # Try to use the official Perplexity Python SDK if available, otherwise fall back to HTTP.
        key = os.getenv("PERPLEXITY_API_KEY") or os.getenv("OPENAI_API_KEY")
        if not key:
            raise RuntimeError("PERPLEXITY_API_KEY not set")
        try:
            # prefer official SDK
            import perplexity
            # the SDK may pick up the key from env; try to instantiate
            try:
                client = perplexity.Perplexity(api_key=key)
            except Exception:
                try:
                    client = perplexity.Perplexity()
                except Exception:
                    client = None
            if client is not None:
                self._client = {"type": "perplexity", "mode": "sdk", "client": client}
                return
        except Exception:
            # SDK not installed or failed; fall back to requests-based HTTP
            pass
        try:
            import requests
        except Exception:
            raise RuntimeError("requests package not installed; cannot call Perplexity API")
        # store minimal client info for HTTP fallback
        self._client = {"type": "perplexity", "mode": "http", "key": key, "requests": requests}

    def _init_gemini(self):
        # Best-effort HTTP wrapper for Gemini-like keys. Client libraries differ; implement conservative POST.
        key = os.getenv("GEMINI_API_KEY")
        if not key:
            raise RuntimeError("GEMINI_API_KEY not set")
        try:
            import requests
        except Exception:
            raise RuntimeError("requests package not installed; cannot call Gemini API")
        self._client = {"type": "gemini", "key": key, "requests": requests}

    def _init_deepseek(self):
        # Best-effort HTTP wrapper for Deepseek (a hypothetical provider). Implement conservative POST.
        key = os.getenv("DEEPSEEK_API_KEY")
        if not key:
            raise RuntimeError("DEEPSEEK_API_KEY not set")
        try:
            import requests
        except Exception:
            raise RuntimeError("requests package not installed; cannot call Deepseek API")
        self._client = {"type": "deepseek", "key": key, "requests": requests}

    def _init_transformers(self):
        try:
            from transformers import pipeline
        except Exception:
            raise RuntimeError("transformers not installed")
        # use a lightweight local model if available
        model = os.getenv("HF_MODEL", "gpt2")
        self._client = pipeline("text-generation", model=model)

    def ensure(self):
        if self._client is not None:
            return
        chosen = self._detect_provider_from_env()
        logger.info("LLMAdapter chosen provider: %s", chosen)
        self.provider = chosen
        if chosen == "openai":
            self._init_openai()
            return
        if chosen == "perplexity":
            try:
                self._init_perplexity()
                return
            except Exception as e:
                logger.warning("Perplexity init failed: %s; falling back to transformers", e)
                # continue to transformers
        if chosen == "gemini":
            try:
                self._init_gemini()
                return
            except Exception as e:
                logger.warning("Gemini init failed: %s; falling back to transformers", e)
        if chosen == "deepseek":
            try:
                self._init_deepseek()
                return
            except Exception as e:
                logger.warning("Deepseek init failed: %s; falling back to transformers", e)
        # default fallback
        self._init_transformers()

    def _call_perplexity(self, prompt: str, max_tokens: int = 256) -> str:
        info = self._client
        if not info or info.get("type") != "perplexity":
            raise RuntimeError("Perplexity client not initialized")
        mode = info.get("mode")
        if mode == "sdk":
            client = info.get("client")
            # best-effort SDK usage: try chat.completions.create then search.create
            try:
                # Prefer chat completions (OpenAI-compatible shape)
                # prefer explicit Perplexity model
                model = os.getenv("PERPLEXITY_MODEL")
                if not model:
                    # avoid using OpenAI-only legacy completion names like text-davinci-003 for Perplexity
                    openai_engine = os.getenv("OPENAI_ENGINE")
                    if openai_engine and not openai_engine.startswith("text-"):
                        model = openai_engine
                    else:
                        model = "sonar-pro"
                if hasattr(client, "chat") and hasattr(client.chat, "completions") and hasattr(client.chat.completions, "create"):
                    try:
                        resp = client.chat.completions.create(model=model, messages=[{"role": "user", "content": prompt}])
                    except Exception:
                        # some SDK variants accept positional prompt
                        resp = client.chat.completions.create(messages=[{"role": "user", "content": prompt}], model=model)
                    # extract text: resp.choices[0].message.content
                    try:
                        choices = getattr(resp, "choices", None) or (resp.get("choices") if isinstance(resp, dict) else None)
                        if choices:
                            choice = choices[0]
                            # support object or dict shapes
                            if hasattr(choice, "message"):
                                m = choice.message
                                content = m.content if hasattr(m, "content") else (m.get("content") if isinstance(m, dict) else None)
                                if content:
                                    return content.strip()
                            # dict-like
                            if isinstance(choice, dict):
                                msg = choice.get("message") or choice.get("text")
                                if isinstance(msg, dict):
                                    cont = msg.get("content") or msg.get("text")
                                    if cont:
                                        return cont.strip()
                                if isinstance(msg, str):
                                    return msg.strip()
                    except Exception:
                        pass
                    # fallback to string of resp
                    return str(resp).strip()
                # fallback to search
                if hasattr(client, "search") and hasattr(client.search, "create"):
                    resp = client.search.create(query=[prompt])
                    # try resp.results
                    results = getattr(resp, "results", None) or (resp.get("results") if isinstance(resp, dict) else None)
                    if results:
                        parts = []
                        for r in results:
                            title = getattr(r, "title", None) or (r.get("title") if isinstance(r, dict) else None)
                            url = getattr(r, "url", None) or (r.get("url") if isinstance(r, dict) else None)
                            if title:
                                parts.append(f"{title}: {url or ''}")
                        if parts:
                            return "\n".join(parts)
                    return str(resp)
            except Exception as e:
                logger.exception("Perplexity SDK call failed: %s", e)
                raise
        # HTTP fallback (conservative)
        requests = info["requests"]
        key = info["key"]
        url = os.getenv("PERPLEXITY_API_URL", "https://api.perplexity.ai/chat")
        headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
        payload = {"query": prompt, "top_n": 1}
        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            # try best-effort extraction
            if isinstance(data, dict):
                # common shapes: {'answer': '...'} or {'response': '...'} or {'data': {'text': '...'}}
                for k in ("answer", "response", "text"):
                    if k in data and isinstance(data[k], str):
                        return data[k].strip()
                # nested
                d = data.get("data") or data.get("result")
                if isinstance(d, dict):
                    for k in ("answer", "response", "text"):
                        if k in d and isinstance(d[k], str):
                            return d[k].strip()
            # fallback to raw text
            return resp.text.strip()
        except Exception as e:
            logger.exception("Perplexity API call failed: %s", e)
            raise

    def _call_gemini(self, prompt: str, max_tokens: int = 256) -> str:
        info = self._client
        if not info or info.get("type") != "gemini":
            raise RuntimeError("Gemini client not initialized")
        requests = info["requests"]
        key = info["key"]
        # Conservative best-effort POST to a Gemini-like endpoint. Users should supply GEMINI_API_URL if different.
        url = os.getenv("GEMINI_API_URL", "https://api.gemini.google.com/v1/chat")
        headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
        payload = {"prompt": prompt, "max_tokens": max_tokens}
        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            # best-effort extraction
            if isinstance(data, dict):
                for k in ("answer", "response", "text", "content"):
                    if k in data and isinstance(data[k], str):
                        return data[k].strip()
                d = data.get("data") or data.get("result")
                if isinstance(d, dict):
                    for k in ("answer", "response", "text", "content"):
                        if k in d and isinstance(d[k], str):
                            return d[k].strip()
            return resp.text.strip()
        except Exception as e:
            logger.exception("Gemini API call failed: %s", e)
            raise

    def _call_deepseek(self, prompt: str, max_tokens: int = 256) -> str:
        info = self._client
        if not info or info.get("type") != "deepseek":
            raise RuntimeError("Deepseek client not initialized")
        requests = info["requests"]
        key = info["key"]
        url = os.getenv("DEEPLSEEK_API_URL", "https://api.deepseek.ai/v1/generate")
        headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
        payload = {"input": prompt, "max_tokens": max_tokens}
        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, dict):
                for k in ("answer", "text", "response", "output"):
                    if k in data and isinstance(data[k], str):
                        return data[k].strip()
                d = data.get("data") or data.get("result")
                if isinstance(d, dict):
                    for k in ("answer", "text", "response", "output"):
                        if k in d and isinstance(d[k], str):
                            return d[k].strip()
            return resp.text.strip()
        except Exception as e:
            logger.exception("Deepseek API call failed: %s", e)
            raise

    def generate(self, prompt: str, max_tokens: int = 256) -> str:
        self.ensure()
        if self.provider == "openai":
            # Use modern OpenAI ChatCompletion API when available
            try:
                engine = os.getenv("OPENAI_ENGINE", "gpt-3.5-turbo")
                # The OpenAI Python package has multiple shapes across versions; try new client then fallbacks.
                OpenAIClass = getattr(self._client, "OpenAI", None)
                if OpenAIClass:
                    client = OpenAIClass()
                    # new-style
                    try:
                        resp = client.chat.completions.create(
                            model=engine,
                            messages=[{"role": "user", "content": prompt}],
                            max_tokens=max_tokens,
                            temperature=0,
                        )
                        if resp and getattr(resp, "choices", None):
                            choice = resp.choices[0]
                            msg = None
                            if hasattr(choice, "message"):
                                m = choice.message
                                if isinstance(m, dict):
                                    msg = m.get("content")
                                else:
                                    msg = getattr(m, "content", None)
                            else:
                                msg = getattr(choice, "text", None)
                            return (msg or "").strip()
                    except Exception:
                        # fallthrough to other shapes
                        pass
                # module-level ChatCompletion
                if hasattr(self._client, "ChatCompletion"):
                    resp = self._client.ChatCompletion.create(
                        model=engine,
                        messages=[{"role": "user", "content": prompt}],
                        max_tokens=max_tokens,
                        temperature=0,
                    )
                    if resp and getattr(resp, "choices", None):
                        choice = resp.choices[0]
                        if hasattr(choice, "message"):
                            m = choice.message
                            if isinstance(m, dict):
                                return (m.get("content") or "").strip()
                            else:
                                return (getattr(m, "content", "") or "").strip()
                # fallback to legacy completions
                if hasattr(self._client, "Completion"):
                    resp = self._client.Completion.create(
                        engine=os.getenv("OPENAI_ENGINE", "text-davinci-003"),
                        prompt=prompt,
                        max_tokens=max_tokens,
                        temperature=0,
                    )
                    return resp.choices[0].text.strip()
            except Exception as e:
                logger.exception("OpenAI call failed: %s", e)
                raise
            raise RuntimeError("OpenAI client did not return a usable response")
        elif self.provider == "perplexity":
            try:
                return self._call_perplexity(prompt, max_tokens=max_tokens)
            except Exception:
                # bubble up to caller after logging
                raise
        elif self.provider == "gemini":
            return self._call_gemini(prompt, max_tokens=max_tokens)
        elif self.provider == "deepseek":
            return self._call_deepseek(prompt, max_tokens=max_tokens)
        else:
            # transformers pipeline
            out = self._client(prompt, max_length=max_tokens + len(prompt))
            # transformers pipeline returns list of dicts
            return out[0]["generated_text"].strip()
