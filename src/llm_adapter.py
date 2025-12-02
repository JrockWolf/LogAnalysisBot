from pathlib import Path
import os
from typing import Optional, Dict
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
    - Optional `api_keys` dict lets callers supply per-request secrets without mutating process env.
    - Optional `model_overrides` dict lets callers hint the model/engine per provider.
    - Otherwise, detect from environment variables: PERPLEXITY_API_KEY, OPENAI_API_KEY, HF_MODEL.
    - If an OpenAI-looking key starts with 'pplx-' we will NOT call OpenAI; instead try Perplexity HTTP call if PERPLEXITY_API_KEY set.
    """

    def __init__(
        self,
        provider: Optional[str] = None,
        api_keys: Optional[Dict[str, str]] = None,
        model_overrides: Optional[Dict[str, str]] = None,
    ):
        normalized = provider
        if normalized in (None, "", "auto"):
            normalized = None
        self.requested_provider = provider
        self.provider = normalized or os.getenv("LLM_PROVIDER")
        self._client = None
        self.api_keys = api_keys or {}
        self.model_overrides = model_overrides or {}
        self.active_model: Optional[str] = None

    def _detect_provider_from_env(self):
        # explicit PERPLEXITY key
        pplx = self.api_keys.get("perplexity") or os.getenv("PERPLEXITY_API_KEY")
        gemini = self.api_keys.get("gemini") or os.getenv("GEMINI_API_KEY")
        deepseek = self.api_keys.get("deepseek") or os.getenv("DEEPSEEK_API_KEY")
        openai_key = self.api_keys.get("openai") or os.getenv("OPENAI_API_KEY")
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
        key = self.api_keys.get("openai") or os.getenv("OPENAI_API_KEY")
        if not key:
            raise RuntimeError("OPENAI_API_KEY not set")
        # assign key to client
        try:
            # openai library v2+ uses openai.api_key, older still accepts
            openai.api_key = key
        except Exception:
            pass
        self._client = openai
        engine = self.model_overrides.get("openai") or os.getenv("OPENAI_ENGINE")
        if engine:
            self.active_model = engine

    def _init_perplexity(self):
        # Try to use the official Perplexity Python SDK if available, otherwise fall back to HTTP.
        key = (
            self.api_keys.get("perplexity")
            or os.getenv("PERPLEXITY_API_KEY")
            or self.api_keys.get("openai")
            or os.getenv("OPENAI_API_KEY")
        )
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
                self.active_model = self.model_overrides.get("perplexity") or os.getenv("PERPLEXITY_MODEL")
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
        self.active_model = self.model_overrides.get("perplexity") or os.getenv("PERPLEXITY_MODEL")

    def _init_gemini(self):
        # Lightweight wrapper for the Google Generative Language REST API (Gemini models).
        key = (
            self.api_keys.get("gemini")
            or os.getenv("GEMINI_API_KEY")
            or os.getenv("GOOGLE_API_KEY")
            or os.getenv("GOOGLE_AI_API_KEY")
        )
        if not key:
            raise RuntimeError("GEMINI_API_KEY not set")
        raw_model = self.model_overrides.get("gemini") or os.getenv("GEMINI_MODEL", "models/gemini-flash-latest")
        raw_model = raw_model.strip()
        http_model = raw_model if raw_model.startswith("models/") else f"models/{raw_model}"
        sdk_model = raw_model.split("/", 1)[1] if raw_model.startswith("models/") else raw_model
        base_url = os.getenv("GEMINI_API_URL", "https://generativelanguage.googleapis.com/v1beta").rstrip("/")

        # Prefer official Google SDK if available so newer models/endpoints work automatically.
        try:
            import google.generativeai as genai

            try:
                genai.configure(api_key=key)
                self._client = {
                    "type": "gemini",
                    "mode": "sdk",
                    "sdk": genai,
                    "key": key,
                    "model": http_model,
                    "sdk_model": sdk_model,
                    "base_url": base_url,
                }
                self.active_model = http_model
                return
            except Exception as sdk_err:
                logger.warning("Gemini SDK configure failed: %s; falling back to HTTP", sdk_err)
        except Exception:
            logger.debug("Gemini SDK not available", exc_info=True)

        try:
            import requests
        except Exception:
            raise RuntimeError("requests package not installed; cannot call Gemini API")
        self._client = {
            "type": "gemini",
            "mode": "http",
            "key": key,
            "requests": requests,
            "base_url": base_url,
            "model": http_model,
        }
        self.active_model = http_model

    def _init_deepseek(self):
        # Best-effort HTTP wrapper for Deepseek (a hypothetical provider). Implement conservative POST.
        key = self.api_keys.get("deepseek") or os.getenv("DEEPSEEK_API_KEY")
        if not key:
            raise RuntimeError("DEEPSEEK_API_KEY not set")
        try:
            import requests
        except Exception:
            raise RuntimeError("requests package not installed; cannot call Deepseek API")
        self._client = {"type": "deepseek", "key": key, "requests": requests}
        self.active_model = self.model_overrides.get("deepseek") or os.getenv("DEEPSEEK_MODEL")

    def _init_transformers(self):
        try:
            from transformers import pipeline
        except Exception:
            raise RuntimeError("transformers not installed")
        # use a lightweight local model if available
        model = self.model_overrides.get("transformers") or os.getenv("HF_MODEL", "gpt2")
        self._client = pipeline("text-generation", model=model)
        self.active_model = model

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
                model = self.model_overrides.get("perplexity") or os.getenv("PERPLEXITY_MODEL")
                if not model:
                    # avoid using OpenAI-only legacy completion names like text-davinci-003 for Perplexity
                    openai_engine = os.getenv("OPENAI_ENGINE")
                    if openai_engine and not openai_engine.startswith("text-"):
                        model = openai_engine
                    else:
                        model = "sonar-pro"
                self.active_model = model
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
        model_name = self.model_overrides.get("perplexity") or os.getenv("PERPLEXITY_MODEL") or "sonar-pro"
        self.active_model = model_name
        payload = {"query": prompt, "top_n": 1, "model": model_name}
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
        mode = info.get("mode", "http")
        key = info.get("key")
        model = info.get("model")
        self.active_model = model

        if mode == "sdk":
            genai = info.get("sdk")
            sdk_model = info.get("sdk_model") or model
            generation_config = {"max_output_tokens": max_tokens, "temperature": 0}
            try:
                gm = genai.GenerativeModel(model_name=sdk_model, generation_config=generation_config)
                response = gm.generate_content(prompt)
                if getattr(response, "text", None):
                    return response.text.strip()
                texts = []
                for candidate in getattr(response, "candidates", []) or []:
                    content = getattr(candidate, "content", None)
                    parts = getattr(content, "parts", None) if content else None
                    if isinstance(parts, list):
                        for part in parts:
                            text = getattr(part, "text", None)
                            if text:
                                texts.append(text)
                if texts:
                    return "\n".join(texts).strip()
                feedback = getattr(response, "prompt_feedback", None)
                if feedback and getattr(feedback, "block_reason", None):
                    return f"(Gemini) Request blocked: {feedback.block_reason}"
                return ""
            except Exception as e:
                logger.exception("Gemini SDK call failed: %s", e)
                # fall through to HTTP fallback if possible
                mode = "http"

        if mode != "http":
            raise RuntimeError("Gemini client not configured for HTTP fallback")

        requests_lib = info["requests"]
        base_url = info.get("base_url", "https://generativelanguage.googleapis.com/v1beta")

        def _post(base: str):
            url = f"{base.rstrip('/')}/{model}:generateContent?key={key}"
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"maxOutputTokens": max_tokens, "temperature": 0},
            }
            resp = requests_lib.post(url, json=payload, timeout=20)
            try:
                resp.raise_for_status()
            except requests_lib.exceptions.HTTPError as http_err:  # type: ignore[attr-defined]
                status = http_err.response.status_code if http_err.response else None
                extra_message = None
                try:
                    err_json = http_err.response.json()
                    extra_message = err_json.get("error", {}).get("message")
                except Exception:
                    pass
                if status == 404 and "/v1beta" in base:
                    alt_base = base.replace("/v1beta", "/v1")
                    logger.info("Gemini model not found on v1beta; retrying with %s", alt_base)
                    info["base_url"] = alt_base
                    return _post(alt_base)
                if status == 404:
                    message = "Gemini model not found. Set GEMINI_MODEL (e.g. 'gemini-pro-latest') or update GEMINI_API_URL."
                elif status == 403:
                    message = "Gemini API access denied. Ensure the key has Generative Language API enabled."
                else:
                    message = "Gemini API request failed"
                if extra_message:
                    message += f" Details: {extra_message}"
                raise RuntimeError(message) from http_err
            try:
                return resp.json()
            except ValueError:
                return {"raw": resp.text}

        try:
            data = _post(base_url)
            if isinstance(data, dict):
                candidates = data.get("candidates")
                if candidates:
                    texts = []
                    for cand in candidates:
                        content = cand.get("content") if isinstance(cand, dict) else None
                        parts = content.get("parts") if isinstance(content, dict) else None
                        if isinstance(parts, list):
                            for part in parts:
                                text = part.get("text") if isinstance(part, dict) else None
                                if text:
                                    texts.append(text)
                    if texts:
                        return "\n".join(texts).strip()
                prompt_feedback = data.get("promptFeedback")
                if isinstance(prompt_feedback, dict):
                    block_reason = prompt_feedback.get("blockReason")
                    if block_reason:
                        return f"(Gemini) Request blocked: {block_reason}"
            return ""
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
                engine = self.model_overrides.get("openai") or os.getenv("OPENAI_ENGINE", "gpt-3.5-turbo")
                self.active_model = engine
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
                    legacy_engine = self.model_overrides.get("openai") or os.getenv("OPENAI_ENGINE", "text-davinci-003")
                    resp = self._client.Completion.create(
                        engine=legacy_engine,
                        prompt=prompt,
                        max_tokens=max_tokens,
                        temperature=0,
                    )
                    self.active_model = legacy_engine
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
            try:
                # Keep prompt within the model's context window to avoid index errors.
                tokenizer = getattr(self._client, "tokenizer", None)
                model = getattr(self._client, "model", None)
                ctx_limit = None
                if model and getattr(model, "config", None):
                    ctx_limit = getattr(model.config, "max_position_embeddings", None)
                if not ctx_limit:
                    ctx_limit = 1024  # sensible fallback for small GPT-style models

                max_new_tokens = max_tokens or 64
                if max_new_tokens >= ctx_limit:
                    max_new_tokens = max(32, ctx_limit // 4)

                prompt_for_model = prompt
                if tokenizer:
                    # Reserve room for generation; hard truncate the prompt in token space.
                    limit = max(ctx_limit - max_new_tokens - 1, 32)
                    encoded = tokenizer.encode(prompt, truncation=True, max_length=limit)
                    prompt_for_model = tokenizer.decode(encoded)
                else:
                    # Fallback: trim raw text to a conservative length.
                    prompt_for_model = prompt[:4000]

                out = self._client(
                    prompt_for_model,
                    max_new_tokens=max_new_tokens,
                    truncation=True,
                    do_sample=False,
                    pad_token_id=self._client.tokenizer.eos_token_id if hasattr(self._client, 'tokenizer') else None
                )
                # transformers pipeline returns list of dicts
                if out and len(out) > 0 and "generated_text" in out[0]:
                    return out[0]["generated_text"].strip()
                else:
                    logger.warning("Transformers pipeline returned empty or invalid response")
                    return ""
            except Exception as e:
                logger.exception("Transformers generation failed: %s", e)
                raise RuntimeError(f"Transformers pipeline error: {e}")

    def estimate_tokens(self, text: str) -> int:
        if not text:
            return 0
        try:
            self.ensure()
        except Exception:
            pass

        # Prefer tokenizer metadata when available
        tokenizer = getattr(self._client, "tokenizer", None)
        if tokenizer:
            try:
                encoded = tokenizer.encode(text, truncation=False)
                return len(encoded)
            except Exception:
                pass

        if self.provider == "openai":
            try:
                import tiktoken

                model_name = os.getenv("OPENAI_ENGINE", "gpt-3.5-turbo")
                try:
                    enc = tiktoken.encoding_for_model(model_name)
                except Exception:
                    enc = tiktoken.get_encoding("cl100k_base")
                return len(enc.encode(text))
            except Exception:
                pass

        # Fallback: rough heuristic assuming ~4 chars per token
        approx_word_tokens = len(text.split())
        approx_char_tokens = max(1, len(text) // 4)
        return max(approx_word_tokens, approx_char_tokens)
