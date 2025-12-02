from fastapi import FastAPI, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path
from .analyzer import analyze_logs_with_llm, heuristic_detect
from .parsers import parse_text_log
import tempfile
import logging
import os

SUPPORTED_PROVIDERS = [
    ("auto", "Automatic (use environment or supplied key)"),
    ("openai", "OpenAI"),
    ("perplexity", "Perplexity"),
    ("gemini", "Gemini"),
    ("deepseek", "DeepSeek"),
    ("transformers", "Local transformers (no key required)"),
]

PROVIDER_LABELS = {value: label for value, label in SUPPORTED_PROVIDERS}


def _provider_display(value: str | None) -> str:
    if not value:
        return "None"
    key = value.lower()
    return PROVIDER_LABELS.get(key, value)

logger = logging.getLogger("logbot.webapp")
if not logger.handlers:
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(h)
    logger.setLevel(logging.INFO)

app = FastAPI()
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")


@app.get("/", response_class=HTMLResponse)
def index(request: Request, provider: str | None = None, model: str | None = None):
    selected = (provider or "auto").strip().lower() or "auto"
    if selected not in PROVIDER_LABELS:
        selected = "auto"
    raw_model_pref = (model or "").strip()
    model_pref = raw_model_pref if selected == "gemini" else ""
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "error": None,
            "providers": SUPPORTED_PROVIDERS,
            "selected_provider": selected,
            "selected_model": model_pref,
        },
    )


@app.post("/analyze", response_class=HTMLResponse)
async def analyze(
    request: Request,
    pasted: str = Form(""),
    upload: UploadFile | None = File(None),
    provider: str = Form("auto"),
    api_key: str = Form(""),
    model: str = Form(""),
):
    """Analyze uploaded or pasted logs with best-effort decoding and decompression.

    Will attempt gzip/zip detection and try UTF-8, UTF-16, CP1252, Latin-1 decodings.
    If decoding required a fallback, pass a warning to the template.
    """
    # Check if user provided any log data
    selected_provider = (provider or "auto").strip().lower() or "auto"
    if selected_provider not in PROVIDER_LABELS:
        selected_provider = "auto"
    provided_key = (api_key or "").strip()
    model_hint = (model or "").strip()

    if selected_provider == "gemini" and not provided_key:
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "error": "Gemini requests require an API key. Please provide your Gemini key to continue.",
                "providers": SUPPORTED_PROVIDERS,
                "selected_provider": selected_provider,
                "selected_model": model_hint,
            },
        )

    if selected_provider != "gemini":
        model_hint = ""

    if (not upload or not upload.filename) and not pasted.strip():
        return templates.TemplateResponse(
            "index.html",
            {
                "request": request,
                "error": "Please provide log data by either uploading a file or pasting log text.",
                "providers": SUPPORTED_PROVIDERS,
                "selected_provider": selected_provider,
                "selected_model": model_hint,
            }
        )
    
    decode_warning = None
    raw_text = None

    def try_decode(b: bytes):
        # try common encodings
        encodings = ["utf-8", "utf-16", "cp1252", "latin-1"]
        for enc in encodings:
            try:
                return b.decode(enc), enc
            except Exception:
                continue
        # as last resort, latin-1 with replacement
        return b.decode("latin-1", errors="replace"), "latin-1-replace"

    if upload and upload.filename:
        data = await upload.read()
        b = data
        # check for gzip
        try:
            import gzip
            if b.startswith(b"\x1f\x8b"):
                try:
                    dec = gzip.decompress(b)
                    text, enc = try_decode(dec)
                    decode_warning = f"File was gzip compressed; decompressed and decoded as {enc}."
                    raw_text = text
                except Exception:
                    # fallback to trying to decode original
                    text, enc = try_decode(b)
                    decode_warning = f"Could not fully decompress gzip; decoded raw bytes as {enc}."
                    raw_text = text
                
            elif b.startswith(b"PK\x03\x04"):
                # zipfile
                import zipfile, io
                try:
                    z = zipfile.ZipFile(io.BytesIO(b))
                    # find first reasonable text file
                    names = z.namelist()
                    content = None
                    for name in names:
                        if name.endswith('/'): 
                            continue
                        try:
                            val = z.read(name)
                            txt, enc = try_decode(val)
                            content = txt
                            decode_warning = f"Zip archive; using file {name} decoded as {enc}."
                            break
                        except Exception:
                            continue
                    if content is None:
                        raw_text, enc = try_decode(b)
                        decode_warning = "Zip archive could not be read; decoded raw bytes with fallback."
                    else:
                        raw_text = content
                except Exception:
                    raw_text, enc = try_decode(b)
                    decode_warning = f"Zip handling failed; decoded raw bytes as {enc}."
            else:
                # not compressed — try decoding
                text, enc = try_decode(b)
                raw_text = text
                if enc != "utf-8":
                    decode_warning = f"Decoded using {enc} (not utf-8)."
        except Exception as e:
            # any unexpected error — attempt simple decode
            raw_text, enc = try_decode(b)
            decode_warning = f"Unexpected error while processing upload: {e}; decoded as {enc}."

        # write to temp file for analyzer
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as tf:
            tf.write(raw_text)
            path = Path(tf.name)
    else:
        # pasted text path
        raw_text = pasted
        path = None
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as tf:
            tf.write(pasted)
            path = Path(tf.name)
    # Safety: if user placed a Perplexity key into OPENAI_API_KEY (prefix pplx-),
    # make it available as PERPLEXITY_API_KEY so the adapter will prefer Perplexity
    # (avoids accidentally calling OpenAI with a non-OpenAI key).
    try:
        openai_key = os.getenv("OPENAI_API_KEY")
        pplx = os.getenv("PERPLEXITY_API_KEY")
        if openai_key and openai_key.startswith("pplx-") and not pplx:
            os.environ["PERPLEXITY_API_KEY"] = openai_key
            logger.info("Detected pplx- key in OPENAI_API_KEY; setting PERPLEXITY_API_KEY for this process to prefer Perplexity SDK.")
    except Exception:
        pass

    # Run analysis for both upload and pasted text paths. Ensure analysis is defined
    # even if LLM fails, so the template can render heuristics and any error notes.
    try:
        analysis = analyze_logs_with_llm(
            path,
            provider=selected_provider,
            api_key=provided_key or None,
            model=model_hint or None,
        )
    except Exception as e:
        logger.exception("Analysis failed: %s", e)
        analysis = {"findings": [f"(Error) analysis failed: {e}"], "llm_text": None, "llm_provider": None}

    # Keep concise info logs: provider and number of findings
    try:
        n = len(analysis.get("findings", [])) if isinstance(analysis, dict) else 0
        logger.info("Analysis complete: provider=%s findings=%d", analysis.get("llm_provider"), n)
    except Exception:
        logger.debug("Analysis completed but could not compute summary", exc_info=True)
    findings = analysis.get("findings", [])
    llm_text = analysis.get("llm_text")
    llm_provider = analysis.get("llm_provider")
    requested_provider = analysis.get("requested_provider") or selected_provider
    requested_model = analysis.get("requested_model") or model_hint or None
    model_used = analysis.get("model_used")
    token_usage = analysis.get("token_usage")
    return templates.TemplateResponse(
        "results.html",
        {
            "request": request,
            "findings": findings,
            "raw": raw_text,
            "decode_warning": decode_warning,
            "llm_text": llm_text,
            "llm_provider": llm_provider,
            "llm_provider_display": _provider_display(llm_provider),
            "requested_provider_display": _provider_display(requested_provider),
            "requested_provider": requested_provider,
            "requested_model": requested_model,
            "model_used": model_used,
            "token_usage": token_usage,
            "analysis": analysis,
        },
    )
