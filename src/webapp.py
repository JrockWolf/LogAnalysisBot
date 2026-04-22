from fastapi import FastAPI, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pathlib import Path
from .analyzer import analyze_logs_with_llm, heuristic_detect
from .parsers import parse_log, is_labeled_dataset_csv, detect_file_type
from .mitre_mapping import enrich_findings_with_mitre
from .charts import generate_chart_data
from .pipeline import run_isolation_forest, run_local_outlier_factor, run_one_class_svm, \
    run_dbscan, run_random_forest_supervised, run_all_models, compute_statistics, dataset_overview, \
    compute_model_performance, compute_baseline_comparison, compute_statistical_tests, \
    compute_error_analysis, compute_hypotheses
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


# ── Helpers ────────────────────────────────────────────────────────

ACCEPTED_EXTENSIONS = (
    ".log", ".txt", ".csv", ".json", ".jsonl",
    ".pcap", ".pcapng", ".cap",
    ".gz", ".zip",
)


def try_decode(b: bytes):
    encodings = ["utf-8", "utf-16", "cp1252", "latin-1"]
    for enc in encodings:
        try:
            return b.decode(enc), enc
        except Exception:
            continue
    return b.decode("latin-1", errors="replace"), "latin-1-replace"


def _handle_upload(data: bytes, upload_name: str):
    """Decompress if needed, decode, return (raw_text_or_None, bytes_or_None, effective_suffix, warning)."""
    effective_suffix = Path(upload_name).suffix.lower() or ".log"
    decode_warning = None
    raw_text = None
    raw_bytes = None  # for binary files like pcap

    # Check for binary (pcap) files first
    if data[:4] in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\x0a\x0d\x0d\x0a") or effective_suffix in (".pcap", ".pcapng", ".cap"):
        return None, data, effective_suffix, None

    try:
        import gzip
        if data.startswith(b"\x1f\x8b"):
            stem = Path(upload_name)
            if stem.suffix.lower() == ".gz":
                effective_suffix = Path(stem.stem).suffix.lower() or ".log"
            try:
                dec = gzip.decompress(data)
                # Check if decompressed content is pcap
                if dec[:4] in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\x0a\x0d\x0d\x0a"):
                    return None, dec, effective_suffix if effective_suffix in (".pcap", ".pcapng", ".cap") else ".pcap", f"File was gzip compressed; decompressed as pcap."
                text, enc = try_decode(dec)
                return text, None, effective_suffix, f"File was gzip compressed; decompressed and decoded as {enc}."
            except Exception:
                text, enc = try_decode(data)
                return text, None, effective_suffix, f"Could not decompress gzip; decoded raw bytes as {enc}."

        elif data.startswith(b"PK\x03\x04"):
            import zipfile, io
            try:
                z = zipfile.ZipFile(io.BytesIO(data))
                entries = [n for n in z.namelist() if not n.endswith("/")]
                if not entries:
                    raw_text, enc = try_decode(data)
                    return raw_text, None, effective_suffix, "Zip archive is empty."
                elif len(entries) == 1:
                    name = entries[0]
                    effective_suffix = Path(name).suffix.lower() or ".log"
                    val = z.read(name)
                    if val[:4] in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\x0a\x0d\x0d\x0a"):
                        return None, val, effective_suffix if effective_suffix in (".pcap", ".pcapng", ".cap") else ".pcap", f"Zip: extracted {name} as pcap."
                    raw_text, enc = try_decode(val)
                    return raw_text, None, effective_suffix, f"Zip: extracted {name} (decoded as {enc})."
                else:
                    parts = []
                    used_names = []
                    first_suffix = None
                    for name in entries:
                        try:
                            val = z.read(name)
                            txt, enc = try_decode(val)
                            parts.append(txt)
                            used_names.append(name)
                            if first_suffix is None:
                                first_suffix = Path(name).suffix.lower()
                        except Exception:
                            continue
                    if parts:
                        raw_text = "\n".join(parts)
                        effective_suffix = first_suffix or ".log"
                        return raw_text, None, effective_suffix, f"Zip: concatenated {len(parts)} files."
                    raw_text, enc = try_decode(data)
                    return raw_text, None, effective_suffix, "Zip: could not read entries."
            except Exception as exc:
                raw_text, enc = try_decode(data)
                return raw_text, None, effective_suffix, f"Zip handling failed ({exc})."
        else:
            text, enc = try_decode(data)
            warning = f"Decoded using {enc} (not utf-8)." if enc != "utf-8" else None
            return text, None, effective_suffix, warning
    except Exception as e:
        raw_text, enc = try_decode(data)
        return raw_text, None, effective_suffix, f"Error processing upload: {e}; decoded as {enc}."


# ── Routes ─────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
def index(request: Request, provider: str | None = None, model: str | None = None):
    selected = (provider or "auto").strip().lower() or "auto"
    if selected not in PROVIDER_LABELS:
        selected = "auto"
    raw_model_pref = (model or "").strip()
    model_pref = raw_model_pref if selected == "gemini" else ""
    return templates.TemplateResponse(
        request,
        "index.html",
        context={
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
    """Analyze uploaded or pasted logs — security findings, MITRE mapping, anomaly detection."""
    selected_provider = (provider or "auto").strip().lower() or "auto"
    if selected_provider not in PROVIDER_LABELS:
        selected_provider = "auto"
    provided_key = (api_key or "").strip()
    model_hint = (model or "").strip()

    if selected_provider == "gemini" and not provided_key:
        return templates.TemplateResponse(request, "index.html", context={
            "error": "Gemini requires an API key.",
            "providers": SUPPORTED_PROVIDERS,
            "selected_provider": selected_provider,
            "selected_model": model_hint,
        })

    if selected_provider != "gemini":
        model_hint = ""

    if (not upload or not upload.filename) and not pasted.strip():
        return templates.TemplateResponse(request, "index.html", context={
            "error": "Please provide data by uploading a file or pasting text.",
            "providers": SUPPORTED_PROVIDERS,
            "selected_provider": selected_provider,
            "selected_model": model_hint,
        })

    decode_warning = None
    raw_text = None
    effective_suffix = ".log"
    is_binary = False

    if upload and upload.filename:
        data = await upload.read()
        raw_text, raw_bytes, effective_suffix, decode_warning = _handle_upload(data, upload.filename)

        if raw_bytes is not None:
            # Binary file (pcap) - write as binary
            is_binary = True
            with tempfile.NamedTemporaryFile(delete=False, suffix=effective_suffix) as tf:
                tf.write(raw_bytes)
                path = Path(tf.name)
            raw_text = f"[Binary file: {upload.filename}, {len(raw_bytes)} bytes]"
        else:
            with tempfile.NamedTemporaryFile("w", delete=False, suffix=effective_suffix, encoding="utf-8") as tf:
                tf.write(raw_text or "")
                path = Path(tf.name)
    else:
        raw_text = pasted
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".log", encoding="utf-8") as tf:
            tf.write(pasted)
            path = Path(tf.name)

    # Detect file type
    file_type = detect_file_type(path)

    # Perplexity key fixup
    try:
        openai_key = os.getenv("OPENAI_API_KEY")
        pplx = os.getenv("PERPLEXITY_API_KEY")
        if openai_key and openai_key.startswith("pplx-") and not pplx:
            os.environ["PERPLEXITY_API_KEY"] = openai_key
    except Exception:
        pass

    # Set provider-specific env var from form key so LLMAdapter picks it up immediately
    if provided_key:
        key_env_map = {
            "gemini": "GEMINI_API_KEY",
            "openai": "OPENAI_API_KEY",
            "perplexity": "PERPLEXITY_API_KEY",
            "deepseek": "DEEPSEEK_API_KEY",
        }
        env_name = key_env_map.get(selected_provider)
        if env_name:
            os.environ[env_name] = provided_key

    # Run analysis
    try:
        analysis = analyze_logs_with_llm(
            path, provider=selected_provider,
            api_key=provided_key or None, model=model_hint or None,
        )
    except Exception as e:
        logger.exception("Analysis failed: %s", e)
        analysis = {"findings": [f"(Error) analysis failed: {e}"], "llm_text": None, "llm_provider": None}

    findings = analysis.get("findings", [])
    llm_text = analysis.get("llm_text")
    llm_provider = analysis.get("llm_provider")
    requested_provider = analysis.get("requested_provider") or selected_provider
    requested_model = analysis.get("requested_model") or model_hint or None
    model_used = analysis.get("model_used")
    token_usage = analysis.get("token_usage")

    # MITRE enrichment
    mitre_mappings = enrich_findings_with_mitre(findings)

    # Parse records for pipeline
    records = parse_log(path)

    # Dataset overview
    ds_overview = dataset_overview(records)

    # Labeled dataset specific
    dataset_summary_data = None
    ds_rows = None
    if is_labeled_dataset_csv(path):
        try:
            from .dataset_loader import load_dataset_csv, dataset_summary as ds_summary
            _, ds_rows = load_dataset_csv(path, max_rows=10000)
            dataset_summary_data = ds_summary(ds_rows)
        except Exception:
            pass

    # Merge overviews
    summary_for_charts = dataset_summary_data or ds_overview

    # Use consistent row set for all pipeline functions
    effective_rows = ds_rows or records

    # Run all anomaly detection models on effective_rows
    anomaly_result = None
    all_models_result = None
    try:
        all_models_result = run_all_models(effective_rows)
        anomaly_result = all_models_result.get("isolation_forest")
        if anomaly_result and anomaly_result.get("anomaly_count", 0) > 0:
            anom_pct = anomaly_result['anomaly_count'] / max(anomaly_result['total_records'], 1) * 100
            findings.append(
                f"Anomaly Detection: {anomaly_result['anomaly_count']} of "
                f"{anomaly_result['total_records']} records ({anom_pct:.1f}%) flagged as anomalous "
                f"by Isolation Forest"
            )
        ensemble = all_models_result.get("ensemble", {})
        if ensemble.get("anomaly_count", 0) != (anomaly_result or {}).get("anomaly_count", 0):
            findings.append(
                f"Ensemble consensus ({ensemble.get('method','')}) flagged "
                f"{ensemble.get('anomaly_count', 0)} records."
            )
    except Exception as e:
        logger.warning("Anomaly detection skipped: %s", e)

    return templates.TemplateResponse(request, "results.html", context={
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
        "mitre_mappings": mitre_mappings,
        "dataset_summary": summary_for_charts,
        "anomaly_result": anomaly_result,
        "all_models_result": all_models_result,
        "file_type": file_type,
        "filename": upload.filename if upload and upload.filename else "pasted_text",
    })


@app.post("/visualize", response_class=HTMLResponse)
async def visualize(
    request: Request,
    upload: UploadFile | None = File(None),
    pasted: str = Form(""),
):
    """Generate charts and statistical analysis on a dataset — no LLM needed."""
    if (not upload or not upload.filename) and not pasted.strip():
        return templates.TemplateResponse(request, "index.html", context={
            "error": "Please provide data for visualization.",
            "providers": SUPPORTED_PROVIDERS,
            "selected_provider": "auto",
            "selected_model": "",
        })

    decode_warning = None
    raw_text = None
    is_binary = False

    if upload and upload.filename:
        data = await upload.read()
        raw_text, raw_bytes, effective_suffix, decode_warning = _handle_upload(data, upload.filename)
        if raw_bytes is not None:
            is_binary = True
            with tempfile.NamedTemporaryFile(delete=False, suffix=effective_suffix) as tf:
                tf.write(raw_bytes)
                path = Path(tf.name)
            raw_text = f"[Binary file: {upload.filename}, {len(raw_bytes)} bytes]"
        else:
            with tempfile.NamedTemporaryFile("w", delete=False, suffix=effective_suffix, encoding="utf-8") as tf:
                tf.write(raw_text or "")
                path = Path(tf.name)
    else:
        raw_text = pasted
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".csv", encoding="utf-8") as tf:
            tf.write(pasted)
            path = Path(tf.name)

    file_type = detect_file_type(path)
    records = parse_log(path)

    # Dataset overview
    ds_overview = dataset_overview(records)

    # Labeled dataset specific
    dataset_summary_data = None
    ds_rows = None
    if is_labeled_dataset_csv(path):
        try:
            from .dataset_loader import load_dataset_csv, dataset_summary as ds_summary
            _, ds_rows = load_dataset_csv(path, max_rows=10000)
            dataset_summary_data = ds_summary(ds_rows)
        except Exception:
            pass

    summary_for_charts = dataset_summary_data or ds_overview

    # Use consistent row set for all pipeline functions
    effective_rows = ds_rows or records

    # Compute statistics
    stats = compute_statistics(effective_rows)

    # Run anomaly detection on effective_rows so indices stay consistent
    anomaly_result = None
    try:
        anomaly_result = run_isolation_forest(effective_rows)
    except Exception as e:
        logger.warning("Anomaly detection skipped: %s", e)

    # Analytics
    model_perf = compute_model_performance(effective_rows, anomaly_result)
    baseline_comp = compute_baseline_comparison(effective_rows, anomaly_result)
    stat_tests = compute_statistical_tests(effective_rows, anomaly_result)
    error_ana = compute_error_analysis(effective_rows, anomaly_result)
    hypotheses = compute_hypotheses(effective_rows, anomaly_result, summary_for_charts)

    chart_data = generate_chart_data(
        rows=effective_rows,
        findings=None,
        dataset_summary=summary_for_charts,
        anomaly_result=anomaly_result,
        statistics=stats,
        model_performance=model_perf,
        baseline_comparison=baseline_comp,
        error_analysis=error_ana,
    )

    return templates.TemplateResponse(request, "visualize.html", context={
        "chart_data": chart_data,
        "statistics": stats,
        "dataset_summary": summary_for_charts,
        "anomaly_result": anomaly_result,
        "decode_warning": decode_warning,
        "file_type": file_type,
        "filename": upload.filename if upload and upload.filename else "pasted_data",
        "total_records": len(records),
        "model_performance": model_perf,
        "baseline_comparison": baseline_comp,
        "statistical_tests": stat_tests,
        "error_analysis": error_ana,
        "hypotheses": hypotheses,
    })
