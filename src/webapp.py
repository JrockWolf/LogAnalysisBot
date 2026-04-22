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
import asyncio

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

    # Determine row cap based on file size — reservoir-sample large files so
    # memory stays bounded and ML models run in reasonable time.
    _file_size = path.stat().st_size
    if _file_size > 200 * 1024 * 1024:   # >200 MB
        _max_rows = 50_000
    elif _file_size > 50 * 1024 * 1024:  # >50 MB
        _max_rows = 100_000
    elif _file_size > 10 * 1024 * 1024:  # >10 MB
        _max_rows = 200_000
    else:
        _max_rows = None  # read everything

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

    # Parse records for pipeline (reservoir-sampled for large files)
    records = parse_log(path, max_rows=_max_rows)

    # Dataset overview
    ds_overview = dataset_overview(records)

    # Labeled dataset specific
    dataset_summary_data = None
    ds_rows = None
    if is_labeled_dataset_csv(path):
        try:
            from .dataset_loader import load_dataset_csv, dataset_summary as ds_summary
            _, ds_rows = load_dataset_csv(path, max_rows=_max_rows or 50_000)
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
    generate_summary: str = Form(""),
    provider: str = Form("auto"),
    api_key: str = Form(""),
    model: str = Form(""),
):
    """Generate charts, statistical analysis and an optional AI-readable summary."""
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

    # Size-based row cap for visualize route
    _vis_size = path.stat().st_size
    if _vis_size > 200 * 1024 * 1024:
        _vis_max = 50_000
    elif _vis_size > 50 * 1024 * 1024:
        _vis_max = 100_000
    elif _vis_size > 10 * 1024 * 1024:
        _vis_max = 200_000
    else:
        _vis_max = None

    records = parse_log(path, max_rows=_vis_max)

    # ── Structurize unstructured records ──────────────────────────────────
    # Convert raw text/syslog lines into structured records with consistent
    # fields (timestamp, severity, src_ip, dst_ip, port, protocol, action …).
    # Already-structured types (pcap, labeled CSV, JSON) are passed through.
    from .structurizer import structurize_records, structurize_summary
    is_text_type = file_type in ("text", "log", "syslog", "txt", None) or \
                   (file_type not in ("pcap", "csv", "json", "jsonl", "dataset"))
    if is_text_type:
        records = structurize_records(records)
    struct_summary = structurize_summary(records)

    # Structured charts (top IPs, severity dist, ports, etc.)
    from .charts import generate_structured_charts
    structured_charts: dict = {}
    if is_text_type and struct_summary.get("structured_pct", 0) > 0:
        structured_charts = generate_structured_charts(records)

    # Preview: first 200 records showing only populated fields
    _PREVIEW_FIELDS = [
        "timestamp", "severity", "hostname", "process",
        "src_ip", "src_port", "dst_ip", "dst_port",
        "protocol", "action", "user",
        "status_code", "method", "url", "bytes_sent", "message",
    ]
    # Determine which preview columns actually have data
    preview_cols = [
        f for f in _PREVIEW_FIELDS
        if any(r.get(f) is not None for r in records[:500])
    ]
    structured_preview = [
        {f: r.get(f) for f in preview_cols}
        for r in records[:200]
    ]

    # Dataset overview
    ds_overview = dataset_overview(records)

    # Labeled dataset specific
    dataset_summary_data = None
    ds_rows = None
    if is_labeled_dataset_csv(path):
        try:
            from .dataset_loader import load_dataset_csv, dataset_summary as ds_summary
            _, ds_rows = load_dataset_csv(path, max_rows=_vis_max or 50_000)
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

    # Optional AI-readable summary
    ai_summary = None
    ai_provider_display = None
    if generate_summary and generate_summary not in ("", "0", "false"):
        try:
            from .llm_adapter import LLMAdapter
            _prov = (provider or "").strip().lower() or None
            if _prov == "auto":
                _prov = None
            _key_map: dict = {}
            _key_value = (api_key or "").strip()
            if _key_value:
                if _prov in {"openai", "perplexity", "deepseek", "gemini"}:
                    _key_map[_prov] = _key_value
                else:
                    if _key_value.startswith("pplx-"):
                        _key_map["perplexity"] = _key_value
                    elif _key_value.startswith("sk-") or _key_value.startswith("rk-"):
                        _key_map["openai"] = _key_value
                    elif _key_value.startswith("AIza") or _key_value.upper().startswith("AI"):
                        _key_map["gemini"] = _key_value
                    elif _key_value.lower().startswith("ds-"):
                        _key_map["deepseek"] = _key_value

            _model_map: dict = {}
            _model_val = (model or "").strip()
            if _model_val and _prov:
                _model_map[_prov] = _model_val

            llm = LLMAdapter(provider=_prov, api_keys=_key_map, model_overrides=_model_map)

            # Build a compact data description for the prompt
            _anom_count = anomaly_result.get("anomaly_count", 0) if anomaly_result else 0
            _total = len(records)
            _ftype = file_type
            _cat_dist = ""
            if summary_for_charts and isinstance(summary_for_charts, dict):
                cats = summary_for_charts.get("category_distribution", {})
                if cats:
                    _cat_dist = "\nLabel distribution: " + ", ".join(
                        f"{k}: {v}" for k, v in list(cats.items())[:10]
                    )
            _stats_text = ""
            if stats and isinstance(stats, dict):
                _numeric = stats.get("numeric_summary", {})
                if _numeric:
                    _stats_text = "\nNumeric feature stats: " + "; ".join(
                        f"{col}: mean={v.get('mean', 'N/A'):.3g}, std={v.get('std', 'N/A'):.3g}"
                        for col, v in list(_numeric.items())[:6]
                    )

            _summary_prompt = f"""You are a data analyst assistant. A user has uploaded a security/network dataset for analysis.
Provide a clear, human-readable plain-English summary of what this data contains and the key findings.

Dataset info:
- File type: {_ftype}
- Total records: {_total:,}
- Anomalies detected: {_anom_count} ({(_anom_count / _total * 100) if _total else 0:.1f}%){_cat_dist}{_stats_text}

Write a concise, easy-to-read analysis report (3–5 paragraphs) covering:
1. What type of data this is and what it represents
2. Key patterns or notable characteristics in the data
3. What the anomalies/outliers suggest about threats or abnormal activity
4. Actionable recommendations for investigation or remediation
Use plain language. Avoid excessive jargon. Format with short paragraphs separated by blank lines."""

            def _call_llm():
                return llm.generate_with_timeout(_summary_prompt, max_tokens=600, timeout_seconds=30.0)

            ai_summary = await asyncio.get_event_loop().run_in_executor(None, _call_llm)
            ai_provider_display = llm.provider or provider or "auto"
        except Exception as e:
            logger.warning("AI summary failed: %s", e)
            ai_summary = f"AI summary could not be generated: {e}"

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
        "ai_summary": ai_summary,
        "ai_provider_display": ai_provider_display,
        # Structured data
        "struct_summary": struct_summary,
        "structured_preview": structured_preview,
        "preview_cols": preview_cols,
        "structured_charts": structured_charts,
        "is_text_type": is_text_type,
    })
