from pathlib import Path
from typing import List, Dict, Any, Optional
from .parsers import parse_log
from .llm_adapter import LLMAdapter
import re
import logging

logger = logging.getLogger("logbot.analyzer")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


def heuristic_detect(records: List[Dict[str, Any]]) -> List[str]:
    findings = []
    # aggregate SSH failures by IP
    ssh_failures = {}
    for r in records:
        raw = r.get("raw") or str(r)
        m = re.search(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)", raw)
        if m:
            ip = m.group(1)
            ssh_failures[ip] = ssh_failures.get(ip, 0) + 1
    for ip, count in ssh_failures.items():
        if count >= 3:
            findings.append(f"Multiple failed SSH logins from {ip} ({count} attempts)")

    # detect sudo to sensitive files
    for r in records:
        raw = r.get("raw") or str(r)
        if re.search(r"sudo:.*COMMAND=.*(/etc/shadow|/etc/sudoers)", raw):
            findings.append("User account attempting privilege escalation or reading sensitive files")

    # unauthorized file access
    for r in records:
        raw = r.get("raw") or str(r)
        if "audit(" in raw and "/etc/shadow" in raw:
            findings.append("Audit event: possible unauthorized access to /etc/shadow")

    return findings


def analyze_logs(path: Path) -> List[str]:
    records = parse_log(path)
    # run heuristic first
    findings = heuristic_detect(records)
    # produce LLM-enhanced summaries if available
    llm = LLMAdapter()
    prompt = """Analyze these security log entries and provide findings with solutions.

For each security issue found, format as:
Finding: [describe the issue]
Solution: [recommended action to resolve it]

Log entries:
{lines}
"""
    if findings:
        # if heuristics already found things, prepend them as context
        seed_context = "\n".join([f"Detected: {f}" for f in findings])
        prompt_filled = prompt.format(lines=seed_context + "\n\n" + "\n".join([r.get("raw","") for r in records[:200]]))
    else:
        prompt_filled = prompt.format(lines="\n".join([r.get("raw","") for r in records[:200]]))

    try:
        # ensure the adapter is initialized to know provider
        try:
            llm.ensure()
        except Exception:
            pass
        provider = llm.provider or "(unspecified)"
        logger.info("Calling LLM provider: %s", provider)
        text = llm.generate(prompt_filled, max_tokens=256)
        logger.info("LLM returned %d chars", len(text) if text else 0)
        llm_text = text or ""
        # split into lines and return combined unique findings (keep heuristics first)
        extra = [line.strip() for line in text.splitlines() if line.strip()]
        combined = findings + extra
        # dedupe while preserving order
        seen = set()
        out = []
        for item in combined:
            if item not in seen:
                seen.add(item)
                out.append(item)
        # if there were no LLM-specific findings but LLM was used, add an informational note
        if provider and provider != "transformers" and not extra:
            out.append(f"(Info) LLM provider {provider} returned no extractable findings.")
        # package llm_text into a tuple for compatibility with web UI
        return out
    except Exception as e:
        logger.exception("LLM generation failed: %s", e)
        # Surface a helpful informational finding so UI shows why heuristics-only were returned
        if llm and getattr(llm, "provider", None):
            findings.append(f"(Info) LLM attempt with provider '{llm.provider}' failed: {e}")
        else:
            findings.append(f"(Info) LLM attempt failed: {e}")
        return findings


def analyze_logs_with_llm(
    path: Path,
    provider: Optional[str] = None,
    api_key: Optional[str] = None,
    model: Optional[str] = None,
) -> Dict[str, Any]:
    """Return a dict with findings, llm_text (raw), and llm_provider for the web UI."""
    records = parse_log(path)
    findings = heuristic_detect(records)
    selected_provider = (provider or "").strip().lower() or None
    if selected_provider == "auto":
        selected_provider = None

    key_map: Dict[str, str] = {}
    key_value = (api_key or "").strip()
    if selected_provider == "gemini":
        if not key_value:
            raise RuntimeError("Gemini provider requires an API key.")
        key_map["gemini"] = key_value
    elif key_value:
        if selected_provider in {"openai", "perplexity", "deepseek"}:
            key_map[selected_provider] = key_value
        else:
            inferred = None
            if key_value.startswith("pplx-"):
                inferred = "perplexity"
            elif key_value.startswith("sk-") or key_value.startswith("rk-") or key_value.startswith("pk-"):
                inferred = "openai"
            elif key_value.lower().startswith("gk-") or key_value.startswith("AIza") or key_value.startswith("AI"):
                inferred = "gemini"
            elif key_value.lower().startswith("ds-"):
                inferred = "deepseek"
            if inferred:
                key_map[inferred] = key_value

    raw_model_hint = (model or "").strip()
    model_hint = raw_model_hint if selected_provider == "gemini" else ""
    model_map: Dict[str, str] = {}
    if model_hint:
        model_map["gemini"] = model_hint

    llm = LLMAdapter(provider=selected_provider, api_keys=key_map, model_overrides=model_map)
    prompt = """Analyze these security log entries and provide findings with solutions.

For each security issue found, format as:
Finding: [describe the issue]
Solution: [recommended action to resolve it]

Log entries:
{lines}
"""
    if findings:
        seed_context = "\n".join([f"Detected: {f}" for f in findings])
        prompt_filled = prompt.format(lines=seed_context + "\n\n" + "\n".join([r.get("raw", "") for r in records[:200]]))
    else:
        prompt_filled = prompt.format(lines="\n".join([r.get("raw", "") for r in records[:200]]))

    prompt_tokens = 0
    try:
        prompt_tokens = llm.estimate_tokens(prompt_filled)
    except Exception:
        prompt_tokens = max(1, len(prompt_filled.split())) if prompt_filled else 0

    result = {
        "findings": findings,
        "llm_text": None,
        "llm_provider": None,
        "requested_provider": selected_provider or "auto",
        "requested_model": model_hint or None,
        "model_used": None,
        "token_usage": {
            "prompt": prompt_tokens,
            "completion": 0,
            "total": prompt_tokens,
        },
    }
    try:
        try:
            llm.ensure()
        except Exception:
            pass
        result["llm_provider"] = llm.provider or "(unspecified)"
        result["model_used"] = llm.active_model
        logger.info("Calling LLM provider: %s", result["llm_provider"])
        text = llm.generate(prompt_filled, max_tokens=256)
        result["llm_text"] = text
        try:
            completion_tokens = llm.estimate_tokens(text)
        except Exception:
            completion_tokens = max(1, len(text.split())) if text else 0
        result["token_usage"]["completion"] = completion_tokens
        result["token_usage"]["total"] = result["token_usage"]["prompt"] + completion_tokens
        
        # For local models like GPT-2 that echo the prompt, try to extract only new content
        # Remove the original prompt from the response
        clean_text = text
        if text and prompt_filled in text:
            # The model echoed the prompt, extract only what comes after
            clean_text = text.replace(prompt_filled, "").strip()
        
        # Extract meaningful lines (skip empty lines and obvious log entries)
        extra = []
        if clean_text:
            for line in clean_text.splitlines():
                stripped = line.strip()
                # Skip empty lines
                if not stripped:
                    continue
                # Skip lines that look like raw log entries (timestamps or JSON structure)
                if re.match(r'^\d{4}-\d{2}-\d{2}|^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:', stripped):
                    continue
                # Skip JSON-like lines
                if re.match(r'^[\{\[]|^"[a-z_]+"\s*:', stripped):
                    continue
                # Skip duplicate detected items
                if stripped.startswith("Detected:"):
                    continue
                # Include everything else
                extra.append(stripped)
        
        combined = findings + extra
        seen = set()
        out = []
        for item in combined:
            if item not in seen:
                seen.add(item)
                out.append(item)
        result["findings"] = out
        return result
    except Exception as e:
        logger.exception("LLM generation failed: %s", e)
        if llm and getattr(llm, "provider", None):
            result["findings"].append(f"(Info) LLM attempt with provider '{llm.provider}' failed: {e}")
        else:
            result["findings"].append(f"(Info) LLM attempt failed: {e}")
        if llm and getattr(llm, "active_model", None):
            result["model_used"] = llm.active_model
        return result
