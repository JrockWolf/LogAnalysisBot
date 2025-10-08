from pathlib import Path
from typing import List, Dict, Any
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
    prompt = """
You are a security analyst assistant. Given the following log lines, extract up to 5 succinct findings in plain language along with suggested immediate responses. Format each finding as: "Finding: ... | Response: ...".

Log lines:
{lines}
"""
    if findings:
        # if heuristics already found things, prepend them as context
        seed_context = "\n".join([f"Heuristic: {f}" for f in findings])
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


def analyze_logs_with_llm(path: Path) -> Dict[str, Any]:
    """Return a dict with findings, llm_text (raw), and llm_provider for the web UI."""
    records = parse_log(path)
    findings = heuristic_detect(records)
    llm = LLMAdapter()
    prompt = """
You are a security analyst assistant. Given the following log lines, extract up to 5 succinct findings in plain language along with suggested immediate responses. Format each finding as: "Finding: ... | Response: ...".

Log lines:
{lines}
"""
    if findings:
        seed_context = "\n".join([f"Heuristic: {f}" for f in findings])
        prompt_filled = prompt.format(lines=seed_context + "\n\n" + "\n".join([r.get("raw", "") for r in records[:200]]))
    else:
        prompt_filled = prompt.format(lines="\n".join([r.get("raw", "") for r in records[:200]]))

    result = {"findings": findings, "llm_text": None, "llm_provider": None}
    try:
        try:
            llm.ensure()
        except Exception:
            pass
        result["llm_provider"] = llm.provider or "(unspecified)"
        logger.info("Calling LLM provider: %s", result["llm_provider"])
        text = llm.generate(prompt_filled, max_tokens=256)
        result["llm_text"] = text
        extra = [line.strip() for line in (text or "").splitlines() if line.strip()]
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
        return result
