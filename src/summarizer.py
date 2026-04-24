"""Summarizer — stage 4 of the parse → normalize → detect → summarize pipeline.

Takes :class:`~src.detector.FindingCandidate` objects and a list of normalized
records, attaches evidence lines, maps MITRE techniques, calls the optional LLM
for a narrative, and returns a populated :class:`~src.output_schema.AnalysisResult`.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .detector import FindingCandidate
from .mitre_mapping import map_category_to_mitre
from .output_schema import AnalysisResult, Evidence, Finding, MitreTechniqueRef

logger = logging.getLogger("logbot.summarizer")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def summarize(
    candidates: List[FindingCandidate],
    records: List[Dict[str, Any]],
    file_path: Optional[Path] = None,
    redacted: bool = False,
    llm_provider: Optional[str] = None,
    llm_api_key: Optional[str] = None,
    llm_model: Optional[str] = None,
    max_findings: int = 50,
) -> AnalysisResult:
    """Convert raw detection candidates into a structured :class:`AnalysisResult`.

    Parameters
    ----------
    candidates:
        Output of :func:`src.detector.detect`.
    records:
        Normalized records (used to attach evidence lines).
    file_path:
        Path to the analyzed file — stored in result metadata.
    redacted:
        Whether the records have already been redacted.
    llm_provider:
        LLM provider name for narrative generation ('openai', 'gemini', …).
        ``None`` skips the LLM call.
    llm_api_key:
        API key for the chosen provider.
    llm_model:
        Model name / identifier override.
    max_findings:
        Cap on the number of findings returned (highest confidence first).
    """
    # Deduplicate and rank candidates
    ranked = _deduplicate(candidates)[:max_findings]

    # Build Finding objects
    findings: List[Finding] = []
    for i, cand in enumerate(ranked):
        evidence = _build_evidence(cand.evidence_indices, records)
        mitre_refs = _build_mitre_refs(cand.category)

        findings.append(
            Finding(
                id=f"f-{i + 1:03d}",
                severity=cand.severity,
                confidence=round(cand.confidence, 3),
                category=cand.category,
                description=cand.description,
                evidence=evidence,
                mitre=mitre_refs,
                method=cand.method,
            )
        )

    # Optional LLM narrative
    narrative: Optional[str] = None
    llm_provider_used: Optional[str] = None
    if llm_provider or os.getenv("OPENAI_API_KEY") or os.getenv("GEMINI_API_KEY") \
            or os.getenv("PERPLEXITY_API_KEY") or os.getenv("DEEPSEEK_API_KEY") \
            or os.getenv("HF_MODEL"):
        narrative, llm_provider_used = _generate_narrative(
            findings, records, llm_provider, llm_api_key, llm_model
        )

    # Build one-line summary even without LLM
    if not narrative:
        narrative = _fallback_summary(findings, len(records))

    return AnalysisResult(
        file=str(file_path) if file_path else None,
        analyzed_at=datetime.now(timezone.utc).isoformat(),
        record_count=len(records),
        redacted=redacted,
        findings=findings,
        summary=narrative,
        llm_provider=llm_provider_used,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _deduplicate(candidates: List[FindingCandidate]) -> List[FindingCandidate]:
    """Remove near-duplicate findings (same category + very similar description)."""
    seen: set[str] = set()
    out: List[FindingCandidate] = []
    for c in candidates:
        # Key on category + first 80 chars of description
        key = (c.category.lower(), c.description[:80].lower())
        if key not in seen:
            seen.add(key)
            out.append(c)
    return out


def _build_evidence(indices: List[int], records: List[Dict[str, Any]]) -> List[Evidence]:
    """Pull evidence lines from *records* at the given *indices*."""
    evidence: List[Evidence] = []
    for idx in indices[:10]:  # cap at 10 evidence lines per finding
        if idx >= len(records):
            continue
        rec = records[idx]
        raw = str(rec.get("raw", "") or rec.get("message", ""))
        line_num = rec.get("_line") or rec.get("line")
        evidence.append(Evidence(line_number=line_num, raw=raw[:500]))
    return evidence


def _build_mitre_refs(category: str) -> List[MitreTechniqueRef]:
    """Map a category name to MITRE ATT&CK technique references."""
    techniques = map_category_to_mitre(category)
    refs: List[MitreTechniqueRef] = []
    for tech in techniques:
        refs.append(
            MitreTechniqueRef(
                technique_id=tech.technique_id,
                name=tech.name,
                tactic=tech.tactic,
                url=tech.url,
            )
        )
    return refs


def _generate_narrative(
    findings: List[Finding],
    records: List[Dict[str, Any]],
    provider: Optional[str],
    api_key: Optional[str],
    model: Optional[str],
) -> tuple[Optional[str], Optional[str]]:
    """Call the LLM to produce an analyst-style narrative paragraph."""
    from .llm_adapter import LLMAdapter

    key_map: Dict[str, str] = {}
    if provider and api_key:
        key_map[provider] = api_key

    model_map: Dict[str, str] = {}
    if provider and model:
        model_map[provider] = model

    llm = LLMAdapter(provider=provider, api_keys=key_map, model_overrides=model_map)

    high_findings = [f for f in findings if f.severity in ("critical", "high")]
    finding_lines = "\n".join(
        f"- [{f.severity.upper()}] {f.category}: {f.description}" for f in findings[:20]
    )
    prompt = (
        f"You are a SOC analyst. Write a concise triage paragraph (3-5 sentences) "
        f"for the following {len(findings)} security findings. Focus on the highest-severity "
        f"items and recommend immediate next steps.\n\nFindings:\n{finding_lines}"
    )

    try:
        llm.ensure()
        text = llm.generate_with_timeout(prompt, max_tokens=200, timeout_seconds=30)
        return text, llm.provider
    except Exception as exc:
        logger.warning("LLM narrative failed: %s", exc)
        return None, None


def _fallback_summary(findings: List[Finding], record_count: int) -> str:
    if not findings:
        return f"No threats detected across {record_count} records."

    high = sum(1 for f in findings if f.severity in ("critical", "high"))
    med = sum(1 for f in findings if f.severity == "medium")
    cats = list(dict.fromkeys(f.category for f in findings))  # preserve order, dedupe
    top_cats = ", ".join(cats[:3])
    return (
        f"{len(findings)} finding(s) across {record_count} records. "
        f"{high} high/critical, {med} medium. "
        f"Top categories: {top_cats}."
    )
