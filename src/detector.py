"""Detector — stage 3 of the parse → normalize → detect → summarize pipeline.

Combines rule-based heuristics with six ML anomaly detection models and
returns a list of :class:`FindingCandidate` objects ready for the Summarizer.

Heuristic detection is always fast and has no dependencies beyond the standard
library.  ML models require scikit-learn / numpy but degrade gracefully when
those libraries are unavailable.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("logbot.detector")

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class FindingCandidate:
    """An unranked threat signal produced by a single detection method."""

    category: str
    """Attack/anomaly category (e.g. "Brute Force", "DoS", "ML Anomaly")."""

    description: str
    """Human-readable description of the finding."""

    severity: str = "medium"
    """'critical', 'high', 'medium', 'low', or 'info'."""

    confidence: float = 0.5
    """0.0 – 1.0 confidence estimate."""

    evidence_indices: List[int] = field(default_factory=list)
    """Indices into the original record list that triggered this finding."""

    method: str = "heuristic"
    """Detection method: 'heuristic', 'isolation_forest', 'lof', 'svm',
    'dbscan', 'random_forest', 'lstm_autoencoder', 'ensemble', or
    'ml_consensus'."""

    ml_model_votes: int = 0
    """Number of ML models that flagged this record (for ensemble findings)."""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def detect(records: List[Dict[str, Any]], run_ml: bool = True) -> List[FindingCandidate]:
    """Run all detectors against *records* and return combined findings.

    Parameters
    ----------
    records:
        Normalized records (output of ``src.normalizer.normalize``).
    run_ml:
        Whether to also run the six ML anomaly models.  Set to ``False`` for
        unit tests or large batches where only heuristics are needed.

    Returns
    -------
    List of :class:`FindingCandidate` sorted by descending confidence.
    """
    candidates: List[FindingCandidate] = []

    # Stage A: heuristic rules (always runs)
    candidates.extend(_heuristic_candidates(records))

    # Stage B: ML anomaly models
    if run_ml and records:
        try:
            candidates.extend(_ml_candidates(records))
        except Exception as exc:  # noqa: BLE001
            logger.warning("ML detection skipped: %s", exc)

    # Sort by confidence descending
    candidates.sort(key=lambda c: c.confidence, reverse=True)
    return candidates


# ---------------------------------------------------------------------------
# Heuristic detection
# ---------------------------------------------------------------------------

def _heuristic_candidates(records: List[Dict[str, Any]]) -> List[FindingCandidate]:
    """Thin wrapper: delegate to the established heuristic engine in analyzer.py."""
    from .analyzer import heuristic_detect

    raw_findings: List[str] = heuristic_detect(records)
    out: List[FindingCandidate] = []

    # Map text strings → FindingCandidates with lightweight keyword parsing
    for idx, text in enumerate(raw_findings):
        cat, sev, conf = _classify_finding_text(text)
        out.append(
            FindingCandidate(
                category=cat,
                description=text,
                severity=sev,
                confidence=conf,
                evidence_indices=_find_evidence_indices(text, records),
                method="heuristic",
            )
        )
    return out


_SEVERITY_KEYWORDS = {
    "critical":   ("critical", 0.95),
    "flood":      ("high",     0.85),
    "ddos":       ("high",     0.88),
    "dos":        ("high",     0.85),
    "brute":      ("high",     0.82),
    "scan":       ("medium",   0.70),
    "port scan":  ("medium",   0.72),
    "botnet":     ("high",     0.80),
    "infiltration": ("high",   0.83),
    "web attack": ("high",     0.80),
    "sql":        ("high",     0.80),
    "xss":        ("medium",   0.70),
    "exploit":    ("high",     0.85),
    "privilege":  ("high",     0.82),
    "shadow":     ("critical", 0.90),
    "exfiltration": ("high",   0.88),
    "malicious":  ("medium",   0.65),
    "anomaly":    ("medium",   0.60),
}


def _classify_finding_text(text: str) -> tuple[str, str, float]:
    """Return (category, severity, confidence) by scanning finding text."""
    lower = text.lower()
    for kw, (sev, conf) in _SEVERITY_KEYWORDS.items():
        if kw in lower:
            # Derive category from keyword
            cat = kw.replace(" ", "_").title()
            return cat, sev, conf
    return "General", "info", 0.40


def _find_evidence_indices(finding_text: str, records: List[Dict[str, Any]]) -> List[int]:
    """Return up to 5 record indices whose raw text is semantically related."""
    import re

    # Pull IPs / keywords from the finding text for matching
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", finding_text)
    kws = re.findall(
        r"\b(brute|scan|flood|ddos|dos|ssh|http|failed|denied|shadow|exploit)\b",
        finding_text,
        re.IGNORECASE,
    )

    matched: List[int] = []
    for i, rec in enumerate(records):
        raw = str(rec.get("raw", "") or rec.get("message", ""))
        if ips and any(ip in raw for ip in ips):
            matched.append(i)
        elif kws and any(kw.lower() in raw.lower() for kw in kws):
            matched.append(i)
        if len(matched) >= 5:
            break
    return matched


# ---------------------------------------------------------------------------
# ML anomaly detection
# ---------------------------------------------------------------------------

def _ml_candidates(records: List[Dict[str, Any]]) -> List[FindingCandidate]:
    """Run all available ML models and return consensus-flagged candidates."""
    from .pipeline import run_all_models

    all_results = run_all_models(records)
    # Exclude the synthetic 'ensemble' key — we recompute consensus ourselves
    model_results = {k: v for k, v in all_results.items() if k != "ensemble"}

    if not model_results:
        return []

    # Count votes per record index
    vote_counts: Dict[int, int] = {}
    for result in model_results.values():
        for idx in result.get("anomaly_indices", []):
            vote_counts[idx] = vote_counts.get(idx, 0) + 1

    # Promote records with ≥2 votes to findings
    candidates: List[FindingCandidate] = []
    for idx, votes in sorted(vote_counts.items(), key=lambda x: -x[1]):
        if votes < 2:
            continue
        rec = records[idx]
        raw_preview = str(rec.get("raw", "") or rec.get("message", ""))[:120]
        conf = min(0.95, 0.50 + votes * 0.10)
        sev = "high" if votes >= 4 else "medium"
        candidates.append(
            FindingCandidate(
                category="ML Anomaly",
                description=(
                    f"ML consensus anomaly ({votes}/{len(model_results)} models agree"
                    f"{', incl. LSTM sequence analysis' if votes >= 2 else ''}): "
                    f"{raw_preview}"
                ),
                severity=sev,
                confidence=conf,
                evidence_indices=[idx],
                method="ml_consensus",
                ml_model_votes=votes,
            )
        )

    return candidates
