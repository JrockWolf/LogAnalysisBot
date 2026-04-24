"""Structured output schema for LogAnalysisBot.

Defines the Pydantic models that form the public contract for all analysis
results.  Every analysis path — CLI, Web UI, direct Python API — should
ultimately return an :class:`AnalysisResult`.

JSON output example
-------------------
::

    {
      "file": "firewall.log",
      "analyzed_at": "2026-04-24T10:00:00Z",
      "record_count": 4200,
      "redacted": true,
      "findings": [
        {
          "id": "f-001",
          "severity": "high",
          "confidence": 0.91,
          "category": "Brute Force",
          "description": "Multiple failed SSH logins from [IP_0] (14 attempts)",
          "evidence": [
            {"line_number": 42, "raw": "Failed password for root from [IP_0] port 2222"}
          ],
          "mitre": [
            {
              "technique_id": "T1110.001",
              "name": "Password Guessing",
              "tactic": "Credential Access",
              "url": "https://attack.mitre.org/techniques/T1110/001/"
            }
          ],
          "method": "heuristic"
        }
      ],
      "summary": "14 high-severity findings...",
      "llm_provider": "openai"
    }
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

try:
    from pydantic import BaseModel, Field
    _PYDANTIC = True
except ImportError:  # pragma: no cover
    # Lightweight fallback for environments without pydantic
    from dataclasses import dataclass as _dc, field as _field  # noqa: F401
    BaseModel = object  # type: ignore[assignment,misc]
    _PYDANTIC = False


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------

class Evidence(BaseModel if _PYDANTIC else object):  # type: ignore[misc]
    """A single log line that provides evidence for a finding."""

    line_number: Optional[int] = None
    """1-based line number in the source file, if known."""

    raw: str = ""
    """Raw (possibly redacted) log line text."""

    if not _PYDANTIC:
        def __init__(self, line_number=None, raw=""):
            self.line_number = line_number
            self.raw = raw

    def to_dict(self) -> Dict[str, Any]:
        return {"line_number": self.line_number, "raw": self.raw}


class MitreTechniqueRef(BaseModel if _PYDANTIC else object):  # type: ignore[misc]
    """A reference to a MITRE ATT&CK technique."""

    technique_id: str = ""
    name: str = ""
    tactic: str = ""
    url: str = ""

    if not _PYDANTIC:
        def __init__(self, technique_id="", name="", tactic="", url=""):
            self.technique_id = technique_id
            self.name = name
            self.tactic = tactic
            self.url = url

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "tactic": self.tactic,
            "url": self.url,
        }


class Finding(BaseModel if _PYDANTIC else object):  # type: ignore[misc]
    """A single threat finding with evidence links and MITRE mapping."""

    id: str = ""
    """Unique identifier within this result set (e.g. "f-001")."""

    severity: str = "medium"
    """'critical', 'high', 'medium', 'low', or 'info'."""

    confidence: float = 0.5
    """Confidence score in the range [0, 1]."""

    category: str = ""
    """Attack/anomaly category (e.g. "Brute Force", "DoS", "ML Anomaly")."""

    description: str = ""
    """Human-readable description of the finding."""

    evidence: List[Evidence] = []
    """Log lines that triggered or support this finding."""

    mitre: List[MitreTechniqueRef] = []
    """MITRE ATT&CK technique references mapped from the category."""

    method: str = "heuristic"
    """Detection method that produced this finding."""

    if not _PYDANTIC:
        def __init__(self, id="", severity="medium", confidence=0.5, category="",
                     description="", evidence=None, mitre=None, method="heuristic"):
            self.id = id
            self.severity = severity
            self.confidence = confidence
            self.category = category
            self.description = description
            self.evidence = evidence or []
            self.mitre = mitre or []
            self.method = method

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "severity": self.severity,
            "confidence": self.confidence,
            "category": self.category,
            "description": self.description,
            "evidence": [e.to_dict() for e in self.evidence],
            "mitre": [m.to_dict() for m in self.mitre],
            "method": self.method,
        }


# ---------------------------------------------------------------------------
# Top-level result
# ---------------------------------------------------------------------------

class AnalysisResult(BaseModel if _PYDANTIC else object):  # type: ignore[misc]
    """The complete structured output of a LogAnalysisBot analysis run."""

    file: Optional[str] = None
    """Path or name of the analyzed file."""

    analyzed_at: Optional[str] = None
    """ISO 8601 UTC timestamp of when analysis was run."""

    record_count: int = 0
    """Total number of log records ingested."""

    redacted: bool = False
    """Whether PII redaction was applied before LLM calls."""

    findings: List[Finding] = []
    """Ranked list of findings (highest confidence first)."""

    summary: Optional[str] = None
    """One-paragraph triage narrative (from LLM or auto-generated)."""

    llm_provider: Optional[str] = None
    """LLM provider used for the narrative, if any."""

    if not _PYDANTIC:
        def __init__(self, file=None, analyzed_at=None, record_count=0, redacted=False,
                     findings=None, summary=None, llm_provider=None):
            self.file = file
            self.analyzed_at = analyzed_at
            self.record_count = record_count
            self.redacted = redacted
            self.findings = findings or []
            self.summary = summary
            self.llm_provider = llm_provider

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file": self.file,
            "analyzed_at": self.analyzed_at,
            "record_count": self.record_count,
            "redacted": self.redacted,
            "findings": [f.to_dict() for f in self.findings],
            "summary": self.summary,
            "llm_provider": self.llm_provider,
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize to a JSON string."""
        import json
        return json.dumps(self.to_dict(), indent=indent, default=str)

    @property
    def high_severity_count(self) -> int:
        return sum(1 for f in self.findings if f.severity in ("critical", "high"))

    @property
    def finding_count(self) -> int:
        return len(self.findings)
