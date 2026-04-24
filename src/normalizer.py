"""Normalizer — stage 2 of the parse → normalize → detect → summarize pipeline.

Converts raw records produced by ``src.parsers`` into a typed schema with
consistent field names:

    timestamp, severity, severity_num, hostname, process, pid,
    src_ip, dst_ip, src_port, dst_port, protocol, action,
    user, status_code, bytes_sent, method, url, message, raw

Records that are already structured (CSV dataset rows, JSON objects) pass
through with their existing fields intact; only text/syslog records are
actively structurized.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .structurizer import structurize_record, structurize_records as _structurize_records


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------

def normalize(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Normalize *records* in-place and return the list.

    - Text / syslog records (``type == "text"``) are structurized via the
      full regex engine in ``src.structurizer``.
    - JSON / CSV / PCAP / dataset records keep their existing fields; a best-
      effort pass extracts severity, IPs, and ports from any ``raw`` field
      that is present.

    Parameters
    ----------
    records:
        Raw records as returned by ``src.parsers.parse_log``.

    Returns
    -------
    The same list with records mutated in-place (structured fields added).
    """
    if not records:
        return records

    rec_type = records[0].get("type", "")

    if rec_type in ("text", "json"):
        # Full structurization pass
        return _structurize_records(records)

    # For CSV/dataset/PCAP records perform a lightweight enrichment pass
    for rec in records:
        _enrich_severity(rec)

    return records


def normalize_one(record: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a single record.  Returns the mutated dict."""
    rec_type = record.get("type", "")
    if rec_type in ("text", "json"):
        return structurize_record(record.get("raw", "") or record.get("message", ""))
    _enrich_severity(record)
    return record


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SEV_KEYWORDS: List[tuple[str, int]] = [
    ("critical", 2),
    ("crit",     2),
    ("fatal",    2),
    ("panic",    2),
    ("error",    3),
    ("err",      3),
    ("warning",  4),
    ("warn",     4),
    ("notice",   5),
    ("info",     6),
    ("debug",    7),
]

_SEV_NAME: Dict[int, str] = {
    2: "critical", 3: "error", 4: "warning",
    5: "notice",   6: "info",  7: "debug",
}


def _enrich_severity(record: Dict[str, Any]) -> None:
    """Best-effort severity injection from ``raw`` when not already set."""
    if record.get("severity_num") is not None:
        return

    raw = str(record.get("raw", "") or record.get("message", "")).lower()
    if not raw:
        return

    for kw, num in _SEV_KEYWORDS:
        if kw in raw:
            record["severity_num"] = num
            record.setdefault("severity", _SEV_NAME[num])
            return
