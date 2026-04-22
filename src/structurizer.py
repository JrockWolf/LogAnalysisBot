"""Unstructured log → structured record converter.

Supports the following log formats (auto-detected per line):
  - Syslog RFC 3164 (Nov 12 14:32:01 host process[pid]: msg)
  - Syslog RFC 5424 (<pri>1 timestamp host app pid msgid - msg)
  - Apache / Nginx combined access log
  - Nginx error log
  - iptables / UFW / pf firewall logs (SRC= DST= PROTO= DPT=)
  - Snort / Suricata alert format
  - Windows Event Log text exports
  - ISO 8601 / common timestamp prefix + severity bracket
  - Generic key=value / key="value" pairs
  - Plain fallback: extracts IPs, ports, severity words with regex

Output schema (None for fields absent from the line):
  timestamp, severity, severity_num, hostname, process, pid,
  src_ip, dst_ip, src_port, dst_port, protocol, action,
  user, status_code, bytes_sent, method, url, message, raw
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

# ── Compiled regex patterns ────────────────────────────────────────────────

# RFC 3164: Nov 12 14:32:01 myhost sshd[1234]: message
_SYSLOG_3164 = re.compile(
    r"^(?P<month>[A-Za-z]{3})\s{1,2}(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>[^:\[\s]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.+)$"
)

# RFC 5424: <34>1 2026-04-22T12:00:00Z host app pid msgid - msg
_SYSLOG_5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ver>\d)\s+"
    r"(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+"
    r"(?P<pid>\S+)\s+(?P<msgid>\S+)\s+(?P<sd>\S+)\s+"
    r"(?P<message>.*)$"
)

# Apache / Nginx combined access log
_APACHE_ACCESS = re.compile(
    r"^(?P<src_ip>\S+)\s+\S+\s+(?P<user>\S+)\s+"
    r'\[(?P<time>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<url>\S+)\s+\S+"\s+'
    r"(?P<status>\d{3})\s+(?P<bytes>\S+)"
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)

# Nginx error log: 2026/04/22 12:00:00 [error] 1234#0: *N msg
_NGINX_ERROR = re.compile(
    r"^(?P<date>\d{4}/\d{2}/\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"\[(?P<level>\w+)\]\s+(?P<pid>\d+)#\S+:\s+(?P<message>.*)$"
)

# ISO 8601 / common log prefix: 2026-04-22T12:00:00 [LEVEL] msg
_ISO_PREFIX = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s*"
    r"(?:\[(?P<level>[A-Za-z]+)\])?\s*"
    r"(?:(?P<process>[A-Za-z0-9_-]+)(?:\[(?P<pid>\d+)\])?:)?\s*"
    r"(?P<message>.+)$"
)

# iptables / UFW / pf firewall: keyword ... SRC=x DST=y PROTO=z SPT=a DPT=b
_IPTABLES_KVPAIRS = re.compile(
    r"(?P<action>ACCEPT|DROP|REJECT|BLOCK|DRP|ALLOW)\s*"
    r"(?:IN=(?P<in_if>\S*)\s+)?(?:OUT=(?P<out_if>\S*)\s+)?"
    r"(?:(?:MAC|PHYSIN|PHYSOUT)=\S*\s+)*"
    r"(?:SRC=(?P<src_ip>[\d.]+)\s+)?(?:DST=(?P<dst_ip>[\d.]+)\s+)?",
    re.IGNORECASE,
)
_IPTABLES_PROTO = re.compile(r"PROTO=(\w+)", re.IGNORECASE)
_IPTABLES_SPT = re.compile(r"SPT=(\d+)", re.IGNORECASE)
_IPTABLES_DPT = re.compile(r"DPT=(\d+)", re.IGNORECASE)

# Snort / Suricata alert: [gid:sid:rev] msg ... {PROTO} src:sport -> dst:dport
_SNORT = re.compile(
    r"\[\d+:\d+:\d+\]\s+(?P<message>[^{[]+)"
    r"(?:\[Classification:\s*(?P<cls>[^\]]+)\])?"
    r"(?:\s+\{(?P<proto>\w+)\})?\s+"
    r"(?P<src_ip>[\d.]+):(?P<src_port>\d+)\s*->\s*"
    r"(?P<dst_ip>[\d.]+):(?P<dst_port>\d+)"
)

# Windows Event Log text: 2026-04-22 12:00:00 EventID=N ...
_WIN_EVENT = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"EventID=(?P<event_id>\d+)\s+(?P<rest>.*)$",
    re.IGNORECASE,
)

# Generic key=value extractor (key=value or key="value")
_KV = re.compile(r'(\b\w+)\s*=\s*(?:"([^"]*?)"|(\S+?)(?=\s+\w+=|\s*$))')

# Bare IP / port / hour extraction fallbacks
_RE_IP = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\b")
_RE_PORT = re.compile(r"(?:port\s+|:)(\d{1,5})\b", re.IGNORECASE)
_RE_HOUR = re.compile(r"\b(\d{2}):(\d{2}):(\d{2})\b")

# Severity keyword lookup
_SEVERITY_MAP: Dict[str, int] = {
    "emerg": 0, "emergency": 0,
    "alert": 1,
    "crit": 2, "critical": 2,
    "error": 3, "err": 3,
    "warn": 4, "warning": 4,
    "notice": 5,
    "info": 6, "information": 6, "informational": 6,
    "debug": 7,
}
_RE_SEV = re.compile(
    r"\b(emerg(?:ency)?|alert|crit(?:ical)?|error|err|warn(?:ing)?|notice|info(?:rmation(?:al)?)?|debug)\b",
    re.IGNORECASE,
)

# Windows Event ID severity map
_WIN_EVENT_SEV: Dict[int, tuple] = {
    4624: ("info", 6),    # Successful logon
    4625: ("warning", 4), # Failed logon
    4648: ("warning", 4), # Logon with explicit credentials
    4672: ("info", 6),    # Special privileges assigned
    4688: ("info", 6),    # Process creation
    4698: ("warning", 4), # Scheduled task created
    4699: ("warning", 4), # Scheduled task deleted
    4700: ("warning", 4), # Scheduled task enabled
    4701: ("warning", 4), # Scheduled task disabled
    4719: ("critical", 2), # System audit policy changed
    4720: ("info", 6),    # User account created
    4726: ("warning", 4), # User account deleted
    4740: ("warning", 4), # Account locked out
    4756: ("warning", 4), # Member added to security group
    7045: ("warning", 4), # New service installed
}


# ── Helpers ────────────────────────────────────────────────────────────────

def _sev(word: Optional[str]) -> int:
    """Convert severity string to numeric 0–7 (lower = worse)."""
    if not word:
        return 6
    return _SEVERITY_MAP.get(word.lower().rstrip("."), 6)


def _kv(text: str) -> Dict[str, str]:
    """Extract key=value / key="value" pairs from text."""
    result: Dict[str, str] = {}
    for m in _KV.finditer(text):
        key = m.group(1).lower()
        val = m.group(2) if m.group(2) is not None else (m.group(3) or "")
        result[key] = val.strip()
    return result


def _blank(raw: str) -> Dict[str, Any]:
    """Return an empty structured record skeleton."""
    return {
        "timestamp": None,
        "severity": None,
        "severity_num": None,
        "hostname": None,
        "process": None,
        "pid": None,
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "protocol": None,
        "action": None,
        "user": None,
        "status_code": None,
        "bytes_sent": None,
        "method": None,
        "url": None,
        "message": None,
        "raw": raw,
    }


def _fill_ips_ports(rec: Dict[str, Any], text: str) -> None:
    """Best-effort extract IPs and ports from raw text into rec if not yet set."""
    if not rec["src_ip"]:
        ips = _RE_IP.findall(text)
        if ips:
            rec["src_ip"] = ips[0]
            if len(ips) > 1:
                rec["dst_ip"] = rec["dst_ip"] or ips[1]
    if not rec["src_port"]:
        ports = _RE_PORT.findall(text)
        if ports:
            try:
                rec["src_port"] = int(ports[0])
            except ValueError:
                pass
            if len(ports) > 1 and not rec["dst_port"]:
                try:
                    rec["dst_port"] = int(ports[1])
                except ValueError:
                    pass


def _fill_sev(rec: Dict[str, Any], text: str) -> None:
    """Best-effort extract severity from raw text into rec if not yet set."""
    if rec["severity"] is None:
        m = _RE_SEV.search(text)
        if m:
            rec["severity"] = m.group(1).lower()
            rec["severity_num"] = _sev(m.group(1))


def _fill_hour(rec: Dict[str, Any], ts_str: Optional[str], fallback_raw: str) -> None:
    """Parse hour from timestamp string or raw fallback."""
    source = ts_str or fallback_raw
    if source:
        m = _RE_HOUR.search(source)
        if m:
            rec["hour"] = int(m.group(1))


# ── Format-specific parsers ────────────────────────────────────────────────

def _try_syslog_3164(raw: str) -> Optional[Dict[str, Any]]:
    m = _SYSLOG_3164.match(raw)
    if not m:
        return None
    d = m.groupdict()
    rec = _blank(raw)
    rec["timestamp"] = f"{d['month']} {d['day']} {d['time']}"
    rec["hostname"] = d["host"]
    rec["process"] = d["process"]
    rec["pid"] = int(d["pid"]) if d.get("pid") else None
    msg = d["message"]
    rec["message"] = msg
    _fill_sev(rec, msg)
    _fill_ips_ports(rec, msg)
    # extract user from common patterns: "for USER from ...", "user=X"
    u = re.search(r"(?:for|user)\s+(\S+?)(?:\s|$)", msg, re.IGNORECASE)
    if u and u.group(1) not in ("from", "to", "the", "a", "an"):
        rec["user"] = u.group(1)
    # key=value from message
    pairs = _kv(msg)
    rec["user"] = rec["user"] or pairs.get("user") or pairs.get("username")
    rec["action"] = pairs.get("action") or pairs.get("event")
    rec["protocol"] = pairs.get("proto") or pairs.get("protocol")
    return rec


def _try_syslog_5424(raw: str) -> Optional[Dict[str, Any]]:
    m = _SYSLOG_5424.match(raw)
    if not m:
        return None
    d = m.groupdict()
    rec = _blank(raw)
    rec["timestamp"] = d["ts"]
    rec["hostname"] = d["host"]
    rec["process"] = d["app"]
    rec["pid"] = d["pid"] if d.get("pid") and d["pid"] != "-" else None
    rec["message"] = d["message"]
    pri = int(d.get("pri") or 48)
    sev_code = pri & 0x07
    rev_map = [k for k, v in _SEVERITY_MAP.items() if v == sev_code]
    rec["severity"] = rev_map[0] if rev_map else "info"
    rec["severity_num"] = sev_code
    _fill_ips_ports(rec, d["message"])
    return rec


def _try_apache_access(raw: str) -> Optional[Dict[str, Any]]:
    m = _APACHE_ACCESS.match(raw)
    if not m:
        return None
    d = m.groupdict()
    rec = _blank(raw)
    rec["src_ip"] = d["src_ip"]
    rec["timestamp"] = d["time"]
    rec["user"] = d["user"] if d["user"] != "-" else None
    rec["method"] = d["method"]
    rec["url"] = d["url"]
    try:
        rec["status_code"] = int(d["status"])
    except (TypeError, ValueError):
        pass
    if d.get("bytes") and d["bytes"] != "-":
        try:
            rec["bytes_sent"] = int(d["bytes"])
        except ValueError:
            pass
    sc = rec["status_code"]
    if sc:
        if sc >= 500:
            rec["severity"] = "error"; rec["severity_num"] = 3
        elif sc >= 400:
            rec["severity"] = "warning"; rec["severity_num"] = 4
        else:
            rec["severity"] = "info"; rec["severity_num"] = 6
    rec["protocol"] = "HTTP"
    rec["message"] = f'{d["method"]} {d["url"]} → {d["status"]}'
    return rec


def _try_nginx_error(raw: str) -> Optional[Dict[str, Any]]:
    m = _NGINX_ERROR.match(raw)
    if not m:
        return None
    d = m.groupdict()
    rec = _blank(raw)
    rec["timestamp"] = f'{d["date"]} {d["time"]}'
    rec["severity"] = d["level"].lower()
    rec["severity_num"] = _sev(d["level"])
    rec["pid"] = int(d["pid"]) if d.get("pid") else None
    rec["message"] = d["message"]
    rec["process"] = "nginx"
    _fill_ips_ports(rec, d["message"])
    return rec


def _try_iso_prefix(raw: str) -> Optional[Dict[str, Any]]:
    m = _ISO_PREFIX.match(raw)
    if not m:
        return None
    d = m.groupdict()
    # Only accept if timestamp was captured
    if not d.get("ts"):
        return None
    rec = _blank(raw)
    rec["timestamp"] = d["ts"]
    if d.get("level"):
        rec["severity"] = d["level"].lower()
        rec["severity_num"] = _sev(d["level"])
    rec["process"] = d.get("process")
    rec["pid"] = int(d["pid"]) if d.get("pid") else None
    rec["message"] = d.get("message", "").strip()
    _fill_sev(rec, rec["message"] or raw)
    _fill_ips_ports(rec, rec["message"] or raw)
    pairs = _kv(rec["message"] or raw)
    rec["src_ip"] = rec["src_ip"] or pairs.get("src") or pairs.get("srcip") or pairs.get("src_ip")
    rec["dst_ip"] = rec["dst_ip"] or pairs.get("dst") or pairs.get("dstip") or pairs.get("dst_ip")
    rec["user"] = pairs.get("user") or pairs.get("username")
    rec["action"] = pairs.get("action") or pairs.get("event")
    return rec


def _try_iptables(raw: str) -> Optional[Dict[str, Any]]:
    # Must contain at least SRC= or DST= to qualify
    upper = raw.upper()
    if "SRC=" not in upper and "DST=" not in upper:
        return None
    rec = _blank(raw)
    m = _IPTABLES_KVPAIRS.search(raw)
    if m:
        d = m.groupdict()
        rec["action"] = (d.get("action") or "").upper() or None
        rec["src_ip"] = d.get("src_ip")
        rec["dst_ip"] = d.get("dst_ip")
    else:
        # Fallback: parse SRC= / DST= individually
        src = re.search(r"SRC=([\d.]+)", raw, re.IGNORECASE)
        dst = re.search(r"DST=([\d.]+)", raw, re.IGNORECASE)
        rec["src_ip"] = src.group(1) if src else None
        rec["dst_ip"] = dst.group(1) if dst else None
        act = re.search(r"\b(ACCEPT|DROP|REJECT|BLOCK|DRP|ALLOW)\b", raw, re.IGNORECASE)
        rec["action"] = act.group(1).upper() if act else None

    pm = _IPTABLES_PROTO.search(raw)
    if pm:
        rec["protocol"] = pm.group(1).upper()
    sm = _IPTABLES_SPT.search(raw)
    if sm:
        try:
            rec["src_port"] = int(sm.group(1))
        except ValueError:
            pass
    dm = _IPTABLES_DPT.search(raw)
    if dm:
        try:
            rec["dst_port"] = int(dm.group(1))
        except ValueError:
            pass

    action = rec["action"] or ""
    if action in ("DROP", "REJECT", "BLOCK", "DRP"):
        rec["severity"] = "warning"; rec["severity_num"] = 4
    else:
        rec["severity"] = "info"; rec["severity_num"] = 6

    ts_m = _RE_HOUR.search(raw)
    if ts_m:
        rec["timestamp"] = f"{ts_m.group(1)}:{ts_m.group(2)}:{ts_m.group(3)}"
    rec["message"] = raw.strip()
    return rec


def _try_snort(raw: str) -> Optional[Dict[str, Any]]:
    m = _SNORT.search(raw)
    if not m:
        return None
    d = m.groupdict()
    rec = _blank(raw)
    rec["message"] = d["message"].strip()
    rec["protocol"] = (d.get("proto") or "").upper() or None
    rec["src_ip"] = d.get("src_ip")
    rec["dst_ip"] = d.get("dst_ip")
    try:
        rec["src_port"] = int(d["src_port"]) if d.get("src_port") else None
        rec["dst_port"] = int(d["dst_port"]) if d.get("dst_port") else None
    except ValueError:
        pass
    rec["severity"] = "alert"; rec["severity_num"] = 1
    rec["action"] = "ALERT"
    return rec


def _try_windows_event(raw: str) -> Optional[Dict[str, Any]]:
    m = _WIN_EVENT.match(raw)
    if not m:
        return None
    d = m.groupdict()
    rec = _blank(raw)
    rec["timestamp"] = f'{d["date"]} {d["time"]}'
    event_id = int(d["event_id"])
    sev_pair = _WIN_EVENT_SEV.get(event_id, ("info", 6))
    rec["severity"] = sev_pair[0]; rec["severity_num"] = sev_pair[1]
    rec["action"] = f"EventID={event_id}"
    rest = d.get("rest", "")
    pairs = _kv(rest)
    rec["user"] = pairs.get("targetusername") or pairs.get("subjectusername") or pairs.get("user")
    rec["src_ip"] = pairs.get("ipaddress") or pairs.get("sourceaddress") or pairs.get("src_ip")
    rec["message"] = rest.strip()
    return rec


def _try_kv_generic(raw: str) -> Optional[Dict[str, Any]]:
    """Parse lines with 3+ key=value pairs."""
    pairs = _kv(raw)
    if len(pairs) < 3:
        return None
    rec = _blank(raw)

    # Timestamp keys
    for k in ("timestamp", "time", "ts", "datetime", "date"):
        if k in pairs and pairs[k]:
            rec["timestamp"] = pairs[k]
            break

    # IP keys
    for k in ("src_ip", "src", "sip", "sourceip", "source_ip", "client_ip", "remote_ip"):
        if k in pairs and pairs[k]:
            rec["src_ip"] = pairs[k]
            break
    for k in ("dst_ip", "dst", "dip", "destip", "dest_ip", "destination_ip", "server_ip"):
        if k in pairs and pairs[k]:
            rec["dst_ip"] = pairs[k]
            break

    # Port keys
    for k in ("sport", "src_port", "spt", "source_port"):
        if k in pairs and pairs[k]:
            try: rec["src_port"] = int(pairs[k])
            except ValueError: pass
            break
    for k in ("dport", "dst_port", "dpt", "dest_port", "destination_port"):
        if k in pairs and pairs[k]:
            try: rec["dst_port"] = int(pairs[k])
            except ValueError: pass
            break

    # Other fields
    rec["protocol"] = pairs.get("proto") or pairs.get("protocol")
    rec["action"] = pairs.get("action") or pairs.get("type") or pairs.get("event")
    rec["user"] = pairs.get("user") or pairs.get("username") or pairs.get("usr")
    rec["process"] = pairs.get("process") or pairs.get("proc") or pairs.get("app")
    rec["hostname"] = pairs.get("host") or pairs.get("hostname") or pairs.get("server")

    # Message
    rec["message"] = pairs.get("msg") or pairs.get("message") or pairs.get("description") or raw.strip()

    # Severity
    lev = pairs.get("level") or pairs.get("severity") or pairs.get("priority") or pairs.get("sev")
    if lev:
        rec["severity"] = lev.lower()
        rec["severity_num"] = _sev(lev)
    else:
        _fill_sev(rec, raw)

    # HTTP fields
    if "method" in pairs:
        rec["method"] = pairs["method"].upper()
    if "url" in pairs or "uri" in pairs or "path" in pairs:
        rec["url"] = pairs.get("url") or pairs.get("uri") or pairs.get("path")
    for k in ("status", "status_code", "http_status", "response_code"):
        if k in pairs:
            try: rec["status_code"] = int(pairs[k])
            except ValueError: pass
            break
    for k in ("bytes", "bytes_sent", "size", "content_length"):
        if k in pairs:
            try: rec["bytes_sent"] = int(pairs[k])
            except ValueError: pass
            break

    # Fill missing IPs from fallback regex if not found in kv
    if not rec["src_ip"]:
        _fill_ips_ports(rec, raw)
    return rec


def _fallback(raw: str) -> Dict[str, Any]:
    """Last-resort extraction: IPs, ports, severity, timestamp from raw text."""
    rec = _blank(raw)
    rec["message"] = raw.strip()
    _fill_ips_ports(rec, raw)
    _fill_sev(rec, raw)
    m = _RE_HOUR.search(raw)
    if m:
        rec["timestamp"] = f"{m.group(1)}:{m.group(2)}:{m.group(3)}"
    return rec


# ── Public API ─────────────────────────────────────────────────────────────

# Format detection order (most specific → least specific)
_PARSERS = [
    _try_syslog_3164,
    _try_apache_access,
    _try_nginx_error,
    _try_syslog_5424,
    _try_snort,
    _try_windows_event,
    _try_iptables,
    _try_iso_prefix,
    _try_kv_generic,
]


def structurize_line(raw: str) -> Dict[str, Any]:
    """Parse a single raw log line into a structured record.

    Tries each format parser in order and returns the first successful match.
    Falls back to regex-based extraction if no format matches.
    """
    stripped = raw.strip()
    if not stripped:
        return _blank(raw)
    for parser in _PARSERS:
        result = parser(stripped)
        if result is not None:
            return result
    return _fallback(stripped)


def _is_already_structured(rec: Dict[str, Any]) -> bool:
    """Return True if the record already has meaningful structured fields."""
    structural_keys = {
        "src_ip", "dst_ip", "src_port", "dst_port",
        "status_code", "method", "url", "protocol",
    }
    return any(rec.get(k) is not None for k in structural_keys)


def structurize_records(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Convert a list of raw text records into structured records.

    Skips records that are already structured (PCAP, labeled CSV, JSON with
    real fields) to avoid double-processing.  Returns a new list; originals
    are not mutated.
    """
    out: List[Dict[str, Any]] = []
    for rec in records:
        rtype = rec.get("type", "text")
        # Skip already-structured record types
        if rtype in ("pcap", "dataset"):
            out.append(rec)
            continue
        if rtype in ("csv", "json") and _is_already_structured(rec):
            out.append(rec)
            continue
        raw = str(rec.get("raw", "") or rec.get("message", "") or "")
        if not raw:
            out.append(rec)
            continue
        structured = structurize_line(raw)
        # Merge: structured values overwrite only None slots in original
        merged = dict(rec)
        for k, v in structured.items():
            if v is not None:
                merged[k] = v
        out.append(merged)
    return out


def structurize_summary(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Return structurization coverage stats for a record set."""
    total = len(records)
    if total == 0:
        return {
            "total": 0,
            "structured_count": 0,
            "structured_pct": 0.0,
            "field_coverage": {},
            "detected_formats": {},
        }

    schema_fields = [
        "timestamp", "severity", "hostname", "src_ip", "dst_ip",
        "src_port", "dst_port", "protocol", "action", "user",
        "status_code", "method", "message",
    ]

    field_counts: Dict[str, int] = {f: 0 for f in schema_fields}
    structured_count = 0
    presence_fields = {"timestamp", "src_ip", "severity", "action", "method"}

    # Detect format distribution heuristically
    fmt_counts: Dict[str, int] = {}
    for rec in records:
        has_any = False
        for f in schema_fields:
            if rec.get(f) is not None:
                field_counts[f] += 1
        if any(rec.get(f) is not None for f in presence_fields):
            structured_count += 1
            has_any = True
        # Infer format
        if rec.get("method"):
            fmt = "HTTP access log"
        elif rec.get("action") in ("DROP", "REJECT", "BLOCK", "ACCEPT", "DRP"):
            fmt = "Firewall log"
        elif rec.get("hostname") and rec.get("process"):
            fmt = "Syslog"
        elif rec.get("status_code"):
            fmt = "HTTP access log"
        elif rec.get("url"):
            fmt = "HTTP access log"
        elif has_any:
            fmt = "Generic / key-value"
        else:
            fmt = "Unrecognised"
        fmt_counts[fmt] = fmt_counts.get(fmt, 0) + 1

    return {
        "total": total,
        "structured_count": structured_count,
        "structured_pct": round(structured_count / total * 100, 1),
        "field_coverage": {
            f: round(field_counts[f] / total * 100, 1) for f in schema_fields
        },
        "detected_formats": fmt_counts,
    }
