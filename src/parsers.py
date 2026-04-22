"""Multi-format log and data parsers.

Supported formats:
- Plain text logs (syslog, firewall, generic)
- JSON / JSONL
- CSV (generic & labeled datasets)
- PCAP / PCAPNG (Wireshark captures via scapy)
"""

from typing import List, Dict, Any
import csv
import json
import random
from pathlib import Path


# ---------------------------------------------------------------------------
# Reservoir sampling helper
# ---------------------------------------------------------------------------

def _reservoir_sample(stream, k: int) -> list:
    """Uniform reservoir sample of at most k items from an iterable."""
    result = []
    for i, item in enumerate(stream):
        if i < k:
            result.append(item)
        else:
            j = random.randint(0, i)
            if j < k:
                result[j] = item
    return result


# ---------------------------------------------------------------------------
# Text / Syslog
# ---------------------------------------------------------------------------

def parse_text_log(path: Path, max_rows: int | None = None) -> List[Dict[str, Any]]:
    """Line-by-line text parser: returns one record per line with raw message.

    If max_rows is set and the file has more lines, a uniform reservoir sample
    of max_rows records is returned so large files don't overwhelm memory.
    """
    def _gen():
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for lineno, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                yield {"line": lineno, "raw": line, "type": "text"}

    if max_rows is None:
        return list(_gen())
    return _reservoir_sample(_gen(), max_rows)


# ---------------------------------------------------------------------------
# JSON / JSONL
# ---------------------------------------------------------------------------

def parse_json_log(path: Path, max_rows: int | None = None) -> List[Dict[str, Any]]:
    def _gen():
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for lineno, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(obj, dict):
                    obj.setdefault("_line", lineno)
                    obj.setdefault("type", "json")
                    yield obj
                else:
                    yield {"_line": lineno, "value": obj, "type": "json"}

    if max_rows is None:
        return list(_gen())
    return _reservoir_sample(_gen(), max_rows)


# ---------------------------------------------------------------------------
# CSV (generic)
# ---------------------------------------------------------------------------

def parse_csv_log(path: Path, max_rows: int | None = None) -> List[Dict[str, Any]]:
    def _gen():
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for lineno, row in enumerate(reader, start=1):
                row["_line"] = lineno
                row["type"] = "csv"
                yield dict(row)

    if max_rows is None:
        return list(_gen())
    return _reservoir_sample(_gen(), max_rows)


# ---------------------------------------------------------------------------
# Labeled dataset CSV
# ---------------------------------------------------------------------------

def is_labeled_dataset_csv(path: Path) -> bool:
    """Detect whether a CSV file is a labeled intrusion detection dataset."""
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            header = f.readline().lower()
            return "label" in header and ("flow duration" in header or "destination port" in header)
    except Exception:
        return False

# Backward-compatible alias
is_cicids_csv = is_labeled_dataset_csv


def parse_dataset_csv(path: Path, max_rows: int | None = None) -> List[Dict[str, Any]]:
    """Parse a labeled dataset CSV and produce records with a *raw* key for the analyzer."""
    from .dataset_loader import normalize_label

    def _gen():
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            headers = [h.strip() for h in (reader.fieldnames or [])]
            reader.fieldnames = headers
            for lineno, row in enumerate(reader, start=1):
                stripped = {k.strip(): v.strip() for k, v in row.items() if k}
                label = stripped.get("Label", "UNKNOWN")
                category = normalize_label(label)
                dst_port = stripped.get("Destination Port", "?")
                fwd_pkts = stripped.get("Total Fwd Packets", "?")
                bwd_pkts = stripped.get("Total Backward Packets", "?")
                flow_bps = stripped.get("Flow Bytes/s", "?")
                syn = stripped.get("SYN Flag Count", "0")
                raw = (
                    f"Flow: dst_port={dst_port} fwd_pkts={fwd_pkts} bwd_pkts={bwd_pkts} "
                    f"flow_bytes_s={flow_bps} syn_flags={syn} label={label}"
                )
                record: Dict[str, Any] = {
                    "_line": lineno,
                    "raw": raw,
                    "type": "dataset",
                    "_label": label,
                    "_category": category,
                }
                record.update(stripped)
                yield record

    if max_rows is None:
        return list(_gen())
    return _reservoir_sample(_gen(), max_rows)

# Backward-compatible alias
parse_cicids_csv = parse_dataset_csv


# ---------------------------------------------------------------------------
# PCAP / PCAPNG  (Wireshark captures)
# ---------------------------------------------------------------------------

def is_pcap(path: Path) -> bool:
    """Detect PCAP or PCAPNG by magic bytes."""
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
            return magic in (
                b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1",  # PCAP
                b"\x0a\x0d\x0d\x0a",                          # PCAPNG
            )
    except Exception:
        return False


def parse_pcap(path: Path, max_packets: int = 50000) -> List[Dict[str, Any]]:
    """Parse a PCAP/PCAPNG file using scapy and return structured records."""
    try:
        from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS, Raw
    except ImportError:
        raise ImportError(
            "scapy is required for PCAP parsing. Install with: pip install scapy"
        )

    packets = rdpcap(str(path), count=max_packets)
    records: List[Dict[str, Any]] = []

    for idx, pkt in enumerate(packets, start=1):
        record: Dict[str, Any] = {
            "_line": idx,
            "type": "pcap",
            "time": float(pkt.time),
            "length": len(pkt),
        }

        if IP in pkt:
            record["src_ip"] = pkt[IP].src
            record["dst_ip"] = pkt[IP].dst
            record["protocol"] = pkt[IP].proto
            record["ttl"] = pkt[IP].ttl

        if TCP in pkt:
            record["src_port"] = pkt[TCP].sport
            record["dst_port"] = pkt[TCP].dport
            record["tcp_flags"] = str(pkt[TCP].flags)
            record["proto_name"] = "TCP"
        elif UDP in pkt:
            record["src_port"] = pkt[UDP].sport
            record["dst_port"] = pkt[UDP].dport
            record["proto_name"] = "UDP"
        elif ICMP in pkt:
            record["proto_name"] = "ICMP"
            record["icmp_type"] = pkt[ICMP].type
            record["icmp_code"] = pkt[ICMP].code

        if DNS in pkt:
            record["proto_name"] = "DNS"
            try:
                if pkt[DNS].qd:
                    record["dns_query"] = pkt[DNS].qd.qname.decode(errors="ignore")
            except Exception:
                pass

        payload_len = len(pkt[Raw].load) if Raw in pkt else 0
        record["payload_length"] = payload_len

        # Build human-readable raw summary
        src = record.get("src_ip", "?")
        dst = record.get("dst_ip", "?")
        proto = record.get("proto_name", "?")
        sport = record.get("src_port", "")
        dport = record.get("dst_port", "")
        flags = record.get("tcp_flags", "")
        raw_parts = [f"{proto} {src}"]
        if sport:
            raw_parts[-1] += f":{sport}"
        raw_parts.append(f"-> {dst}")
        if dport:
            raw_parts[-1] += f":{dport}"
        if flags:
            raw_parts.append(f"[{flags}]")
        raw_parts.append(f"len={record['length']}")
        record["raw"] = " ".join(raw_parts)

        records.append(record)

    return records


# ---------------------------------------------------------------------------
# Unified dispatcher
# ---------------------------------------------------------------------------

def detect_file_type(path: Path) -> str:
    """Detect file type from content and extension."""
    if is_pcap(path):
        return "pcap"
    suf = path.suffix.lower()
    if suf in (".pcap", ".pcapng", ".cap"):
        return "pcap"
    if suf in (".jsonl", ".json"):
        return "json"
    if suf in (".csv",):
        if is_labeled_dataset_csv(path):
            return "dataset"
        return "csv"
    # Check if a .log/.txt file is actually JSON lines
    if suf in (".log", ".txt", ""):
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as f:
                first = f.readline().strip()
                if first.startswith("{") and json.loads(first):
                    return "json"
        except Exception:
            pass
    return "text"


def parse_log(path: Path, max_rows: int | None = None) -> List[Dict[str, Any]]:
    """Auto-detect format and parse the file.

    max_rows: if set, reservoir-sample the file down to this many records so
    that large files (e.g. 600 MB) don't exhaust memory.
    """
    ftype = detect_file_type(path)
    if ftype == "pcap":
        return parse_pcap(path, max_packets=max_rows or 50_000)
    if ftype == "json":
        return parse_json_log(path, max_rows=max_rows)
    if ftype == "dataset":
        return parse_dataset_csv(path, max_rows=max_rows)
    if ftype == "csv":
        return parse_csv_log(path, max_rows=max_rows)
    return parse_text_log(path, max_rows=max_rows)
