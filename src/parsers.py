from typing import List, Dict, Any
import csv
import json
from pathlib import Path


def parse_text_log(path: Path) -> List[Dict[str, Any]]:
    """Very simple text parser: returns one record per line with raw message."""
    records = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            records.append({"line": lineno, "raw": line, "type": "text"})
    return records


def parse_json_log(path: Path) -> List[Dict[str, Any]]:
    records = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                # try to recover by skipping
                continue
            if isinstance(obj, dict):
                obj.setdefault("_line", lineno)
                records.append(obj)
            else:
                records.append({"_line": lineno, "value": obj})
    return records


def parse_csv_log(path: Path) -> List[Dict[str, Any]]:
    records = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for lineno, row in enumerate(reader, start=1):
            row.setdefault("_line", lineno)
            records.append(row)
    return records


def is_cicids_csv(path: Path) -> bool:
    """Detect whether a CSV file is a CIC-IDS2017 dataset file."""
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            header = f.readline().lower()
            return "label" in header and ("flow duration" in header or "destination port" in header)
    except Exception:
        return False


def parse_cicids_csv(path: Path) -> List[Dict[str, Any]]:
    """Parse a CIC-IDS2017 CSV and produce records with a *raw* key for the analyzer."""
    from .dataset_loader import normalize_label, _safe_float
    records = []
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        headers = [h.strip() for h in (reader.fieldnames or [])]
        reader.fieldnames = headers
        for lineno, row in enumerate(reader, start=1):
            stripped = {k.strip(): v.strip() for k, v in row.items() if k}
            label = stripped.get("Label", "UNKNOWN")
            category = normalize_label(label)
            # Build a human-readable raw summary of the flow
            dst_port = stripped.get("Destination Port", "?")
            fwd_pkts = stripped.get("Total Fwd Packets", "?")
            bwd_pkts = stripped.get("Total Backward Packets", "?")
            flow_bps = stripped.get("Flow Bytes/s", "?")
            syn = stripped.get("SYN Flag Count", "0")
            raw = (
                f"Flow: dst_port={dst_port} fwd_pkts={fwd_pkts} bwd_pkts={bwd_pkts} "
                f"flow_bytes_s={flow_bps} syn_flags={syn} label={label}"
            )
            record = {
                "_line": lineno,
                "raw": raw,
                "type": "cicids",
                "_label": label,
                "_category": category,
            }
            record.update(stripped)
            records.append(record)
    return records


def parse_log(path: Path) -> List[Dict[str, Any]]:
    suf = path.suffix.lower()
    if suf in (".jsonl", ".json"):
        return parse_json_log(path)
    if suf in (".csv",):
        if is_cicids_csv(path):
            return parse_cicids_csv(path)
        return parse_csv_log(path)
    return parse_text_log(path)
