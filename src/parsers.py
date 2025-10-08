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


def parse_log(path: Path) -> List[Dict[str, Any]]:
    suf = path.suffix.lower()
    if suf in (".jsonl", ".json"):
        return parse_json_log(path)
    if suf in (".csv",):
        return parse_csv_log(path)
    return parse_text_log(path)
