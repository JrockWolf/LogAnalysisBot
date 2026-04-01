"""Loader for labeled network intrusion detection datasets.

Handles CSV files from intrusion detection datasets where each row represents
a network flow with features and a *Label* column (BENIGN or attack type).

Supported attack labels
-----------------------
- BENIGN
- SSH-Patator / FTP-Patator
- DoS Hulk / DoS slowloris / DoS Slowhttptest / DoS GoldenEye
- DDoS
- PortScan
- Bot
- Infiltration
- Web Attack – Brute Force / Web Attack – XSS / Web Attack – Sql Injection
"""

from __future__ import annotations

import csv
import math
import random
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Canonical mapping from raw labels to attack categories
LABEL_CATEGORY: Dict[str, str] = {
    "BENIGN": "BENIGN",
    "SSH-Patator": "Brute Force",
    "FTP-Patator": "Brute Force",
    "DoS Hulk": "DoS",
    "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS",
    "DoS GoldenEye": "DoS",
    "DDoS": "DDoS",
    "PortScan": "Reconnaissance",
    "Bot": "Botnet",
    "Infiltration": "Infiltration",
    "Web Attack \u00ef\u00bf\u00bd Brute Force": "Web Attack",
    "Web Attack \u00ef\u00bf\u00bd XSS": "Web Attack",
    "Web Attack \u00ef\u00bf\u00bd Sql Injection": "Web Attack",
    # common alternate encodings
    "Web Attack - Brute Force": "Web Attack",
    "Web Attack - XSS": "Web Attack",
    "Web Attack - Sql Injection": "Web Attack",
}

# Important feature columns for heuristic analysis
KEY_FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "SYN Flag Count",
    "FIN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "Label",
]


def _safe_float(v: str) -> float:
    """Convert string to float, handling Inf/NaN/empty."""
    v = v.strip()
    if not v or v.lower() in ("nan", "inf", "-inf", "infinity", "-infinity"):
        return 0.0
    try:
        val = float(v)
        if math.isinf(val) or math.isnan(val):
            return 0.0
        return val
    except ValueError:
        return 0.0


def normalize_label(raw_label: str) -> str:
    """Map a raw dataset label to a canonical category string."""
    raw = raw_label.strip()
    if raw in LABEL_CATEGORY:
        return LABEL_CATEGORY[raw]
    # fuzzy match for encoding issues
    low = raw.lower()
    if "brute" in low:
        return "Brute Force" if "web" not in low else "Web Attack"
    if "xss" in low:
        return "Web Attack"
    if "sql" in low:
        return "Web Attack"
    if "ddos" in low:
        return "DDoS"
    if "dos" in low:
        return "DoS"
    if "portscan" in low:
        return "Reconnaissance"
    if "bot" in low:
        return "Botnet"
    if "infiltr" in low:
        return "Infiltration"
    if "patator" in low:
        return "Brute Force"
    if raw.upper() == "BENIGN":
        return "BENIGN"
    return raw  # unknown


def load_dataset_csv(
    path: Path,
    max_rows: int = 0,
    attack_only: bool = False,
) -> Tuple[List[str], List[Dict[str, Any]]]:
    """Load a labeled dataset CSV file.

    Returns (header_list, rows) where each row is a dict with stripped keys
    and a special ``_category`` key for the normalized attack category, plus
    ``_label`` for the raw label.

    Parameters
    ----------
    path : Path
        CSV file path.
    max_rows : int
        Limit on number of data rows (0 = unlimited).
    attack_only : bool
        If True, skip BENIGN rows.
    """
    rows: List[Dict[str, Any]] = []
    headers: List[str] = []
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        reader = csv.reader(fh)
        raw_header = next(reader)
        headers = [h.strip() for h in raw_header]
        label_idx = None
        for i, h in enumerate(headers):
            if h.lower() == "label":
                label_idx = i
                break

        count = 0
        for csv_row in reader:
            if max_rows and count >= max_rows:
                break
            if len(csv_row) < len(headers):
                continue
            raw_label = csv_row[label_idx].strip() if label_idx is not None else ""
            category = normalize_label(raw_label)
            if attack_only and category == "BENIGN":
                continue

            row: Dict[str, Any] = {}
            for i, h in enumerate(headers):
                row[h] = csv_row[i].strip()
            row["_label"] = raw_label
            row["_category"] = category
            rows.append(row)
            count += 1

    return headers, rows


def load_dataset_directory(
    directory: Path,
    max_per_file: int = 5000,
) -> Tuple[List[str], List[Dict[str, Any]]]:
    """Load all labeled dataset CSV files from a directory.

    Returns combined (headers, rows).
    """
    all_rows: List[Dict[str, Any]] = []
    headers: List[str] = []
    for csv_path in sorted(directory.glob("*.csv")):
        h, rows = load_dataset_csv(csv_path, max_rows=max_per_file)
        if not headers:
            headers = h
        all_rows.extend(rows)
    return headers, all_rows


def dataset_summary(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Return summary statistics for loaded dataset rows."""
    total = len(rows)
    label_counts: Dict[str, int] = {}
    category_counts: Dict[str, int] = {}
    for r in rows:
        lbl = r.get("_label", "UNKNOWN")
        cat = r.get("_category", "UNKNOWN")
        label_counts[lbl] = label_counts.get(lbl, 0) + 1
        category_counts[cat] = category_counts.get(cat, 0) + 1

    return {
        "total_flows": total,
        "benign": category_counts.get("BENIGN", 0),
        "malicious": total - category_counts.get("BENIGN", 0),
        "label_distribution": dict(sorted(label_counts.items(), key=lambda x: -x[1])),
        "category_distribution": dict(sorted(category_counts.items(), key=lambda x: -x[1])),
    }


# Backward-compatible alias
load_cicids_csv = load_dataset_csv


def extract_flow_features(row: Dict[str, Any]) -> Dict[str, float]:
    """Extract numeric features from a dataset row for heuristic analysis."""
    features: Dict[str, float] = {}
    for key in KEY_FEATURES:
        if key == "Label":
            continue
        val = row.get(key, "0")
        features[key] = _safe_float(str(val))
    return features
