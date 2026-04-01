"""Data science pipeline: anomaly detection and statistical analysis.

Uses Isolation Forest for unsupervised anomaly detection on numeric features
extracted from any supported file format.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Tuple


def _safe_float(v: Any) -> float:
    if isinstance(v, (int, float)):
        return 0.0 if (math.isinf(v) or math.isnan(v)) else float(v)
    s = str(v).strip()
    if not s or s.lower() in ("nan", "inf", "-inf", "infinity", "-infinity"):
        return 0.0
    try:
        val = float(s)
        return 0.0 if (math.isinf(val) or math.isnan(val)) else val
    except ValueError:
        return 0.0


def extract_numeric_features(records: List[Dict[str, Any]]) -> Tuple[List[str], List[List[float]]]:
    """Extract numeric columns from records into a feature matrix.

    Returns (feature_names, matrix) where matrix is list of float lists.
    """
    if not records:
        return [], []

    # Identify columns that are numeric across a sample
    sample = records[:min(200, len(records))]
    candidate_cols: Dict[str, int] = {}
    skip_keys = {"_line", "line", "type", "_label", "_category", "raw", "dns_query"}

    for row in sample:
        for k, v in row.items():
            if k in skip_keys or k.startswith("_"):
                continue
            val = _safe_float(v)
            if val != 0.0 or str(v).strip() in ("0", "0.0", "0.00"):
                candidate_cols[k] = candidate_cols.get(k, 0) + 1

    # Keep columns where >30% of samples have numeric values
    threshold = max(1, len(sample) * 0.3)
    feature_names = sorted(k for k, cnt in candidate_cols.items() if cnt >= threshold)

    if not feature_names:
        return [], []

    matrix: List[List[float]] = []
    for row in records:
        vec = [_safe_float(row.get(col, 0)) for col in feature_names]
        matrix.append(vec)

    return feature_names, matrix


def run_isolation_forest(
    records: List[Dict[str, Any]],
    contamination: float = 0.1,
) -> Dict[str, Any]:
    """Run Isolation Forest anomaly detection on the records.

    Returns a dict with:
    - anomaly_indices: list of record indices flagged as anomalies
    - anomaly_scores: list of anomaly scores for all records
    - anomaly_count: number of anomalies found
    - total_records: total input records
    - feature_names: features used
    - feature_importances: dict of feature name -> importance estimate
    - anomaly_records: the flagged records (list of dicts)
    """
    try:
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
        import numpy as np
    except ImportError:
        raise ImportError(
            "scikit-learn and numpy are required for the data science pipeline. "
            "Install with: pip install scikit-learn numpy"
        )

    feature_names, matrix = extract_numeric_features(records)

    if not feature_names or not matrix:
        return {
            "anomaly_indices": [],
            "anomaly_scores": [],
            "anomaly_count": 0,
            "total_records": len(records),
            "feature_names": [],
            "feature_importances": {},
            "anomaly_records": [],
            "error": "No numeric features found for anomaly detection.",
        }

    X = np.array(matrix, dtype=np.float64)
    # Replace any remaining nan/inf
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Fit Isolation Forest
    clf = IsolationForest(
        contamination=min(contamination, 0.5),
        random_state=42,
        n_estimators=100,
        n_jobs=-1,
    )
    predictions = clf.fit_predict(X_scaled)  # -1 = anomaly, 1 = normal
    scores = clf.decision_function(X_scaled)  # lower = more anomalous

    anomaly_indices = [i for i, p in enumerate(predictions) if p == -1]
    anomaly_records = [records[i] for i in anomaly_indices]

    # Estimate feature importance via mean absolute score shift per feature
    importances: Dict[str, float] = {}
    for j, fname in enumerate(feature_names):
        anomaly_vals = [X[i, j] for i in anomaly_indices] if anomaly_indices else []
        normal_vals = [X[i, j] for i in range(len(X)) if predictions[i] == 1]
        if anomaly_vals and normal_vals:
            anom_mean = sum(anomaly_vals) / len(anomaly_vals)
            norm_mean = sum(normal_vals) / len(normal_vals)
            norm_std = max(1e-10, (sum((v - norm_mean) ** 2 for v in normal_vals) / len(normal_vals)) ** 0.5)
            importances[fname] = round(abs(anom_mean - norm_mean) / norm_std, 4)
        else:
            importances[fname] = 0.0

    # Sort by importance
    importances = dict(sorted(importances.items(), key=lambda x: -x[1]))

    return {
        "anomaly_indices": anomaly_indices,
        "anomaly_scores": [round(float(s), 4) for s in scores],
        "anomaly_count": len(anomaly_indices),
        "total_records": len(records),
        "feature_names": feature_names,
        "feature_importances": importances,
        "anomaly_records": anomaly_records[:100],  # cap for display
    }


def compute_statistics(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute summary statistics for a dataset.

    Returns per-column stats (count, mean, std, min, max) and overall info.
    """
    feature_names, matrix = extract_numeric_features(records)
    if not feature_names or not matrix:
        return {"columns": [], "stats": {}, "total_rows": len(records), "numeric_columns": 0}

    try:
        import numpy as np
    except ImportError:
        import math as _m
        # Fallback without numpy
        stats: Dict[str, Any] = {}
        for j, fname in enumerate(feature_names):
            col = [row[j] for row in matrix]
            n = len(col)
            mean = sum(col) / n if n else 0
            variance = sum((x - mean) ** 2 for x in col) / n if n else 0
            stats[fname] = {
                "count": n,
                "mean": round(mean, 4),
                "std": round(variance ** 0.5, 4),
                "min": round(min(col), 4) if col else 0,
                "max": round(max(col), 4) if col else 0,
            }
        return {
            "columns": feature_names,
            "stats": stats,
            "total_rows": len(records),
            "numeric_columns": len(feature_names),
        }

    X = np.array(matrix, dtype=np.float64)
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)

    stats = {}
    for j, fname in enumerate(feature_names):
        col = X[:, j]
        stats[fname] = {
            "count": int(len(col)),
            "mean": round(float(np.mean(col)), 4),
            "std": round(float(np.std(col)), 4),
            "min": round(float(np.min(col)), 4),
            "max": round(float(np.max(col)), 4),
            "median": round(float(np.median(col)), 4),
            "q25": round(float(np.percentile(col, 25)), 4),
            "q75": round(float(np.percentile(col, 75)), 4),
        }

    # Detect file types present
    types = set()
    for r in records:
        t = r.get("type", "unknown")
        types.add(t)

    return {
        "columns": feature_names,
        "stats": stats,
        "total_rows": len(records),
        "numeric_columns": len(feature_names),
        "file_types": sorted(types),
    }


def dataset_overview(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Provide a high-level overview of the uploaded dataset."""
    total = len(records)
    types: Dict[str, int] = {}
    for r in records:
        t = r.get("type", "unknown")
        types[t] = types.get(t, 0) + 1

    # For PCAP data, count protocols
    protocols: Dict[str, int] = {}
    src_ips: Dict[str, int] = {}
    dst_ips: Dict[str, int] = {}
    for r in records:
        if r.get("type") == "pcap":
            proto = r.get("proto_name", "Unknown")
            protocols[proto] = protocols.get(proto, 0) + 1
            sip = r.get("src_ip", "")
            dip = r.get("dst_ip", "")
            if sip:
                src_ips[sip] = src_ips.get(sip, 0) + 1
            if dip:
                dst_ips[dip] = dst_ips.get(dip, 0) + 1

    # For labeled dataset data
    categories: Dict[str, int] = {}
    for r in records:
        cat = r.get("_category")
        if cat:
            categories[cat] = categories.get(cat, 0) + 1

    overview: Dict[str, Any] = {
        "total_records": total,
        "record_types": types,
    }

    if protocols:
        overview["protocols"] = dict(sorted(protocols.items(), key=lambda x: -x[1]))
    if src_ips:
        overview["top_sources"] = dict(sorted(src_ips.items(), key=lambda x: -x[1])[:20])
    if dst_ips:
        overview["top_destinations"] = dict(sorted(dst_ips.items(), key=lambda x: -x[1])[:20])
    if categories:
        overview["categories"] = dict(sorted(categories.items(), key=lambda x: -x[1]))
        benign = categories.get("BENIGN", 0)
        overview["benign"] = benign
        overview["malicious"] = total - benign

    return overview
