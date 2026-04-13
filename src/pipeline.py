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


# ── Baseline detection (z-score threshold) ─────────────────────────

def run_baseline_zscore(
    records: List[Dict[str, Any]],
    threshold: float = 3.0,
) -> Dict[str, Any]:
    """Simple z-score based anomaly detection as a baseline comparator.

    Flags records where any feature exceeds *threshold* standard deviations
    from the mean. Returns same structure as run_isolation_forest for comparison.
    """
    import numpy as np

    feature_names, matrix = extract_numeric_features(records)
    if not feature_names or not matrix:
        return {
            "anomaly_indices": [],
            "anomaly_count": 0,
            "total_records": len(records),
            "method": "Z-Score Threshold",
        }

    X = np.array(matrix, dtype=np.float64)
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
    means = np.mean(X, axis=0)
    stds = np.std(X, axis=0)
    stds[stds == 0] = 1e-10

    z_scores = np.abs((X - means) / stds)
    max_z = np.max(z_scores, axis=1)
    anomaly_mask = max_z > threshold
    anomaly_indices = list(np.where(anomaly_mask)[0])

    return {
        "anomaly_indices": anomaly_indices,
        "anomaly_count": len(anomaly_indices),
        "total_records": len(records),
        "method": "Z-Score Threshold",
        "threshold": threshold,
    }


def compute_model_performance(
    records: List[Dict[str, Any]],
    anomaly_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Compute model performance metrics by comparing IF predictions to labels.

    For labeled datasets, uses ground-truth labels. For unlabeled data,
    returns anomaly-based summary statistics.
    """
    if not anomaly_result:
        return {}

    total = anomaly_result.get("total_records", 0)
    anom_count = anomaly_result.get("anomaly_count", 0)
    if total == 0:
        return {}

    anomaly_set = set(anomaly_result.get("anomaly_indices", []))

    # Check if records have ground-truth labels
    has_labels = any(r.get("_label") for r in records[:100])

    if has_labels:
        pred_labels = []
        gold_labels = []
        for i, r in enumerate(records):
            gold = r.get("_label", "benign").lower()
            pred = "malicious" if i in anomaly_set else "benign"
            gold_labels.append(gold)
            pred_labels.append(pred)

        from .eval import binary_metrics, per_class_metrics, confusion_matrix

        bm = binary_metrics(pred_labels, gold_labels)

        # Per-class: use _category for finer granularity
        gold_cats = [r.get("_category", "UNKNOWN") for r in records]
        pred_cats = []
        for i, r in enumerate(records):
            if i in anomaly_set:
                pred_cats.append(r.get("_category", "ANOMALY"))
            else:
                pred_cats.append("BENIGN")
        pcm = per_class_metrics(pred_cats, gold_cats)
        cm = confusion_matrix(
            ["malicious" if i in anomaly_set else "benign" for i in range(len(records))],
            [r.get("_label", "benign").lower() for r in records],
        )

        return {
            "has_labels": True,
            "binary_metrics": bm,
            "per_class_metrics": pcm,
            "confusion_matrix": cm,
        }
    else:
        # Unlabeled: return summary stats
        anom_rate = round(anom_count / total, 4) if total else 0
        scores = anomaly_result.get("anomaly_scores", [])
        import numpy as np
        score_arr = np.array(scores) if scores else np.array([])
        return {
            "has_labels": False,
            "anomaly_rate": anom_rate,
            "mean_score": round(float(np.mean(score_arr)), 4) if score_arr.size else 0,
            "std_score": round(float(np.std(score_arr)), 4) if score_arr.size else 0,
            "min_score": round(float(np.min(score_arr)), 4) if score_arr.size else 0,
            "max_score": round(float(np.max(score_arr)), 4) if score_arr.size else 0,
        }


def compute_baseline_comparison(
    records: List[Dict[str, Any]],
    anomaly_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Compare Isolation Forest against z-score baseline.

    Returns side-by-side metrics for both methods.
    """
    if not anomaly_result or not records:
        return {}

    baseline = run_baseline_zscore(records)
    if_indices = set(anomaly_result.get("anomaly_indices", []))
    zs_indices = set(baseline.get("anomaly_indices", []))

    total = len(records)
    overlap = if_indices & zs_indices
    only_if = if_indices - zs_indices
    only_zs = zs_indices - if_indices

    comparison = {
        "isolation_forest": {
            "anomaly_count": anomaly_result.get("anomaly_count", 0),
            "anomaly_rate": round(anomaly_result.get("anomaly_count", 0) / total, 4) if total else 0,
        },
        "zscore_baseline": {
            "anomaly_count": baseline["anomaly_count"],
            "anomaly_rate": round(baseline["anomaly_count"] / total, 4) if total else 0,
            "threshold": baseline.get("threshold", 3.0),
        },
        "agreement": {
            "both_flagged": len(overlap),
            "only_isolation_forest": len(only_if),
            "only_zscore": len(only_zs),
            "agreement_rate": round(
                1 - (len(only_if) + len(only_zs)) / max(total, 1), 4
            ),
        },
    }

    # If labels available, include metrics for both
    has_labels = any(r.get("_label") for r in records[:100])
    if has_labels:
        from .eval import binary_metrics
        gold = [r.get("_label", "benign").lower() for r in records]

        if_pred = ["malicious" if i in if_indices else "benign" for i in range(total)]
        zs_pred = ["malicious" if i in zs_indices else "benign" for i in range(total)]

        comparison["isolation_forest"]["metrics"] = binary_metrics(if_pred, gold)
        comparison["zscore_baseline"]["metrics"] = binary_metrics(zs_pred, gold)

    return comparison


def compute_statistical_tests(
    records: List[Dict[str, Any]],
    anomaly_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Run statistical significance tests on the anomaly detection results.

    Performs:
    - Mann–Whitney U test comparing anomaly scores of flagged vs normal records
    - Feature-level t-tests between anomaly and normal groups
    """
    if not anomaly_result or not records:
        return {}

    import numpy as np

    scores = anomaly_result.get("anomaly_scores", [])
    if not scores:
        return {}

    anomaly_set = set(anomaly_result.get("anomaly_indices", []))
    score_arr = np.array(scores)
    anom_scores = score_arr[list(anomaly_set)] if anomaly_set else np.array([])
    normal_indices = [i for i in range(len(scores)) if i not in anomaly_set]
    normal_scores = score_arr[normal_indices] if normal_indices else np.array([])

    results: Dict[str, Any] = {}

    # Mann-Whitney U test on anomaly scores
    if anom_scores.size >= 2 and normal_scores.size >= 2:
        try:
            from scipy.stats import mannwhitneyu
            stat, p_value = mannwhitneyu(anom_scores, normal_scores, alternative="two-sided")
            results["score_separation"] = {
                "test": "Mann-Whitney U",
                "statistic": round(float(stat), 4),
                "p_value": round(float(p_value), 6),
                "significant": p_value < 0.05,
                "interpretation": (
                    "The anomaly scores of flagged records are statistically "
                    "significantly different from normal records (p < 0.05), "
                    "confirming the model identifies a distinct group."
                    if p_value < 0.05 else
                    "The anomaly scores do not show statistically significant "
                    "separation (p >= 0.05). The model's anomaly boundary may "
                    "be somewhat arbitrary for this dataset."
                ),
            }
        except ImportError:
            results["score_separation"] = {
                "test": "Mann-Whitney U",
                "note": "scipy not installed — install scipy for statistical tests.",
            }

    # Feature-level tests: top features with biggest difference
    feature_names, matrix = extract_numeric_features(records)
    if feature_names and matrix:
        X = np.array(matrix, dtype=np.float64)
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        feature_tests = []
        for j, fname in enumerate(feature_names):
            anom_vals = X[list(anomaly_set), j] if anomaly_set else np.array([])
            norm_vals = X[normal_indices, j] if normal_indices else np.array([])
            if anom_vals.size >= 2 and norm_vals.size >= 2:
                anom_mean = float(np.mean(anom_vals))
                norm_mean = float(np.mean(norm_vals))
                effect_size = abs(anom_mean - norm_mean) / max(float(np.std(norm_vals)), 1e-10)
                try:
                    from scipy.stats import mannwhitneyu
                    _, p = mannwhitneyu(anom_vals, norm_vals, alternative="two-sided")
                    p = float(p)
                except ImportError:
                    p = None
                feature_tests.append({
                    "feature": fname,
                    "anomaly_mean": round(anom_mean, 4),
                    "normal_mean": round(norm_mean, 4),
                    "effect_size": round(effect_size, 4),
                    "p_value": round(p, 6) if p is not None else None,
                    "significant": p < 0.05 if p is not None else None,
                })
        # Sort by effect size descending
        feature_tests.sort(key=lambda x: -x["effect_size"])
        results["feature_tests"] = feature_tests[:15]

    # Summary
    score_mean_anom = round(float(np.mean(anom_scores)), 4) if anom_scores.size else None
    score_mean_norm = round(float(np.mean(normal_scores)), 4) if normal_scores.size else None
    results["score_summary"] = {
        "anomaly_mean_score": score_mean_anom,
        "normal_mean_score": score_mean_norm,
        "anomaly_std_score": round(float(np.std(anom_scores)), 4) if anom_scores.size else None,
        "normal_std_score": round(float(np.std(normal_scores)), 4) if normal_scores.size else None,
    }

    return results


def compute_error_analysis(
    records: List[Dict[str, Any]],
    anomaly_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Analyze prediction errors: false positives and false negatives.

    Only meaningful for labeled datasets.
    """
    if not anomaly_result or not records:
        return {}

    has_labels = any(r.get("_label") for r in records[:100])
    if not has_labels:
        return {"has_labels": False}

    anomaly_set = set(anomaly_result.get("anomaly_indices", []))
    fp_indices = []
    fn_indices = []
    fp_categories: Dict[str, int] = {}
    fn_categories: Dict[str, int] = {}

    for i, r in enumerate(records):
        gold = r.get("_label", "benign").lower()
        pred_anom = i in anomaly_set
        cat = r.get("_category", "UNKNOWN")
        if pred_anom and gold == "benign":
            fp_indices.append(i)
            fp_categories[cat] = fp_categories.get(cat, 0) + 1
        elif not pred_anom and gold != "benign":
            fn_indices.append(i)
            fn_categories[cat] = fn_categories.get(cat, 0) + 1

    total = len(records)
    total_malicious = sum(1 for r in records if r.get("_label", "benign").lower() != "benign")
    total_benign = total - total_malicious

    return {
        "has_labels": True,
        "false_positives": {
            "count": len(fp_indices),
            "rate": round(len(fp_indices) / max(total_benign, 1), 4),
            "by_category": dict(sorted(fp_categories.items(), key=lambda x: -x[1])),
            "sample_indices": fp_indices[:10],
        },
        "false_negatives": {
            "count": len(fn_indices),
            "rate": round(len(fn_indices) / max(total_malicious, 1), 4),
            "by_category": dict(sorted(fn_categories.items(), key=lambda x: -x[1])),
            "sample_indices": fn_indices[:10],
        },
        "total_errors": len(fp_indices) + len(fn_indices),
        "error_rate": round((len(fp_indices) + len(fn_indices)) / max(total, 1), 4),
        "interpretation": _error_interpretation(
            len(fp_indices), len(fn_indices), total_benign, total_malicious
        ),
    }


def _error_interpretation(fp: int, fn: int, benign: int, malicious: int) -> str:
    """Generate a human-readable interpretation of error patterns."""
    parts = []
    if fp + fn == 0:
        return "Perfect classification — no errors detected."

    fp_rate = fp / max(benign, 1)
    fn_rate = fn / max(malicious, 1)

    if fp_rate > fn_rate * 2:
        parts.append(
            f"The model is over-sensitive: {fp} false positives "
            f"({fp_rate:.1%} of benign traffic) vs {fn} false negatives "
            f"({fn_rate:.1%} of malicious traffic). Consider increasing "
            f"the contamination threshold to reduce noise."
        )
    elif fn_rate > fp_rate * 2:
        parts.append(
            f"The model is under-sensitive: {fn} false negatives "
            f"({fn_rate:.1%} of malicious traffic missed) vs {fp} false positives. "
            f"Consider lowering the contamination threshold or adding "
            f"more features to improve detection."
        )
    else:
        parts.append(
            f"Error distribution is roughly balanced: {fp} false positives "
            f"({fp_rate:.1%}) and {fn} false negatives ({fn_rate:.1%})."
        )

    return " ".join(parts)


def compute_hypotheses(
    records: List[Dict[str, Any]],
    anomaly_result: Optional[Dict[str, Any]] = None,
    dataset_summary: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Generate and evaluate data-driven hypotheses about the dataset."""
    hypotheses = []
    total = len(records)
    if total == 0:
        return hypotheses

    # H1: Anomalous traffic is a minority
    if anomaly_result:
        anom_count = anomaly_result.get("anomaly_count", 0)
        anom_rate = anom_count / total
        hypotheses.append({
            "id": "H1",
            "hypothesis": "Anomalous traffic constitutes a small minority of total traffic.",
            "result": "SUPPORTED" if anom_rate < 0.2 else "NOT SUPPORTED",
            "evidence": f"{anom_count}/{total} records ({anom_rate:.1%}) were flagged as anomalous.",
            "detail": (
                "This is consistent with the assumption that most network "
                "traffic is benign, validating the Isolation Forest's contamination parameter."
                if anom_rate < 0.2 else
                f"At {anom_rate:.1%}, the anomaly rate is higher than typical. "
                "This may indicate a high-attack dataset or an aggressive contamination setting."
            ),
        })

    # H2: Labeled dataset — malicious traffic differs statistically
    if dataset_summary:
        benign = dataset_summary.get("benign", 0)
        malicious = dataset_summary.get("malicious", 0)
        if benign and malicious:
            mal_ratio = malicious / (benign + malicious)
            hypotheses.append({
                "id": "H2",
                "hypothesis": "The dataset contains a mix of benign and malicious traffic suitable for evaluation.",
                "result": "SUPPORTED" if 0.05 < mal_ratio < 0.95 else "PARTIALLY SUPPORTED",
                "evidence": f"Benign: {benign}, Malicious: {malicious} ({mal_ratio:.1%} malicious).",
                "detail": (
                    "The class distribution enables meaningful evaluation of detection performance."
                    if 0.05 < mal_ratio < 0.95 else
                    "The dataset is heavily imbalanced, which may skew performance metrics."
                ),
            })

    # H3: Feature importance concentration
    if anomaly_result:
        importances = anomaly_result.get("feature_importances", {})
        if importances:
            vals = list(importances.values())
            top3_sum = sum(sorted(vals, reverse=True)[:3])
            total_sum = sum(vals) or 1
            concentration = top3_sum / total_sum
            hypotheses.append({
                "id": "H3",
                "hypothesis": "A small number of features drive most of the anomaly detection signal.",
                "result": "SUPPORTED" if concentration > 0.5 else "NOT SUPPORTED",
                "evidence": (
                    f"Top 3 features account for {concentration:.1%} of total importance."
                ),
                "detail": (
                    "Feature importance is concentrated, suggesting specific traffic "
                    "characteristics distinguish anomalies."
                    if concentration > 0.5 else
                    "Feature importance is distributed across many features, "
                    "indicating anomalies are multi-dimensional."
                ),
            })

    # H4: Anomaly scores follow a bimodal distribution
    if anomaly_result:
        scores = anomaly_result.get("anomaly_scores", [])
        if len(scores) > 10:
            import numpy as np
            s = np.array(scores)
            median_score = float(np.median(s))
            below = s[s < median_score]
            above = s[s >= median_score]
            if below.size > 0 and above.size > 0:
                gap = float(np.mean(above) - np.mean(below))
                overall_std = float(np.std(s))
                separation = gap / max(overall_std, 1e-10)
                hypotheses.append({
                    "id": "H4",
                    "hypothesis": "Anomaly scores show clear separation between normal and anomalous groups.",
                    "result": "SUPPORTED" if separation > 1.5 else "PARTIALLY SUPPORTED" if separation > 0.8 else "NOT SUPPORTED",
                    "evidence": f"Score separation ratio: {separation:.2f} (gap/std).",
                    "detail": (
                        "Scores show strong bimodal separation, indicating the model "
                        "confidently distinguishes anomalies from normal traffic."
                        if separation > 1.5 else
                        "Moderate separation exists but the boundary is somewhat fuzzy."
                        if separation > 0.8 else
                        "Scores overlap significantly — the anomaly boundary is not well-defined."
                    ),
                })

    return hypotheses
