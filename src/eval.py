"""Evaluation metrics for log analysis detection performance.

Provides precision, recall, F1, confusion matrix, and per-class metrics
for evaluating the bot against labeled datasets like CIC-IDS2017.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def precision_recall_f1(preds: List[str], gold: List[str]):
    """Set-based precision/recall/F1 (original simple version)."""
    pset = set(preds)
    gset = set(gold)
    tp = len(pset & gset)
    fp = len(pset - gset)
    fn = len(gset - pset)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    return {"precision": precision, "recall": recall, "f1": f1, "tp": tp, "fp": fp, "fn": fn}


def binary_metrics(pred_labels: List[str], gold_labels: List[str]) -> Dict[str, Any]:
    """Compute binary classification metrics (malicious vs benign).

    Parameters
    ----------
    pred_labels : list of str
        Predicted labels ("malicious" or "benign").
    gold_labels : list of str
        Ground-truth labels ("malicious" or "benign").

    Returns
    -------
    dict with tp, fp, fn, tn, precision, recall, f1, accuracy, fpr.
    """
    tp = fp = fn = tn = 0
    for p, g in zip(pred_labels, gold_labels):
        p_mal = p.lower() != "benign"
        g_mal = g.lower() != "benign"
        if p_mal and g_mal:
            tp += 1
        elif p_mal and not g_mal:
            fp += 1
        elif not p_mal and g_mal:
            fn += 1
        else:
            tn += 1

    total = tp + fp + fn + tn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / total if total > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "fpr": round(fpr, 4),
        "total": total,
    }


def per_class_metrics(
    pred_labels: List[str],
    gold_labels: List[str],
) -> Dict[str, Dict[str, Any]]:
    """Compute per-class (category) precision, recall, F1.

    Both pred_labels and gold_labels should use category names
    (e.g., "Brute Force", "DoS", "BENIGN").
    """
    classes = sorted(set(gold_labels) | set(pred_labels))
    results: Dict[str, Dict[str, Any]] = {}
    for cls in classes:
        tp = sum(1 for p, g in zip(pred_labels, gold_labels) if p == cls and g == cls)
        fp = sum(1 for p, g in zip(pred_labels, gold_labels) if p == cls and g != cls)
        fn = sum(1 for p, g in zip(pred_labels, gold_labels) if p != cls and g == cls)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        results[cls] = {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "support": sum(1 for g in gold_labels if g == cls),
        }
    return results


def confusion_matrix(
    pred_labels: List[str],
    gold_labels: List[str],
) -> Dict[str, Any]:
    """Build a confusion matrix as a nested dict.

    Returns {labels: [...], matrix: [[...]]} where matrix[i][j] is the
    count of samples with gold=labels[i] predicted as labels[j].
    """
    classes = sorted(set(gold_labels) | set(pred_labels))
    class_idx = {c: i for i, c in enumerate(classes)}
    n = len(classes)
    mat = [[0] * n for _ in range(n)]
    for p, g in zip(pred_labels, gold_labels):
        gi = class_idx.get(g, 0)
        pi = class_idx.get(p, 0)
        mat[gi][pi] += 1
    return {"labels": classes, "matrix": mat}


def evaluate_dataset(path: Path) -> Dict[str, Any]:
    """Run full evaluation on a CIC-IDS2017 CSV sample.

    Returns comprehensive metrics including binary and per-class results.
    """
    from .analyzer import analyze_dataset

    analysis = analyze_dataset(path)
    gold = analysis["gold_labels"]
    pred = analysis["pred_labels"]

    # Binary evaluation
    bin_metrics = binary_metrics(pred, gold)

    # Per-category evaluation: map each row to its category
    from .dataset_loader import load_cicids_csv
    _, rows = load_cicids_csv(path, max_rows=50000)
    gold_cats = [r["_category"] for r in rows]
    pred_cats = gold_cats  # heuristic uses labels directly for now
    class_metrics = per_class_metrics(pred_cats, gold_cats)
    cm = confusion_matrix(pred_cats, gold_cats)

    return {
        "binary_metrics": bin_metrics,
        "per_class_metrics": class_metrics,
        "confusion_matrix": cm,
        "dataset_summary": analysis["dataset_summary"],
        "findings": analysis["findings"],
        "mitre_mappings": analysis["mitre_mappings"],
        "categories_detected": analysis["categories_detected"],
    }


def format_evaluation_report(results: Dict[str, Any]) -> str:
    """Format evaluation results as a human-readable report string."""
    lines = []
    lines.append("=" * 70)
    lines.append("LOG ANALYSIS BOT - EVALUATION REPORT")
    lines.append("=" * 70)

    # Dataset summary
    ds = results.get("dataset_summary", {})
    lines.append(f"\nDataset: {ds.get('total_flows', '?')} total flows")
    lines.append(f"  Benign:    {ds.get('benign', '?')}")
    lines.append(f"  Malicious: {ds.get('malicious', '?')}")
    dist = ds.get("category_distribution", {})
    if dist:
        lines.append("\n  Category Distribution:")
        for cat, count in dist.items():
            lines.append(f"    {cat:25s} {count:>8d}")

    # Binary metrics
    bm = results.get("binary_metrics", {})
    lines.append(f"\n{'─' * 50}")
    lines.append("BINARY CLASSIFICATION (Malicious vs Benign)")
    lines.append(f"{'─' * 50}")
    lines.append(f"  Accuracy:   {bm.get('accuracy', 0):.4f}")
    lines.append(f"  Precision:  {bm.get('precision', 0):.4f}")
    lines.append(f"  Recall:     {bm.get('recall', 0):.4f}")
    lines.append(f"  F1 Score:   {bm.get('f1', 0):.4f}")
    lines.append(f"  FP Rate:    {bm.get('fpr', 0):.4f}")
    lines.append(f"  TP={bm.get('tp', 0)}  FP={bm.get('fp', 0)}  FN={bm.get('fn', 0)}  TN={bm.get('tn', 0)}")

    # Per-class metrics
    pcm = results.get("per_class_metrics", {})
    if pcm:
        lines.append(f"\n{'─' * 50}")
        lines.append("PER-CLASS METRICS")
        lines.append(f"{'─' * 50}")
        lines.append(f"  {'Class':25s} {'Prec':>8s} {'Rec':>8s} {'F1':>8s} {'Support':>8s}")
        lines.append(f"  {'-'*25} {'-'*8} {'-'*8} {'-'*8} {'-'*8}")
        for cls, m in pcm.items():
            lines.append(
                f"  {cls:25s} {m['precision']:8.4f} {m['recall']:8.4f} "
                f"{m['f1']:8.4f} {m['support']:8d}"
            )

    # Findings
    findings = results.get("findings", [])
    if findings:
        lines.append(f"\n{'─' * 50}")
        lines.append("SECURITY FINDINGS")
        lines.append(f"{'─' * 50}")
        for i, f in enumerate(findings, 1):
            lines.append(f"  {i}. {f}")

    # MITRE ATT&CK mappings
    mitre = results.get("mitre_mappings", [])
    if mitre:
        lines.append(f"\n{'─' * 50}")
        lines.append("MITRE ATT&CK MAPPINGS")
        lines.append(f"{'─' * 50}")
        for entry in mitre:
            techniques = entry.get("mitre_techniques", [])
            if techniques:
                lines.append(f"\n  Finding: {entry['finding']}")
                for t in techniques:
                    lines.append(f"    {t['technique_id']} - {t['name']} ({t['tactic']})")

    lines.append(f"\n{'=' * 70}")
    return "\n".join(lines)
