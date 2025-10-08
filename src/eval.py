from typing import List


def precision_recall_f1(preds: List[str], gold: List[str]):
    # treat strings as labels; do simple set-based matching
    pset = set(preds)
    gset = set(gold)
    tp = len(pset & gset)
    fp = len(pset - gset)
    fn = len(gset - pset)
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    return {"precision": precision, "recall": recall, "f1": f1, "tp": tp, "fp": fp, "fn": fn}
