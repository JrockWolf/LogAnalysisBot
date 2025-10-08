import tempfile
from pathlib import Path
from src.generator import generate_samples
from src.parsers import parse_log
from src.analyzer import heuristic_detect
from src.eval import precision_recall_f1


def test_generate_and_parse():
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "sample.log"
        generate_samples(p, seed=1)
        recs = parse_log(p)
        assert len(recs) > 0


def test_heuristic_detect():
    # craft synthetic records
    recs = [{"raw": "Failed password for invalid user root from 192.0.2.5 port 2222"} for _ in range(4)]
    out = heuristic_detect(recs)
    assert any("Multiple failed SSH logins" in o for o in out)


def test_eval_metrics():
    preds = ["a", "b", "c"]
    gold = ["a", "c", "d"]
    stats = precision_recall_f1(preds, gold)
    assert stats["tp"] == 2
    assert stats["fp"] == 1
    assert stats["fn"] == 1
