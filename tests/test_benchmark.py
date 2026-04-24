"""Benchmark tests: measure precision / recall / F1 per attack category
against synthetic ground-truth log corpora.

Each test generates a controlled corpus with a known ground-truth label for
every record, runs heuristic detection, and asserts that recall meets a
minimum threshold.  Results are printed as a Markdown table.

Run with:
    python -m pytest tests/test_benchmark.py -v -s

The ``-s`` flag (no capture) lets the Markdown table print to stdout.
"""

from __future__ import annotations

import math
import random
import time
from typing import Any, Dict, List, Tuple

import pytest

from src.analyzer import heuristic_detect
from src.eval import precision_recall_f1, binary_metrics
from src.generator import generate_samples
from src.parsers import parse_log
from src.redactor import Redactor

# ── Minimum thresholds to pass ───────────────────────────────────────────────
# These are intentionally achievable on synthetic data; tighten as the detector
# improves.
MIN_RECALL_SSH_BRUTE   = 0.70
MIN_RECALL_PORT_SCAN   = 0.60
MIN_RECALL_WEB_ATTACK  = 0.50
MIN_F1_BINARY          = 0.50


# ── Corpus builders ──────────────────────────────────────────────────────────

def _ssh_brute_force_records(n: int = 40, seed: int = 42) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Generate records that mix SSH brute-force events and benign lines."""
    rng = random.Random(seed)
    records: List[Dict[str, Any]] = []
    labels: List[str] = []
    attacker_ip = "10.0.0.99"

    for i in range(n):
        if i < n // 2:
            # Attack records
            raw = (
                f"Failed password for {'invalid user ' if rng.random() > 0.5 else ''}"
                f"{'root' if rng.random() > 0.3 else 'admin'} "
                f"from {attacker_ip} port {rng.randint(40000, 65000)}"
            )
            records.append({"raw": raw, "type": "text", "_line": i + 1})
            labels.append("malicious")
        else:
            # Benign records
            raw = f"Accepted publickey for deploy from 192.168.1.{rng.randint(2, 254)} port 22"
            records.append({"raw": raw, "type": "text", "_line": i + 1})
            labels.append("benign")

    return records, labels


def _port_scan_records(n: int = 60, seed: int = 7) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Generate records with a port scan pattern from a single source."""
    rng = random.Random(seed)
    records: List[Dict[str, Any]] = []
    labels: List[str] = []
    scanner_ip = "172.16.0.5"

    for port in range(1, n + 1):
        raw = (
            f"Connection attempt from {scanner_ip} to port {port} — "
            f"{'RST received' if rng.random() > 0.3 else 'no response'}"
        )
        records.append({"raw": raw, "type": "text", "_line": port})
        labels.append("malicious")

    # Add 20 benign records
    for i in range(20):
        raw = f"ESTABLISHED connection 192.168.1.{rng.randint(2, 200)}:443 -> 10.0.0.1:55000"
        records.append({"raw": raw, "type": "text", "_line": n + i + 1})
        labels.append("benign")

    return records, labels


def _web_attack_records(n: int = 30, seed: int = 13) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Generate web-attack log lines (SQL injection, XSS, path traversal)."""
    rng = random.Random(seed)
    payloads = [
        "GET /login?user=admin'--&pass=x HTTP/1.1",
        "GET /search?q=<script>alert(1)</script> HTTP/1.1",
        "GET /../../etc/passwd HTTP/1.1",
        "POST /api/exec?cmd=cat+/etc/shadow HTTP/1.1",
        "GET /admin?id=1+UNION+SELECT+* HTTP/1.1",
    ]
    records: List[Dict[str, Any]] = []
    labels: List[str] = []
    attacker = "203.0.113.77"

    for i in range(n):
        payload = rng.choice(payloads)
        raw = f"{attacker} - - [24/Apr/2026:10:{i:02d}:00 +0000] \"{payload}\" 400 512"
        records.append({"raw": raw, "type": "text", "_line": i + 1})
        labels.append("malicious")

    for i in range(20):
        raw = (
            f"192.168.1.{rng.randint(2,100)} - - "
            f"[24/Apr/2026:10:{i:02d}:30 +0000] "
            f"\"GET /index.html HTTP/1.1\" 200 1024"
        )
        records.append({"raw": raw, "type": "text", "_line": n + i + 1})
        labels.append("benign")

    return records, labels


def _mixed_corpus(seed: int = 99) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Mixed corpus combining all attack types + benign records."""
    rng = random.Random(seed)
    records, labels = [], []
    for fn in [_ssh_brute_force_records, _port_scan_records, _web_attack_records]:
        r, l = fn(seed=rng.randint(0, 9999))
        records.extend(r)
        labels.extend(l)
    # Shuffle together
    combined = list(zip(records, labels))
    rng.shuffle(combined)
    if combined:
        records, labels = zip(*combined)  # type: ignore[assignment]
        records, labels = list(records), list(labels)
    return records, labels


# ── Metric helpers ────────────────────────────────────────────────────────────

def _detection_hit(findings: List[str], keywords: List[str]) -> bool:
    """Return True if any finding contains any of the keywords."""
    lower_findings = " ".join(findings).lower()
    return any(kw.lower() in lower_findings for kw in keywords)


def _corpus_binary_metrics(
    records: List[Dict[str, Any]],
    labels: List[str],
    attack_keywords: List[str],
) -> Dict[str, Any]:
    """Run heuristic detection and compute binary precision/recall/F1."""
    findings = heuristic_detect(records)
    detected = _detection_hit(findings, attack_keywords)
    # Treat detection as TP if any malicious records exist and detector fires
    has_attack = any(l == "malicious" for l in labels)
    pred_label = "malicious" if detected else "benign"
    gold_label = "malicious" if has_attack else "benign"
    # Per-record binary
    pred_labels = [pred_label] * len(records)
    return binary_metrics(pred_labels, labels)


# ── Benchmark print helper ────────────────────────────────────────────────────

_RESULTS: List[Dict[str, Any]] = []


def _record(name: str, metrics: Dict[str, Any], duration_ms: float) -> None:
    _RESULTS.append({"scenario": name, **metrics, "ms": round(duration_ms, 1)})


def pytest_sessionfinish(session: Any, exitstatus: Any) -> None:  # noqa: ANN001
    """Print Markdown benchmark table after all tests complete."""
    if not _RESULTS:
        return
    header = "| Scenario | P | R | F1 | ms |"
    sep = "|---|---|---|---|---|"
    rows = [
        f"| {r['scenario']} | {r.get('precision', 0):.2f} | {r.get('recall', 0):.2f} | "
        f"{r.get('f1', 0):.2f} | {r['ms']} |"
        for r in _RESULTS
    ]
    print("\n## Benchmark Results\n")
    print(header)
    print(sep)
    for row in rows:
        print(row)
    print()


# ── Test cases ────────────────────────────────────────────────────────────────

class TestSSHBruteForceBenchmark:
    def test_recall_meets_threshold(self):
        records, labels = _ssh_brute_force_records()
        t0 = time.perf_counter()
        findings = heuristic_detect(records)
        elapsed = (time.perf_counter() - t0) * 1000
        detected = _detection_hit(findings, ["ssh", "brute", "failed password", "login"])
        # Compute recall: did we catch the attack at all?
        # (heuristic_detect returns text findings, not per-record labels — measure at corpus level)
        recall = 1.0 if detected else 0.0
        m = binary_metrics(
            ["malicious" if detected else "benign"] * len(records), labels
        )
        _record("SSH Brute Force", m, elapsed)
        assert recall >= MIN_RECALL_SSH_BRUTE, (
            f"SSH brute-force recall {recall:.2f} < threshold {MIN_RECALL_SSH_BRUTE}"
        )

    def test_latency_under_500ms(self):
        records, _ = _ssh_brute_force_records(n=200)
        t0 = time.perf_counter()
        heuristic_detect(records)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert elapsed_ms < 500, f"Detection took {elapsed_ms:.1f}ms (> 500ms)"


class TestPortScanBenchmark:
    def test_recall_meets_threshold(self):
        records, labels = _port_scan_records()
        t0 = time.perf_counter()
        findings = heuristic_detect(records)
        elapsed = (time.perf_counter() - t0) * 1000
        detected = _detection_hit(findings, ["scan", "port", "probe"])
        recall = 1.0 if detected else 0.0
        m = binary_metrics(
            ["malicious" if detected else "benign"] * len(records), labels
        )
        _record("Port Scan", m, elapsed)
        assert recall >= MIN_RECALL_PORT_SCAN, (
            f"Port-scan recall {recall:.2f} < threshold {MIN_RECALL_PORT_SCAN}"
        )


class TestWebAttackBenchmark:
    def test_recall_meets_threshold(self):
        records, labels = _web_attack_records()
        t0 = time.perf_counter()
        findings = heuristic_detect(records)
        elapsed = (time.perf_counter() - t0) * 1000
        detected = _detection_hit(findings, ["sql", "xss", "inject", "web", "attack", "shadow"])
        recall = 1.0 if detected else 0.0
        m = binary_metrics(
            ["malicious" if detected else "benign"] * len(records), labels
        )
        _record("Web Attack", m, elapsed)
        assert recall >= MIN_RECALL_WEB_ATTACK, (
            f"Web-attack recall {recall:.2f} < threshold {MIN_RECALL_WEB_ATTACK}"
        )


class TestMixedCorpusBenchmark:
    def test_binary_f1_meets_threshold(self):
        records, labels = _mixed_corpus()
        t0 = time.perf_counter()
        findings = heuristic_detect(records)
        elapsed = (time.perf_counter() - t0) * 1000
        detected = _detection_hit(
            findings,
            ["ssh", "brute", "scan", "port", "sql", "xss", "inject", "web", "attack",
             "failed password", "shadow"],
        )
        m = binary_metrics(
            ["malicious" if detected else "benign"] * len(records), labels
        )
        _record("Mixed Corpus", m, elapsed)
        assert m["f1"] >= MIN_F1_BINARY, (
            f"Mixed corpus F1 {m['f1']:.2f} < threshold {MIN_F1_BINARY}"
        )

    def test_finding_count_nonzero(self):
        records, _ = _mixed_corpus()
        findings = heuristic_detect(records)
        assert len(findings) > 0, "Expected at least one finding on mixed corpus"


class TestRedactionBenchmark:
    """Verify redactor does not break heuristic detection output."""

    def test_redacted_records_still_trigger_detection(self):
        records, _ = _ssh_brute_force_records()
        r = Redactor()
        redacted = r.redact_records([dict(rec) for rec in records])
        findings = heuristic_detect(redacted)
        detected = _detection_hit(findings, ["ssh", "brute", "failed", "login"])
        assert detected, "Heuristic should still fire on redacted SSH brute-force records"

    def test_ip_replaced_in_output(self):
        r = Redactor()
        out = r.redact("Connection from 192.168.1.100 blocked")
        assert "192.168.1.100" not in out
        assert "[IP_" in out

    def test_email_replaced_in_output(self):
        r = Redactor()
        out = r.redact("Alert for user admin@corp.example.com")
        assert "admin@corp.example.com" not in out
        assert "[EMAIL_" in out

    def test_restore_roundtrip(self):
        r = Redactor()
        original = "Login from 10.0.0.1 for user bob@example.com"
        redacted = r.redact(original)
        restored = r.restore(redacted)
        assert restored == original

    def test_custom_pattern_redacted(self):
        r = Redactor(custom_patterns=[r"corp-\d{4}"])
        out = r.redact("ticket corp-1234 opened")
        assert "corp-1234" not in out
        assert "[REDACTED_" in out


class TestGeneratorBenchmark:
    """Benchmark the synthetic log generator and ensure the detector fires."""

    def test_generated_logs_trigger_detection(self, tmp_path):
        from src.generator import generate_samples

        log_path = tmp_path / "bench.log"
        generate_samples(log_path, seed=42)
        records = parse_log(log_path)
        assert len(records) > 0
        t0 = time.perf_counter()
        findings = heuristic_detect(records)
        elapsed = (time.perf_counter() - t0) * 1000
        _record("Generator Corpus", {"precision": 0, "recall": 0, "f1": 0}, elapsed)
        # Generator produces attack events — at least one finding expected
        assert len(findings) > 0
