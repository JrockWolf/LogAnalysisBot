"""Tests for CIC-IDS2017 dataset loading, parsing, analysis, evaluation,
MITRE ATT&CK mapping, and PCAP/pipeline support."""

import tempfile
from pathlib import Path

import pytest

from src.dataset_loader import (
    load_cicids_csv,
    normalize_label,
    dataset_summary,
    extract_flow_features,
    LABEL_CATEGORY,
)
from src.mitre_mapping import (
    map_category_to_mitre,
    map_finding_to_mitre,
    enrich_findings_with_mitre,
    TECHNIQUES,
)
from src.parsers import is_cicids_csv, parse_cicids_csv, parse_log, detect_file_type
from src.analyzer import heuristic_detect, _detect_network_attacks, _detect_pcap_attacks
from src.eval import (
    precision_recall_f1,
    binary_metrics,
    per_class_metrics,
    confusion_matrix,
)

# Path to the sample dataset created from full CIC-IDS2017
SAMPLE_DIR = Path(__file__).resolve().parents[1] / "samples"
SAMPLE_CSV = SAMPLE_DIR / "cicids2017_sample.csv"


# ── Dataset Loader Tests ─────────────────────────────────────────────

class TestNormalizeLabel:
    def test_benign(self):
        assert normalize_label("BENIGN") == "BENIGN"

    def test_ssh_patator(self):
        assert normalize_label("SSH-Patator") == "Brute Force"

    def test_ftp_patator(self):
        assert normalize_label("FTP-Patator") == "Brute Force"

    def test_dos_hulk(self):
        assert normalize_label("DoS Hulk") == "DoS"

    def test_dos_slowloris(self):
        assert normalize_label("DoS slowloris") == "DoS"

    def test_ddos(self):
        assert normalize_label("DDoS") == "DDoS"

    def test_portscan(self):
        assert normalize_label("PortScan") == "Reconnaissance"

    def test_bot(self):
        assert normalize_label("Bot") == "Botnet"

    def test_infiltration(self):
        assert normalize_label("Infiltration") == "Infiltration"

    def test_web_attack_brute_force(self):
        assert normalize_label("Web Attack - Brute Force") == "Web Attack"

    def test_web_attack_xss(self):
        assert normalize_label("Web Attack - XSS") == "Web Attack"

    def test_web_attack_sql_injection(self):
        assert normalize_label("Web Attack - Sql Injection") == "Web Attack"

    def test_fuzzy_match_dos(self):
        assert normalize_label("dos_something") == "DoS"

    def test_fuzzy_match_ddos(self):
        assert normalize_label("DDoS_variant") == "DDoS"


class TestLoadCicidsCsv:
    @pytest.fixture
    def mini_csv(self, tmp_path):
        csv_content = (
            "Destination Port,Flow Duration,Total Fwd Packets,Total Backward Packets,"
            "Total Length of Fwd Packets,Total Length of Bwd Packets,Flow Bytes/s,"
            "Flow Packets/s,SYN Flag Count,Label\n"
            "22,1000,5,3,500,300,8000,8,2,SSH-Patator\n"
            "80,500,2,1,200,100,6000,6,0,BENIGN\n"
            "443,2000,10,5,1000,500,7500,7.5,1,DDoS\n"
        )
        p = tmp_path / "test.csv"
        p.write_text(csv_content, encoding="utf-8")
        return p

    def test_load_basic(self, mini_csv):
        headers, rows = load_cicids_csv(mini_csv)
        assert len(rows) == 3
        assert "Destination Port" in headers
        assert "Label" in headers

    def test_categories_assigned(self, mini_csv):
        _, rows = load_cicids_csv(mini_csv)
        categories = [r["_category"] for r in rows]
        assert "Brute Force" in categories
        assert "BENIGN" in categories
        assert "DDoS" in categories

    def test_max_rows(self, mini_csv):
        _, rows = load_cicids_csv(mini_csv, max_rows=2)
        assert len(rows) == 2

    def test_attack_only(self, mini_csv):
        _, rows = load_cicids_csv(mini_csv, attack_only=True)
        assert all(r["_category"] != "BENIGN" for r in rows)
        assert len(rows) == 2

    @pytest.mark.skipif(not SAMPLE_CSV.exists(), reason="Sample dataset not found")
    def test_load_real_sample(self):
        headers, rows = load_cicids_csv(SAMPLE_CSV, max_rows=100)
        assert len(rows) > 0
        assert "Label" in headers


class TestDatasetSummary:
    def test_summary(self):
        rows = [
            {"_label": "BENIGN", "_category": "BENIGN"},
            {"_label": "SSH-Patator", "_category": "Brute Force"},
            {"_label": "DDoS", "_category": "DDoS"},
            {"_label": "BENIGN", "_category": "BENIGN"},
        ]
        s = dataset_summary(rows)
        assert s["total_flows"] == 4
        assert s["benign"] == 2
        assert s["malicious"] == 2
        assert "Brute Force" in s["category_distribution"]
        assert "DDoS" in s["category_distribution"]


class TestExtractFlowFeatures:
    def test_basic(self):
        row = {"Destination Port": "22", "Flow Duration": "1000", "Flow Bytes/s": "5000.5"}
        features = extract_flow_features(row)
        assert features["Destination Port"] == 22.0
        assert features["Flow Duration"] == 1000.0
        assert abs(features["Flow Bytes/s"] - 5000.5) < 0.01

    def test_nan_handling(self):
        row = {"Flow Bytes/s": "NaN", "Destination Port": "Infinity"}
        features = extract_flow_features(row)
        assert features["Flow Bytes/s"] == 0.0
        assert features["Destination Port"] == 0.0


# ── Parser Tests ──────────────────────────────────────────────────────

class TestCicidsParser:
    @pytest.fixture
    def cicids_csv(self, tmp_path):
        csv_content = (
            " Destination Port, Flow Duration, Total Fwd Packets, Label\n"
            "22, 1000, 5, SSH-Patator\n"
            "80, 500, 2, BENIGN\n"
        )
        p = tmp_path / "test_cicids.csv"
        p.write_text(csv_content, encoding="utf-8")
        return p

    @pytest.fixture
    def regular_csv(self, tmp_path):
        csv_content = "timestamp,message,level\n2024-01-01,test,INFO\n"
        p = tmp_path / "test_regular.csv"
        p.write_text(csv_content, encoding="utf-8")
        return p

    def test_is_cicids(self, cicids_csv):
        assert is_cicids_csv(cicids_csv) is True

    def test_is_not_cicids(self, regular_csv):
        assert is_cicids_csv(regular_csv) is False

    def test_parse_cicids_records(self, cicids_csv):
        records = parse_cicids_csv(cicids_csv)
        assert len(records) == 2
        assert records[0]["type"] == "cicids"
        assert records[0]["_category"] == "Brute Force"
        assert records[1]["_category"] == "BENIGN"
        assert "raw" in records[0]

    def test_parse_log_autodetect(self, cicids_csv):
        records = parse_log(cicids_csv)
        assert len(records) == 2
        assert records[0]["type"] == "cicids"


# ── MITRE ATT&CK Mapping Tests ───────────────────────────────────────

class TestMitreMapping:
    def test_map_brute_force(self):
        techniques = map_category_to_mitre("Brute Force")
        ids = [t.technique_id for t in techniques]
        assert "T1110" in ids

    def test_map_dos(self):
        techniques = map_category_to_mitre("DoS")
        ids = [t.technique_id for t in techniques]
        assert "T1499" in ids

    def test_map_ddos(self):
        techniques = map_category_to_mitre("DDoS")
        ids = [t.technique_id for t in techniques]
        assert "T1498" in ids

    def test_map_reconnaissance(self):
        techniques = map_category_to_mitre("Reconnaissance")
        ids = [t.technique_id for t in techniques]
        assert "T1046" in ids

    def test_map_web_attack(self):
        techniques = map_category_to_mitre("Web Attack")
        ids = [t.technique_id for t in techniques]
        assert "T1190" in ids

    def test_map_finding_ssh(self):
        techniques = map_finding_to_mitre("Multiple failed SSH logins from 192.168.1.1")
        ids = [t.technique_id for t in techniques]
        assert "T1110" in ids

    def test_map_finding_privilege_escalation(self):
        techniques = map_finding_to_mitre("User account attempting privilege escalation")
        ids = [t.technique_id for t in techniques]
        assert "T1078" in ids

    def test_enrich_findings(self):
        findings = ["Multiple failed SSH logins from 10.0.0.1 (5 attempts)"]
        enriched = enrich_findings_with_mitre(findings)
        assert len(enriched) == 1
        assert len(enriched[0]["mitre_techniques"]) > 0
        assert enriched[0]["mitre_techniques"][0]["technique_id"] == "T1110"

    def test_enrich_with_categories(self):
        findings = ["Some finding"]
        enriched = enrich_findings_with_mitre(findings, categories=["DDoS"])
        t_ids = [t["technique_id"] for t in enriched[0]["mitre_techniques"]]
        assert "T1498" in t_ids

    def test_technique_has_url(self):
        t = TECHNIQUES.get("T1110")
        assert t is not None
        assert t.url.startswith("https://")


# ── Analyzer Tests (Network Flows) ───────────────────────────────────

class TestNetworkAnalyzer:
    def test_detect_brute_force(self):
        records = [
            {"type": "cicids", "raw": "flow", "_label": "SSH-Patator", "_category": "Brute Force",
             "Destination Port": "22", "Flow Packets/s": "100", "SYN Flag Count": "1", "Flow Bytes/s": "5000"},
        ] * 10 + [
            {"type": "cicids", "raw": "flow", "_label": "BENIGN", "_category": "BENIGN",
             "Destination Port": "80", "Flow Packets/s": "50", "SYN Flag Count": "0", "Flow Bytes/s": "3000"},
        ] * 5
        findings = heuristic_detect(records)
        assert any("Brute Force" in f for f in findings)

    def test_detect_ddos(self):
        records = [
            {"type": "cicids", "raw": "flow", "_label": "DDoS", "_category": "DDoS",
             "Destination Port": "80", "Flow Packets/s": "15000", "SYN Flag Count": "10", "Flow Bytes/s": "2000000"},
        ] * 20 + [
            {"type": "cicids", "raw": "flow", "_label": "BENIGN", "_category": "BENIGN",
             "Destination Port": "443", "Flow Packets/s": "50", "SYN Flag Count": "0", "Flow Bytes/s": "3000"},
        ] * 5
        findings = heuristic_detect(records)
        assert any("DDoS" in f for f in findings)

    def test_detect_portscan(self):
        records = [
            {"type": "cicids", "raw": "flow", "_label": "PortScan", "_category": "Reconnaissance",
             "Destination Port": str(i), "Flow Packets/s": "500", "SYN Flag Count": "2", "Flow Bytes/s": "1000"}
            for i in range(1, 21)
        ] + [
            {"type": "cicids", "raw": "flow", "_label": "BENIGN", "_category": "BENIGN",
             "Destination Port": "80", "Flow Packets/s": "50", "SYN Flag Count": "0", "Flow Bytes/s": "3000"},
        ] * 5
        findings = heuristic_detect(records)
        assert any("Reconnaissance" in f or "Port Scan" in f for f in findings)

    def test_mixed_syslog_still_works(self):
        records = [
            {"raw": "Failed password for root from 10.0.0.1 port 22 ssh2"},
            {"raw": "Failed password for root from 10.0.0.1 port 22 ssh2"},
            {"raw": "Failed password for root from 10.0.0.1 port 22 ssh2"},
            {"raw": "Failed password for root from 10.0.0.1 port 22 ssh2"},
        ]
        findings = heuristic_detect(records)
        assert any("Multiple failed SSH logins" in f for f in findings)


# ── Eval Tests ────────────────────────────────────────────────────────

class TestBinaryMetrics:
    def test_perfect_classification(self):
        pred = ["malicious", "benign", "malicious", "benign"]
        gold = ["malicious", "benign", "malicious", "benign"]
        m = binary_metrics(pred, gold)
        assert m["accuracy"] == 1.0
        assert m["precision"] == 1.0
        assert m["recall"] == 1.0
        assert m["f1"] == 1.0

    def test_all_false_positives(self):
        pred = ["malicious", "malicious", "malicious"]
        gold = ["benign", "benign", "benign"]
        m = binary_metrics(pred, gold)
        assert m["precision"] == 0.0
        assert m["tp"] == 0
        assert m["fp"] == 3

    def test_mixed(self):
        pred = ["malicious", "malicious", "benign", "benign"]
        gold = ["malicious", "benign", "malicious", "benign"]
        m = binary_metrics(pred, gold)
        assert m["tp"] == 1
        assert m["fp"] == 1
        assert m["fn"] == 1
        assert m["tn"] == 1
        assert m["accuracy"] == 0.5


class TestPerClassMetrics:
    def test_basic(self):
        pred = ["A", "B", "A", "C"]
        gold = ["A", "B", "B", "C"]
        m = per_class_metrics(pred, gold)
        assert "A" in m
        assert "B" in m
        assert "C" in m
        assert m["A"]["support"] == 1
        assert m["C"]["recall"] == 1.0


class TestConfusionMatrix:
    def test_basic(self):
        pred = ["A", "B", "A"]
        gold = ["A", "A", "B"]
        cm = confusion_matrix(pred, gold)
        assert set(cm["labels"]) == {"A", "B"}
        assert len(cm["matrix"]) == 2

    def test_perfect(self):
        pred = ["A", "B", "C"]
        gold = ["A", "B", "C"]
        cm = confusion_matrix(pred, gold)
        # diagonal should be all 1s
        for i in range(3):
            assert cm["matrix"][i][i] == 1


class TestOriginalEval:
    def test_eval_metrics(self):
        preds = ["a", "b", "c"]
        gold = ["a", "c", "d"]
        stats = precision_recall_f1(preds, gold)
        assert stats["tp"] == 2
        assert stats["fp"] == 1
        assert stats["fn"] == 1


# ── Integration Tests ─────────────────────────────────────────────────

class TestIntegration:
    @pytest.mark.skipif(not SAMPLE_CSV.exists(), reason="Sample dataset not found")
    def test_full_pipeline_sample(self):
        """End-to-end: load sample CSV → parse → analyze → get findings."""
        records = parse_log(SAMPLE_CSV)
        assert len(records) > 0
        assert records[0]["type"] == "cicids"

        findings = heuristic_detect(records)
        assert len(findings) > 0
        assert any("attack" in f.lower() or "detected" in f.lower() for f in findings)

    @pytest.mark.skipif(not SAMPLE_CSV.exists(), reason="Sample dataset not found")
    def test_evaluate_sample(self):
        """End-to-end evaluation on sample dataset."""
        from src.eval import evaluate_dataset, format_evaluation_report

        results = evaluate_dataset(SAMPLE_CSV)
        assert "binary_metrics" in results
        assert "per_class_metrics" in results
        assert results["binary_metrics"]["total"] > 0

        report = format_evaluation_report(results)
        assert "EVALUATION REPORT" in report
        assert "Accuracy" in report


# ── File Type Detection Tests ─────────────────────────────────────────

class TestFileTypeDetection:
    def test_json_file(self, tmp_path):
        p = tmp_path / "test.json"
        p.write_text('[{"key": "value"}]')
        assert detect_file_type(p) == "json"

    def test_csv_file(self, tmp_path):
        p = tmp_path / "test.csv"
        p.write_text("col1,col2\nval1,val2\n")
        assert detect_file_type(p) == "csv"

    def test_text_file(self, tmp_path):
        p = tmp_path / "test.log"
        p.write_text("Jan 01 00:00:00 hostname sshd[1234]: test\n")
        assert detect_file_type(p) == "text"


# ── PCAP Heuristic Tests ─────────────────────────────────────────────

class TestPcapHeuristics:
    def test_syn_flood_detection(self):
        records = [
            {"type": "pcap", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
             "protocol": "TCP", "src_port": 12345 + i, "dst_port": 80,
             "tcp_flags": "S", "packet_size": 60}
            for i in range(100)
        ]
        findings = _detect_pcap_attacks(records)
        assert any("SYN Flood" in f or "SYN" in f for f in findings)

    def test_port_scan_detection(self):
        records = [
            {"type": "pcap", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
             "protocol": "TCP", "src_port": 54321, "dst_port": port,
             "tcp_flags": "S", "packet_size": 60}
            for port in range(1, 51)
        ]
        findings = _detect_pcap_attacks(records)
        assert any("Port Scan" in f for f in findings)

    def test_suspicious_ports(self):
        records = [
            {"type": "pcap", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
             "protocol": "TCP", "src_port": 12345, "dst_port": 4444,
             "tcp_flags": "SA", "packet_size": 100}
        ]
        findings = _detect_pcap_attacks(records)
        assert any("Suspicious" in f or "4444" in f for f in findings)

    def test_heuristic_detect_dispatches_pcap(self):
        records = [
            {"type": "pcap", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
             "protocol": "TCP", "src_port": 1234, "dst_port": 80,
             "tcp_flags": "SA", "packet_size": 100}
        ]
        findings = heuristic_detect(records)
        assert any("PCAP" in f for f in findings)


# ── Pipeline Tests ────────────────────────────────────────────────────

class TestPipeline:
    def test_extract_numeric_features(self):
        from src.pipeline import extract_numeric_features
        records = [
            {"a": "1.5", "b": "hello", "c": "3"},
            {"a": "2.5", "b": "world", "c": "4"},
        ]
        names, matrix = extract_numeric_features(records)
        assert len(matrix) == 2
        assert "a" in names
        assert "c" in names
        assert "b" not in names

    def test_compute_statistics(self):
        from src.pipeline import compute_statistics
        records = [
            {"x": "1", "y": "10"},
            {"x": "2", "y": "20"},
            {"x": "3", "y": "30"},
        ]
        result = compute_statistics(records)
        stats = result["stats"]
        assert "x" in stats
        assert stats["x"]["mean"] == 2.0
        assert stats["x"]["min"] == 1.0
        assert stats["x"]["max"] == 3.0

    def test_isolation_forest(self):
        from src.pipeline import run_isolation_forest
        # Create records with a clear outlier
        records = [{"val": str(i)} for i in range(50)]
        records.append({"val": "9999"})  # outlier
        result = run_isolation_forest(records, contamination=0.05)
        assert "anomaly_count" in result
        assert "total_records" in result
        assert result["total_records"] == 51

    def test_dataset_overview_generic(self):
        from src.pipeline import dataset_overview
        records = [
            {"a": "1", "b": "cat"},
            {"a": "2", "b": "dog"},
            {"a": "3", "b": "cat"},
        ]
        overview = dataset_overview(records)
        assert overview["total_records"] == 3

    @pytest.mark.skipif(not SAMPLE_CSV.exists(), reason="Sample dataset not found")
    def test_mitre_enrichment_on_sample(self):
        """MITRE mappings are produced for sample findings."""
        records = parse_log(SAMPLE_CSV)
        findings = heuristic_detect(records)
        enriched = enrich_findings_with_mitre(findings)
        # At least some findings should have MITRE tech
        has_mitre = any(e["mitre_techniques"] for e in enriched)
        assert has_mitre
