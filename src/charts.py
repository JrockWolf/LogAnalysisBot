"""Generate chart data structures for the web UI (consumed by Chart.js).

Works with any supported input format: PCAP, CSV, JSON logs, CIC-IDS2017, etc.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List

CHART_COLORS = [
    "#8b5cf6", "#60a5fa", "#f472b6", "#34d399", "#fbbf24",
    "#ff6b6b", "#7c3aed", "#3b82f6", "#ec4899", "#10b981",
    "#f59e0b", "#ef4444", "#6d28d9", "#2563eb", "#db2777",
]


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


def generate_chart_data(
    rows: List[Dict[str, Any]] | None = None,
    findings: List[str] | None = None,
    dataset_summary: Dict[str, Any] | None = None,
    anomaly_result: Dict[str, Any] | None = None,
    statistics: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Return a dict of chart descriptors keyed by chart id.

    Accepts data from any source type and generates appropriate charts.
    """
    charts: Dict[str, Any] = {}

    # ── Dataset overview charts ───────────────────────────────────────
    if dataset_summary:
        # Categories / labels distribution
        cats = dataset_summary.get("categories") or dataset_summary.get("category_distribution", {})
        if cats:
            labels = list(cats.keys())
            charts["category_distribution"] = {
                "type": "doughnut",
                "title": "Category Distribution",
                "labels": labels,
                "data": list(cats.values()),
                "colors": CHART_COLORS[: len(labels)],
            }

        benign = dataset_summary.get("benign", 0)
        malicious = dataset_summary.get("malicious", 0)
        if benign or malicious:
            charts["benign_vs_malicious"] = {
                "type": "pie",
                "title": "Benign vs Malicious Traffic",
                "labels": ["Benign", "Malicious"],
                "data": [benign, malicious],
                "colors": ["#34d399", "#ff6b6b"],
            }

        # Protocol distribution (PCAP)
        protocols = dataset_summary.get("protocols", {})
        if protocols:
            items = sorted(protocols.items(), key=lambda x: -x[1])[:15]
            charts["protocol_distribution"] = {
                "type": "doughnut",
                "title": "Protocol Distribution",
                "labels": [p[0] for p in items],
                "data": [p[1] for p in items],
                "colors": CHART_COLORS[: len(items)],
            }

        # Top source IPs
        top_src = dataset_summary.get("top_sources", {})
        if top_src:
            items = sorted(top_src.items(), key=lambda x: -x[1])[:15]
            charts["top_source_ips"] = {
                "type": "bar",
                "title": "Top Source IPs",
                "labels": [p[0] for p in items],
                "data": [p[1] for p in items],
                "colors": CHART_COLORS[: len(items)],
                "axis_label": "Packet Count",
                "horizontal": True,
            }

        # Top destination IPs
        top_dst = dataset_summary.get("top_destinations", {})
        if top_dst:
            items = sorted(top_dst.items(), key=lambda x: -x[1])[:15]
            charts["top_dest_ips"] = {
                "type": "bar",
                "title": "Top Destination IPs",
                "labels": [p[0] for p in items],
                "data": [p[1] for p in items],
                "colors": CHART_COLORS[: len(items)],
                "axis_label": "Packet Count",
                "horizontal": True,
            }

        # Record types
        rtypes = dataset_summary.get("record_types", {})
        if rtypes and len(rtypes) > 1:
            charts["record_types"] = {
                "type": "pie",
                "title": "Record Types",
                "labels": list(rtypes.keys()),
                "data": list(rtypes.values()),
                "colors": CHART_COLORS[: len(rtypes)],
            }

    # ── Row-level CIC-IDS2017 charts ──────────────────────────────────
    if rows and rows[0].get("type") == "cicids":
        port_counts: Dict[str, int] = {}
        bytes_per_cat: Dict[str, float] = {}
        pkts_per_cat: Dict[str, float] = {}
        flow_count: Dict[str, int] = {}
        syn_per_cat: Dict[str, float] = {}

        for r in rows:
            port = str(r.get("Destination Port", "")).strip()
            if port:
                port_counts[port] = port_counts.get(port, 0) + 1
            cat = r.get("_category", "UNKNOWN")
            flow_count[cat] = flow_count.get(cat, 0) + 1
            bytes_per_cat[cat] = bytes_per_cat.get(cat, 0) + _safe_float(r.get("Flow Bytes/s", 0))
            pkts_per_cat[cat] = pkts_per_cat.get(cat, 0) + _safe_float(r.get("Flow Packets/s", 0))
            syn_per_cat[cat] = syn_per_cat.get(cat, 0) + _safe_float(r.get("SYN Flag Count", 0))

        top_ports = sorted(port_counts.items(), key=lambda x: -x[1])[:15]
        if top_ports:
            charts["top_ports"] = {
                "type": "bar",
                "title": "Top Destination Ports",
                "labels": [f"Port {p[0]}" for p in top_ports],
                "data": [p[1] for p in top_ports],
                "colors": CHART_COLORS[: len(top_ports)],
                "axis_label": "Flow Count",
            }

        # Avg metrics per attack category
        for metric_key, metric_map, title, axis in [
            ("avg_bytes_per_category", bytes_per_cat, "Avg Flow Bytes/s by Category", "Avg Bytes/s"),
            ("avg_packets_per_category", pkts_per_cat, "Avg Flow Packets/s by Category", "Avg Packets/s"),
            ("syn_flags_per_category", syn_per_cat, "Avg SYN Flags by Category", "Avg SYN Flags"),
        ]:
            attack_vals = {
                k: round(metric_map[k] / flow_count[k], 2)
                for k in metric_map if k != "BENIGN" and flow_count.get(k, 0) > 0
            }
            if attack_vals:
                s = sorted(attack_vals.items(), key=lambda x: -x[1])
                charts[metric_key] = {
                    "type": "bar", "title": title,
                    "labels": [c[0] for c in s], "data": [c[1] for c in s],
                    "colors": CHART_COLORS[: len(s)], "axis_label": axis,
                }

        if flow_count:
            sf = sorted(flow_count.items(), key=lambda x: -x[1])
            charts["flows_per_category"] = {
                "type": "bar", "title": "Flow Count by Category",
                "labels": [c[0] for c in sf], "data": [c[1] for c in sf],
                "colors": CHART_COLORS[: len(sf)], "axis_label": "Number of Flows",
                "horizontal": True,
            }

    # ── Row-level PCAP charts ─────────────────────────────────────────
    if rows and rows[0].get("type") == "pcap":
        port_counts_pcap: Dict[str, int] = {}
        for r in rows:
            dp = r.get("dst_port")
            if dp is not None:
                port_counts_pcap[str(dp)] = port_counts_pcap.get(str(dp), 0) + 1
        top_ports_pcap = sorted(port_counts_pcap.items(), key=lambda x: -x[1])[:15]
        if top_ports_pcap:
            charts["top_ports"] = {
                "type": "bar", "title": "Top Destination Ports",
                "labels": [f"Port {p[0]}" for p in top_ports_pcap],
                "data": [p[1] for p in top_ports_pcap],
                "colors": CHART_COLORS[: len(top_ports_pcap)],
                "axis_label": "Packet Count",
            }

        # Packet size distribution (histogram-like)
        size_buckets = {"0-64": 0, "65-256": 0, "257-512": 0, "513-1024": 0, "1025-1500": 0, "1500+": 0}
        for r in rows:
            sz = r.get("length", 0)
            if sz <= 64:
                size_buckets["0-64"] += 1
            elif sz <= 256:
                size_buckets["65-256"] += 1
            elif sz <= 512:
                size_buckets["257-512"] += 1
            elif sz <= 1024:
                size_buckets["513-1024"] += 1
            elif sz <= 1500:
                size_buckets["1025-1500"] += 1
            else:
                size_buckets["1500+"] += 1
        charts["packet_sizes"] = {
            "type": "bar", "title": "Packet Size Distribution",
            "labels": list(size_buckets.keys()),
            "data": list(size_buckets.values()),
            "colors": CHART_COLORS[:6],
            "axis_label": "Packet Count",
        }

        # TCP flags distribution
        flag_counts: Dict[str, int] = {}
        for r in rows:
            flags = r.get("tcp_flags", "")
            if flags:
                flag_counts[flags] = flag_counts.get(flags, 0) + 1
        if flag_counts:
            top_flags = sorted(flag_counts.items(), key=lambda x: -x[1])[:10]
            charts["tcp_flags"] = {
                "type": "bar", "title": "TCP Flag Distribution",
                "labels": [f[0] for f in top_flags],
                "data": [f[1] for f in top_flags],
                "colors": CHART_COLORS[: len(top_flags)],
                "axis_label": "Count",
            }

    # ── Anomaly detection charts ──────────────────────────────────────
    if anomaly_result:
        anom_count = anomaly_result.get("anomaly_count", 0)
        total_recs = anomaly_result.get("total_records", 0)
        normal_count = total_recs - anom_count
        if total_recs > 0:
            charts["anomaly_split"] = {
                "type": "pie", "title": "Normal vs Anomalous Records",
                "labels": ["Normal", "Anomalous"],
                "data": [normal_count, anom_count],
                "colors": ["#34d399", "#ff6b6b"],
            }

        importances = anomaly_result.get("feature_importances", {})
        if importances:
            top_imp = list(importances.items())[:12]
            charts["feature_importances"] = {
                "type": "bar", "title": "Feature Importance (Anomaly Detection)",
                "labels": [i[0] for i in top_imp],
                "data": [i[1] for i in top_imp],
                "colors": CHART_COLORS[: len(top_imp)],
                "axis_label": "Importance Score",
                "horizontal": True,
            }

        scores = anomaly_result.get("anomaly_scores", [])
        if scores:
            # Histogram of anomaly scores
            import math
            bins = 20
            if scores:
                mn = min(scores)
                mx = max(scores)
                rng = mx - mn if mx != mn else 1.0
                bin_width = rng / bins
                hist = [0] * bins
                for s in scores:
                    b = min(int((s - mn) / bin_width), bins - 1)
                    hist[b] += 1
                bin_labels = [f"{mn + i * bin_width:.2f}" for i in range(bins)]
                charts["anomaly_score_dist"] = {
                    "type": "bar", "title": "Anomaly Score Distribution",
                    "labels": bin_labels, "data": hist,
                    "colors": ["#8b5cf6"] * bins,
                    "axis_label": "Record Count",
                }

    # ── Statistics charts ─────────────────────────────────────────────
    if statistics:
        stats = statistics.get("stats", {})
        if stats:
            # Top features by standard deviation (most variable)
            by_std = sorted(
                [(k, v.get("std", 0)) for k, v in stats.items()],
                key=lambda x: -x[1]
            )[:12]
            if by_std:
                charts["feature_variability"] = {
                    "type": "bar", "title": "Feature Variability (Std Dev)",
                    "labels": [b[0] for b in by_std],
                    "data": [b[1] for b in by_std],
                    "colors": CHART_COLORS[: len(by_std)],
                    "axis_label": "Standard Deviation",
                    "horizontal": True,
                }

            # Mean values for top features
            by_mean = sorted(
                [(k, v.get("mean", 0)) for k, v in stats.items()],
                key=lambda x: -abs(x[1])
            )[:12]
            if by_mean:
                charts["feature_means"] = {
                    "type": "bar", "title": "Feature Mean Values",
                    "labels": [b[0] for b in by_mean],
                    "data": [b[1] for b in by_mean],
                    "colors": CHART_COLORS[: len(by_mean)],
                    "axis_label": "Mean",
                    "horizontal": True,
                }

    # ── Findings-based charts ─────────────────────────────────────────
    if findings:
        cats: Dict[str, int] = {}
        for f in findings:
            fl = f.lower()
            if "brute force" in fl or "ssh" in fl or "ftp" in fl:
                cat = "Brute Force"
            elif "ddos" in fl:
                cat = "DDoS"
            elif "dos" in fl or "denial" in fl:
                cat = "DoS"
            elif "port scan" in fl or "reconnaissance" in fl:
                cat = "Reconnaissance"
            elif "web attack" in fl or "xss" in fl or "sql" in fl:
                cat = "Web Attack"
            elif "botnet" in fl or "bot " in fl:
                cat = "Botnet"
            elif "infiltration" in fl or "exfiltration" in fl:
                cat = "Infiltration"
            elif "anomaly" in fl or "high" in fl or "flood" in fl:
                cat = "Anomaly"
            elif "privilege" in fl or "escalation" in fl:
                cat = "Privilege Esc."
            elif "(error)" in fl or "(info)" in fl:
                cat = "Informational"
            else:
                cat = "Other"
            cats[cat] = cats.get(cat, 0) + 1

        if cats:
            sc = sorted(cats.items(), key=lambda x: -x[1])
            chart_type = "doughnut" if len(sc) > 1 else "bar"
            charts["findings_by_type"] = {
                "type": chart_type, "title": "Findings by Category",
                "labels": [c[0] for c in sc], "data": [c[1] for c in sc],
                "colors": CHART_COLORS[: len(sc)], "axis_label": "Count",
            }

        severity: Dict[str, int] = {"Critical": 0, "Warning": 0, "Info": 0}
        for f in findings:
            fl = f.lower()
            if any(k in fl for k in ("ddos", "flood", "exfiltration", "botnet", "infiltration")):
                severity["Critical"] += 1
            elif any(k in fl for k in ("brute", "dos", "attack", "scan", "anomaly", "privilege", "unauthorized")):
                severity["Warning"] += 1
            else:
                severity["Info"] += 1
        severity = {k: v for k, v in severity.items() if v > 0}
        if severity:
            charts["findings_severity"] = {
                "type": "doughnut", "title": "Findings Severity Breakdown",
                "labels": list(severity.keys()),
                "data": list(severity.values()),
                "colors": ["#ff6b6b", "#fbbf24", "#60a5fa"][: len(severity)],
            }

    return charts
