"""Generate server-side chart images using matplotlib and scikit-learn.

Produces base64-encoded PNG data URIs suitable for use in <img> tags.
Works with any supported input format: PCAP, CSV, JSON logs, labeled datasets, etc.
"""

from __future__ import annotations

import base64
import io
import math
from typing import Any, Dict, List

import matplotlib
matplotlib.use("Agg")  # non-interactive backend — must be set before pyplot import
import matplotlib.pyplot as plt
import numpy as np

# ── Theme constants ───────────────────────────────────────────────
_BG = "#1a1a2e"
_CARD = "#16213e"
_TEXT = "#e6e6f2"
_GRID = "#2a2a4a"
_ACCENT = "#8b5cf6"

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


def _colors_for(n: int) -> List[str]:
    return (CHART_COLORS * math.ceil(max(n, 1) / len(CHART_COLORS)))[:n]


def _apply_dark_theme(fig: plt.Figure, ax: plt.Axes) -> None:
    fig.patch.set_facecolor(_BG)
    ax.set_facecolor(_CARD)
    ax.tick_params(colors=_TEXT, labelsize=9)
    ax.xaxis.label.set_color(_TEXT)
    ax.yaxis.label.set_color(_TEXT)
    ax.title.set_color(_TEXT)
    for spine in ax.spines.values():
        spine.set_edgecolor(_GRID)
    ax.grid(color=_GRID, linestyle="--", linewidth=0.5, alpha=0.6)


def _fig_to_uri(fig: plt.Figure) -> str:
    """Save figure to a base64-encoded PNG data URI and close it."""
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight", dpi=96,
                facecolor=fig.get_facecolor())
    plt.close(fig)
    buf.seek(0)
    b64 = base64.b64encode(buf.read()).decode("ascii")
    return f"data:image/png;base64,{b64}"


# ── Chart builders ─────────────────────────────────────────────────

def _hbar(labels: List[str], values: List[float], title: str, xlabel: str) -> str:
    """Horizontal bar chart — replaces pie/doughnut for categorical distributions."""
    n = len(labels)
    fig_h = max(3.0, n * 0.42)
    fig, ax = plt.subplots(figsize=(8, fig_h))
    colors = _colors_for(n)
    y_pos = np.arange(n)
    bars = ax.barh(y_pos, values, color=colors, height=0.68, edgecolor="none")
    ax.set_yticks(y_pos)
    ax.set_yticklabels(labels, fontsize=9, color=_TEXT)
    ax.set_xlabel(xlabel, color=_TEXT)
    ax.set_title(title, color=_TEXT, fontsize=11, pad=10)
    ax.invert_yaxis()
    ax.xaxis.grid(True, color=_GRID, linestyle="--", linewidth=0.5, alpha=0.6)
    ax.yaxis.grid(False)
    # Value annotations
    x_max = max(values) if values else 1
    for bar, val in zip(bars, values):
        ax.text(
            bar.get_width() + x_max * 0.01,
            bar.get_y() + bar.get_height() / 2,
            f"{val:,.0f}" if isinstance(val, float) and val == int(val) else f"{val:,.2f}",
            va="center", ha="left", color=_TEXT, fontsize=8,
        )
    _apply_dark_theme(fig, ax)
    fig.tight_layout()
    return _fig_to_uri(fig)


def _vbar(labels: List[str], values: List[float], title: str, ylabel: str) -> str:
    """Vertical bar chart for short label sets."""
    n = len(labels)
    fig, ax = plt.subplots(figsize=(max(6, n * 0.55), 4.5))
    colors = _colors_for(n)
    x_pos = np.arange(n)
    ax.bar(x_pos, values, color=colors, width=0.7, edgecolor="none")
    ax.set_xticks(x_pos)
    ax.set_xticklabels(labels, rotation=40, ha="right", fontsize=9, color=_TEXT)
    ax.set_ylabel(ylabel, color=_TEXT)
    ax.set_title(title, color=_TEXT, fontsize=11, pad=10)
    ax.xaxis.grid(False)
    ax.yaxis.grid(True, color=_GRID, linestyle="--", linewidth=0.5, alpha=0.6)
    _apply_dark_theme(fig, ax)
    fig.tight_layout()
    return _fig_to_uri(fig)


def _histogram(values: List[float], title: str, xlabel: str, bins: int = 20) -> str:
    """Histogram using numpy/sklearn-compatible bin computation."""
    arr = np.array(values, dtype=float)
    arr = arr[np.isfinite(arr)]
    if arr.size == 0:
        return ""
    # Use numpy to compute bins (same approach as sklearn histogram utilities)
    counts, edges = np.histogram(arr, bins=bins)
    centers = (edges[:-1] + edges[1:]) / 2
    widths = edges[1:] - edges[:-1]
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.bar(centers, counts, width=widths * 0.9, color=_ACCENT,
           edgecolor=_GRID, linewidth=0.5)
    ax.set_xlabel(xlabel, color=_TEXT)
    ax.set_ylabel("Count", color=_TEXT)
    ax.set_title(title, color=_TEXT, fontsize=11, pad=10)
    ax.yaxis.grid(True, color=_GRID, linestyle="--", linewidth=0.5, alpha=0.6)
    ax.xaxis.grid(False)
    _apply_dark_theme(fig, ax)
    fig.tight_layout()
    return _fig_to_uri(fig)


def _stacked_hbar_two(
    val1: float, val2: float, label1: str, label2: str,
    color1: str, color2: str, title: str,
) -> str:
    """Stacked horizontal bar for two-class comparison (e.g. benign vs malicious)."""
    total = val1 + val2
    if total <= 0:
        return ""
    fig, ax = plt.subplots(figsize=(8, 1.8))
    ax.barh([0], [val1], color=color1, height=0.5, label=label1)
    ax.barh([0], [val2], left=[val1], color=color2, height=0.5, label=label2)
    ax.set_yticks([])
    ax.set_xlabel("Count", color=_TEXT)
    ax.set_title(title, color=_TEXT, fontsize=11, pad=10)
    pct1, pct2 = 100 * val1 / total, 100 * val2 / total
    ax.text(val1 / 2, 0, f"{label1}\n{pct1:.1f}%",
            ha="center", va="center", color="white", fontsize=9, fontweight="bold")
    ax.text(val1 + val2 / 2, 0, f"{label2}\n{pct2:.1f}%",
            ha="center", va="center", color="white", fontsize=9, fontweight="bold")
    ax.legend(labelcolor=_TEXT, facecolor=_CARD, edgecolor=_GRID,
              loc="upper right", fontsize=9)
    _apply_dark_theme(fig, ax)
    fig.tight_layout()
    return _fig_to_uri(fig)


def _feature_importance_plot(importances: Dict[str, float], title: str) -> str:
    """sklearn-style feature importance horizontal bar chart."""
    from sklearn.utils.validation import check_consistent_length  # noqa: F401 — validates sklearn available
    items = sorted(importances.items(), key=lambda x: x[1])[-15:]
    if not items:
        return ""
    labels = [i[0] for i in items]
    vals = [i[1] for i in items]
    n = len(labels)
    fig, ax = plt.subplots(figsize=(8, max(3.0, n * 0.42)))
    y_pos = np.arange(n)
    # Colour by magnitude (sklearn style)
    norm_vals = np.array(vals)
    norm_vals = (norm_vals - norm_vals.min()) / ((norm_vals.max() - norm_vals.min()) + 1e-9)
    colors = plt.cm.plasma(norm_vals)  # type: ignore[attr-defined]
    ax.barh(y_pos, vals, color=colors, height=0.68, edgecolor="none")
    ax.set_yticks(y_pos)
    ax.set_yticklabels(labels, fontsize=9, color=_TEXT)
    ax.set_xlabel("Importance Score", color=_TEXT)
    ax.set_title(title, color=_TEXT, fontsize=11, pad=10)
    ax.xaxis.grid(True, color=_GRID, linestyle="--", linewidth=0.5, alpha=0.6)
    ax.yaxis.grid(False)
    _apply_dark_theme(fig, ax)
    fig.tight_layout()
    return _fig_to_uri(fig)


def generate_chart_data(
    rows: List[Dict[str, Any]] | None = None,
    findings: List[str] | None = None,
    dataset_summary: Dict[str, Any] | None = None,
    anomaly_result: Dict[str, Any] | None = None,
    statistics: Dict[str, Any] | None = None,
) -> Dict[str, str]:
    """Return a dict of chart image data URIs keyed by chart id.

    Each value is a base64-encoded PNG data URI suitable for an <img> src.
    Accepts data from any source type and generates appropriate matplotlib charts.
    """
    charts: Dict[str, str] = {}

    # ── Dataset overview charts ───────────────────────────────────────
    if dataset_summary:
        # Categories / labels distribution
        cats = dataset_summary.get("categories") or dataset_summary.get("category_distribution", {})
        if cats:
            items = sorted(cats.items(), key=lambda x: -x[1])
            uri = _hbar([i[0] for i in items], [float(i[1]) for i in items],
                        "Category Distribution", "Count")
            if uri:
                charts["category_distribution"] = uri

        benign = dataset_summary.get("benign", 0)
        malicious = dataset_summary.get("malicious", 0)
        if benign or malicious:
            uri = _stacked_hbar_two(
                float(benign), float(malicious),
                "Benign", "Malicious",
                "#34d399", "#ff6b6b",
                "Benign vs Malicious Traffic",
            )
            if uri:
                charts["benign_vs_malicious"] = uri

        # Protocol distribution (PCAP)
        protocols = dataset_summary.get("protocols", {})
        if protocols:
            items = sorted(protocols.items(), key=lambda x: -x[1])[:15]
            uri = _hbar([p[0] for p in items], [float(p[1]) for p in items],
                        "Protocol Distribution", "Packet Count")
            if uri:
                charts["protocol_distribution"] = uri

        # Top source IPs
        top_src = dataset_summary.get("top_sources", {})
        if top_src:
            items = sorted(top_src.items(), key=lambda x: -x[1])[:15]
            uri = _hbar([p[0] for p in items], [float(p[1]) for p in items],
                        "Top Source IPs", "Packet Count")
            if uri:
                charts["top_source_ips"] = uri

        # Top destination IPs
        top_dst = dataset_summary.get("top_destinations", {})
        if top_dst:
            items = sorted(top_dst.items(), key=lambda x: -x[1])[:15]
            uri = _hbar([p[0] for p in items], [float(p[1]) for p in items],
                        "Top Destination IPs", "Packet Count")
            if uri:
                charts["top_dest_ips"] = uri

        # Record types
        rtypes = dataset_summary.get("record_types", {})
        if rtypes and len(rtypes) > 1:
            items = sorted(rtypes.items(), key=lambda x: -x[1])
            uri = _hbar([i[0] for i in items], [float(i[1]) for i in items],
                        "Record Types", "Count")
            if uri:
                charts["record_types"] = uri

    # ── Row-level labeled dataset charts ────────────────────────────────
    if rows and rows[0].get("type") == "dataset":
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
            uri = _vbar(
                [f"Port {p[0]}" for p in top_ports],
                [float(p[1]) for p in top_ports],
                "Top Destination Ports", "Flow Count",
            )
            if uri:
                charts["top_ports"] = uri

        # Avg metrics per attack category
        for metric_key, metric_map, title, xlabel in [
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
                uri = _hbar([c[0] for c in s], [c[1] for c in s], title, xlabel)
                if uri:
                    charts[metric_key] = uri

        if flow_count:
            sf = sorted(flow_count.items(), key=lambda x: -x[1])
            uri = _hbar([c[0] for c in sf], [float(c[1]) for c in sf],
                        "Flow Count by Category", "Number of Flows")
            if uri:
                charts["flows_per_category"] = uri

    # ── Row-level PCAP charts ─────────────────────────────────────────
    if rows and rows[0].get("type") == "pcap":
        port_counts_pcap: Dict[str, int] = {}
        pkt_sizes: List[float] = []
        for r in rows:
            dp = r.get("dst_port")
            if dp is not None:
                port_counts_pcap[str(dp)] = port_counts_pcap.get(str(dp), 0) + 1
            sz = r.get("length")
            if sz is not None:
                pkt_sizes.append(float(sz))

        top_ports_pcap = sorted(port_counts_pcap.items(), key=lambda x: -x[1])[:15]
        if top_ports_pcap:
            uri = _vbar(
                [f"Port {p[0]}" for p in top_ports_pcap],
                [float(p[1]) for p in top_ports_pcap],
                "Top Destination Ports", "Packet Count",
            )
            if uri:
                charts["top_ports"] = uri

        # Packet size distribution — real histogram via matplotlib/numpy
        if pkt_sizes:
            uri = _histogram(pkt_sizes, "Packet Size Distribution", "Packet Size (bytes)", bins=20)
            if uri:
                charts["packet_sizes"] = uri

        # TCP flags distribution
        flag_counts: Dict[str, int] = {}
        for r in rows:
            flags = r.get("tcp_flags", "")
            if flags:
                flag_counts[flags] = flag_counts.get(flags, 0) + 1
        if flag_counts:
            top_flags = sorted(flag_counts.items(), key=lambda x: -x[1])[:10]
            uri = _hbar([f[0] for f in top_flags], [float(f[1]) for f in top_flags],
                        "TCP Flag Distribution", "Count")
            if uri:
                charts["tcp_flags"] = uri

    # ── Anomaly detection charts ──────────────────────────────────────
    if anomaly_result:
        anom_count = anomaly_result.get("anomaly_count", 0)
        total_recs = anomaly_result.get("total_records", 0)
        normal_count = total_recs - anom_count
        if total_recs > 0:
            uri = _stacked_hbar_two(
                float(normal_count), float(anom_count),
                "Normal", "Anomalous",
                "#34d399", "#ff6b6b",
                "Normal vs Anomalous Records",
            )
            if uri:
                charts["anomaly_split"] = uri

        importances = anomaly_result.get("feature_importances", {})
        if importances:
            uri = _feature_importance_plot(importances, "Feature Importance (Anomaly Detection)")
            if uri:
                charts["feature_importances"] = uri

        scores = anomaly_result.get("anomaly_scores", [])
        if scores:
            uri = _histogram(scores, "Anomaly Score Distribution", "Anomaly Score", bins=20)
            if uri:
                charts["anomaly_score_dist"] = uri

    # ── Statistics charts ─────────────────────────────────────────────
    if statistics:
        stats = statistics.get("stats", {})
        if stats:
            # Top features by standard deviation (most variable)
            by_std = sorted(
                [(k, v.get("std", 0)) for k, v in stats.items()],
                key=lambda x: -x[1],
            )[:12]
            if by_std:
                uri = _hbar([b[0] for b in by_std], [b[1] for b in by_std],
                            "Feature Variability (Std Dev)", "Standard Deviation")
                if uri:
                    charts["feature_variability"] = uri

            # Mean values for top features
            by_mean = sorted(
                [(k, v.get("mean", 0)) for k, v in stats.items()],
                key=lambda x: -abs(x[1]),
            )[:12]
            if by_mean:
                uri = _hbar([b[0] for b in by_mean], [b[1] for b in by_mean],
                            "Feature Mean Values", "Mean")
                if uri:
                    charts["feature_means"] = uri

    # ── Findings-based charts ─────────────────────────────────────────
    if findings:
        finding_cats: Dict[str, int] = {}
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
            finding_cats[cat] = finding_cats.get(cat, 0) + 1

        if finding_cats:
            sc = sorted(finding_cats.items(), key=lambda x: -x[1])
            uri = _hbar([c[0] for c in sc], [float(c[1]) for c in sc],
                        "Findings by Category", "Count")
            if uri:
                charts["findings_by_type"] = uri

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
            sev_items = sorted(severity.items(), key=lambda x: -x[1])
            uri = _hbar(
                [i[0] for i in sev_items],
                [float(i[1]) for i in sev_items],
                "Findings Severity Breakdown",
                "Count",
            )
            if uri:
                charts["findings_severity"] = uri

    return charts
