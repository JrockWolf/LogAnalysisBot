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


def _confusion_matrix_heatmap(labels: List[str], matrix: List[List[int]], title: str) -> str:
    """Render a confusion matrix as a heatmap."""
    n = len(labels)
    if n == 0:
        return ""
    arr = np.array(matrix, dtype=float)
    fig, ax = plt.subplots(figsize=(max(5, n * 0.8 + 2), max(4, n * 0.7 + 1.5)))
    cmap = plt.cm.Purples  # type: ignore[attr-defined]
    im = ax.imshow(arr, cmap=cmap, aspect="auto")
    ax.set_xticks(np.arange(n))
    ax.set_yticks(np.arange(n))
    short_labels = [l[:16] for l in labels]
    ax.set_xticklabels(short_labels, rotation=45, ha="right", fontsize=8, color=_TEXT)
    ax.set_yticklabels(short_labels, fontsize=8, color=_TEXT)
    ax.set_xlabel("Predicted", color=_TEXT, fontsize=10)
    ax.set_ylabel("Actual", color=_TEXT, fontsize=10)
    ax.set_title(title, color=_TEXT, fontsize=11, pad=10)
    # Cell annotations
    thresh = arr.max() / 2.0
    for i in range(n):
        for j in range(n):
            val = int(arr[i, j])
            ax.text(j, i, str(val), ha="center", va="center",
                    color="white" if arr[i, j] > thresh else _TEXT, fontsize=9)
    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    _apply_dark_theme(fig, ax)
    fig.tight_layout()
    return _fig_to_uri(fig)


def _grouped_bar(groups: List[str], series: Dict[str, List[float]], title: str, ylabel: str) -> str:
    """Grouped bar chart for comparing multiple series across groups."""
    n_groups = len(groups)
    n_series = len(series)
    if n_groups == 0 or n_series == 0:
        return ""
    fig, ax = plt.subplots(figsize=(max(6, n_groups * 1.2), 4.5))
    x = np.arange(n_groups)
    width = 0.7 / n_series
    colors = _colors_for(n_series)
    for i, (name, vals) in enumerate(series.items()):
        offset = (i - n_series / 2 + 0.5) * width
        bars = ax.bar(x + offset, vals[:n_groups], width, label=name, color=colors[i], edgecolor="none")
        for bar, val in zip(bars, vals[:n_groups]):
            ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                    f"{val:.2f}", ha="center", va="bottom", color=_TEXT, fontsize=7)
    ax.set_xticks(x)
    ax.set_xticklabels(groups, fontsize=9, color=_TEXT)
    ax.set_ylabel(ylabel, color=_TEXT)
    ax.set_title(title, color=_TEXT, fontsize=11, pad=10)
    ax.legend(labelcolor=_TEXT, facecolor=_CARD, edgecolor=_GRID, fontsize=9)
    ax.yaxis.grid(True, color=_GRID, linestyle="--", linewidth=0.5, alpha=0.6)
    ax.xaxis.grid(False)
    _apply_dark_theme(fig, ax)
    fig.tight_layout()
    return _fig_to_uri(fig)


def _error_bar_chart(categories: Dict[str, int], title: str, xlabel: str, color: str = "#ff6b6b") -> str:
    """Horizontal bar chart for error categories (FP/FN breakdown)."""
    if not categories:
        return ""
    items = sorted(categories.items(), key=lambda x: -x[1])[:15]
    labels = [i[0] for i in items]
    values = [float(i[1]) for i in items]
    n = len(labels)
    fig, ax = plt.subplots(figsize=(8, max(2.5, n * 0.42)))
    y_pos = np.arange(n)
    ax.barh(y_pos, values, color=color, height=0.68, edgecolor="none", alpha=0.85)
    ax.set_yticks(y_pos)
    ax.set_yticklabels(labels, fontsize=9, color=_TEXT)
    ax.set_xlabel(xlabel, color=_TEXT)
    ax.set_title(title, color=_TEXT, fontsize=11, pad=10)
    ax.invert_yaxis()
    ax.xaxis.grid(True, color=_GRID, linestyle="--", linewidth=0.5, alpha=0.6)
    ax.yaxis.grid(False)
    for bar, val in zip(ax.patches, values):
        ax.text(bar.get_width() + max(values) * 0.01, bar.get_y() + bar.get_height() / 2,
                f"{val:,.0f}", va="center", ha="left", color=_TEXT, fontsize=8)
    _apply_dark_theme(fig, ax)
    fig.tight_layout()
    return _fig_to_uri(fig)


# ── Structured log charts ──────────────────────────────────────────────────

def generate_structured_charts(records: List[Dict[str, Any]]) -> Dict[str, str]:
    """Generate charts specifically for structurized text/syslog records.

    Produces: top source IPs, severity distribution, protocol distribution,
    action counts, top destination ports, HTTP status code distribution,
    hourly activity.
    Returns a dict of chart_id → base64 PNG data URI.
    """
    charts: Dict[str, str] = {}
    if not records:
        return charts

    # Collect field data
    src_ips: Dict[str, int] = {}
    dst_ips: Dict[str, int] = {}
    severities: Dict[str, int] = {}
    protocols: Dict[str, int] = {}
    actions: Dict[str, int] = {}
    dst_ports: Dict[int, int] = {}
    status_codes: Dict[int, int] = {}
    hours: List[int] = []

    for r in records:
        if r.get("src_ip"):
            src_ips[r["src_ip"]] = src_ips.get(r["src_ip"], 0) + 1
        if r.get("dst_ip"):
            dst_ips[r["dst_ip"]] = dst_ips.get(r["dst_ip"], 0) + 1
        sev = r.get("severity") or "unknown"
        severities[sev] = severities.get(sev, 0) + 1
        if r.get("protocol"):
            p = str(r["protocol"]).upper()
            protocols[p] = protocols.get(p, 0) + 1
        if r.get("action"):
            a = str(r["action"]).upper()
            actions[a] = actions.get(a, 0) + 1
        dp = r.get("dst_port")
        if dp is not None:
            try:
                dst_ports[int(dp)] = dst_ports.get(int(dp), 0) + 1
            except (TypeError, ValueError):
                pass
        sc = r.get("status_code")
        if sc is not None:
            try:
                status_codes[int(sc)] = status_codes.get(int(sc), 0) + 1
            except (TypeError, ValueError):
                pass
        hr = r.get("hour")
        if hr is None:
            ts = r.get("timestamp")
            if ts:
                import re as _re
                hm = _re.search(r"\b(\d{1,2}):\d{2}", str(ts))
                if hm:
                    try:
                        hr = int(hm.group(1))
                    except ValueError:
                        pass
        if hr is not None:
            try:
                hours.append(int(hr))
            except (TypeError, ValueError):
                pass

    # Top 15 source IPs
    if src_ips:
        top = sorted(src_ips.items(), key=lambda x: -x[1])[:15]
        uri = _hbar([t[0] for t in top], [float(t[1]) for t in top],
                    "Top Source IPs", "Events")
        if uri:
            charts["struct_top_src_ips"] = uri

    # Top 10 destination IPs
    if dst_ips:
        top = sorted(dst_ips.items(), key=lambda x: -x[1])[:10]
        uri = _hbar([t[0] for t in top], [float(t[1]) for t in top],
                    "Top Destination IPs", "Events")
        if uri:
            charts["struct_top_dst_ips"] = uri

    # Severity distribution
    _SEV_ORDER = ["emerg", "alert", "crit", "critical", "error",
                  "warning", "warn", "notice", "info", "debug", "unknown"]
    if severities:
        ordered = sorted(severities.items(),
                         key=lambda x: _SEV_ORDER.index(x[0]) if x[0] in _SEV_ORDER else 99)
        _SEV_COLORS = {
            "emerg": "#ef4444", "alert": "#ef4444", "crit": "#ef4444", "critical": "#ef4444",
            "error": "#f97316", "warning": "#fbbf24", "warn": "#fbbf24",
            "notice": "#60a5fa", "info": "#34d399", "debug": "#a1a1aa", "unknown": "#6b7280",
        }
        colors = [_SEV_COLORS.get(k, _ACCENT) for k, _ in ordered]
        n = len(ordered)
        fig, ax = plt.subplots(figsize=(7, max(2.5, n * 0.38)))
        y = np.arange(n)
        vals = [float(v) for _, v in ordered]
        ax.barh(y, vals, color=colors, height=0.65, edgecolor="none", alpha=0.9)
        ax.set_yticks(y)
        ax.set_yticklabels([k for k, _ in ordered], fontsize=9, color=_TEXT)
        ax.set_xlabel("Events", color=_TEXT)
        ax.set_title("Severity Distribution", color=_TEXT, fontsize=11, pad=10)
        ax.invert_yaxis()
        ax.xaxis.grid(True, color=_GRID, linestyle="--", linewidth=0.5, alpha=0.6)
        ax.yaxis.grid(False)
        for bar, val in zip(ax.patches, vals):
            ax.text(bar.get_width() + max(vals) * 0.01, bar.get_y() + bar.get_height() / 2,
                    f"{val:,.0f}", va="center", ha="left", color=_TEXT, fontsize=8)
        _apply_dark_theme(fig, ax)
        fig.tight_layout()
        charts["struct_severity_dist"] = _fig_to_uri(fig)

    # Protocol distribution
    if protocols:
        top = sorted(protocols.items(), key=lambda x: -x[1])[:12]
        uri = _hbar([t[0] for t in top], [float(t[1]) for t in top],
                    "Protocol Distribution", "Events")
        if uri:
            charts["struct_protocols"] = uri

    # Action counts (DROP / ACCEPT / ALERT etc.)
    if actions:
        top = sorted(actions.items(), key=lambda x: -x[1])[:12]
        _ACT_COLORS = {"DROP": "#ef4444", "REJECT": "#f97316", "BLOCK": "#f97316",
                       "DRP": "#ef4444", "ACCEPT": "#34d399", "ALLOW": "#34d399",
                       "ALERT": "#fbbf24"}
        colors = [_ACT_COLORS.get(a, _ACCENT) for a, _ in top]
        n = len(top)
        fig, ax = plt.subplots(figsize=(7, max(2.0, n * 0.38)))
        y = np.arange(n)
        vals = [float(v) for _, v in top]
        ax.barh(y, vals, color=colors, height=0.65, edgecolor="none", alpha=0.9)
        ax.set_yticks(y)
        ax.set_yticklabels([a for a, _ in top], fontsize=9, color=_TEXT)
        ax.set_xlabel("Count", color=_TEXT)
        ax.set_title("Firewall / Action Counts", color=_TEXT, fontsize=11, pad=10)
        ax.invert_yaxis()
        ax.xaxis.grid(True, color=_GRID, linestyle="--", linewidth=0.5, alpha=0.6)
        ax.yaxis.grid(False)
        for bar, val in zip(ax.patches, vals):
            ax.text(bar.get_width() + max(vals) * 0.01, bar.get_y() + bar.get_height() / 2,
                    f"{val:,.0f}", va="center", ha="left", color=_TEXT, fontsize=8)
        _apply_dark_theme(fig, ax)
        fig.tight_layout()
        charts["struct_actions"] = _fig_to_uri(fig)

    # Top destination ports
    if dst_ports:
        top = sorted(dst_ports.items(), key=lambda x: -x[1])[:15]
        # Map well-known ports to service names
        _PORT_NAMES = {22: "SSH(22)", 23: "Telnet(23)", 25: "SMTP(25)", 53: "DNS(53)",
                       80: "HTTP(80)", 110: "POP3(110)", 143: "IMAP(143)", 443: "HTTPS(443)",
                       445: "SMB(445)", 3306: "MySQL(3306)", 3389: "RDP(3389)",
                       5432: "Postgres(5432)", 6379: "Redis(6379)", 8080: "HTTP-alt(8080)"}
        labels = [_PORT_NAMES.get(p, str(p)) for p, _ in top]
        uri = _hbar(labels, [float(v) for _, v in top], "Top Destination Ports", "Events")
        if uri:
            charts["struct_dst_ports"] = uri

    # HTTP status code distribution
    if status_codes:
        grouped: Dict[str, int] = {}
        for sc, cnt in status_codes.items():
            grp = f"{sc // 100}xx"
            grouped[grp] = grouped.get(grp, 0) + cnt
        top = sorted(grouped.items(), key=lambda x: x[0])
        _SC_COLORS = {"1xx": "#60a5fa", "2xx": "#34d399", "3xx": "#fbbf24",
                      "4xx": "#f97316", "5xx": "#ef4444"}
        colors = [_SC_COLORS.get(g, _ACCENT) for g, _ in top]
        n = len(top)
        fig, ax = plt.subplots(figsize=(6, max(2.0, n * 0.42)))
        y = np.arange(n)
        vals = [float(v) for _, v in top]
        ax.barh(y, vals, color=colors, height=0.65, edgecolor="none", alpha=0.9)
        ax.set_yticks(y)
        ax.set_yticklabels([g for g, _ in top], fontsize=9, color=_TEXT)
        ax.set_xlabel("Count", color=_TEXT)
        ax.set_title("HTTP Status Codes", color=_TEXT, fontsize=11, pad=10)
        ax.invert_yaxis()
        ax.xaxis.grid(True, color=_GRID, linestyle="--", linewidth=0.5, alpha=0.6)
        ax.yaxis.grid(False)
        for bar, val in zip(ax.patches, vals):
            ax.text(bar.get_width() + max(vals) * 0.01, bar.get_y() + bar.get_height() / 2,
                    f"{val:,.0f}", va="center", ha="left", color=_TEXT, fontsize=8)
        _apply_dark_theme(fig, ax)
        fig.tight_layout()
        charts["struct_http_status"] = _fig_to_uri(fig)

    # Hourly activity heatmap / bar
    if hours:
        counts = [0] * 24
        for h in hours:
            if 0 <= h < 24:
                counts[h] += 1
        fig, ax = plt.subplots(figsize=(9, 2.8))
        x = np.arange(24)
        bar_colors = [("#ef4444" if (c == max(counts) and max(counts) > 0) else _ACCENT)
                      for c in counts]
        ax.bar(x, counts, color=bar_colors, width=0.8, edgecolor="none", alpha=0.88)
        ax.set_xticks(x)
        ax.set_xticklabels([f"{h:02d}h" for h in range(24)], fontsize=7, rotation=45, color=_TEXT)
        ax.set_ylabel("Events", color=_TEXT)
        ax.set_title("Hourly Activity", color=_TEXT, fontsize=11, pad=10)
        _apply_dark_theme(fig, ax)
        fig.tight_layout()
        charts["struct_hourly"] = _fig_to_uri(fig)

    return charts


def generate_chart_data(
    rows: List[Dict[str, Any]] | None = None,
    findings: List[str] | None = None,
    dataset_summary: Dict[str, Any] | None = None,
    anomaly_result: Dict[str, Any] | None = None,
    statistics: Dict[str, Any] | None = None,
    model_performance: Dict[str, Any] | None = None,
    baseline_comparison: Dict[str, Any] | None = None,
    error_analysis: Dict[str, Any] | None = None,
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

    # ── Model performance charts ──────────────────────────────────────
    if model_performance:
        # Confusion matrix heatmap
        cm = model_performance.get("confusion_matrix", {})
        if cm.get("labels") and cm.get("matrix"):
            uri = _confusion_matrix_heatmap(cm["labels"], cm["matrix"],
                                            "Confusion Matrix")
            if uri:
                charts["confusion_matrix"] = uri

        # Per-class metrics bar chart
        pcm = model_performance.get("per_class_metrics", {})
        if pcm:
            classes = list(pcm.keys())[:12]
            f1_vals = [pcm[c].get("f1", 0) for c in classes]
            prec_vals = [pcm[c].get("precision", 0) for c in classes]
            rec_vals = [pcm[c].get("recall", 0) for c in classes]
            uri = _grouped_bar(
                classes,
                {"Precision": prec_vals, "Recall": rec_vals, "F1": f1_vals},
                "Per-Class Performance Metrics",
                "Score",
            )
            if uri:
                charts["per_class_metrics"] = uri

    # ── Baseline comparison charts ────────────────────────────────────
    if baseline_comparison:
        iforest = baseline_comparison.get("isolation_forest", {})
        zscore = baseline_comparison.get("zscore_baseline", {})

        if_metrics = iforest.get("metrics", {})
        zs_metrics = zscore.get("metrics", {})
        if if_metrics and zs_metrics:
            metric_names = ["Precision", "Recall", "F1", "Accuracy"]
            if_vals = [if_metrics.get(m.lower(), 0) for m in metric_names]
            zs_vals = [zs_metrics.get(m.lower(), 0) for m in metric_names]
            uri = _grouped_bar(
                metric_names,
                {"Isolation Forest": if_vals, "Z-Score Baseline": zs_vals},
                "Model vs Baseline Performance",
                "Score",
            )
            if uri:
                charts["model_vs_baseline"] = uri
        else:
            # Just compare anomaly counts
            labels = ["Isolation Forest", "Z-Score Baseline"]
            counts = [float(iforest.get("anomaly_count", 0)), float(zscore.get("anomaly_count", 0))]
            if any(c > 0 for c in counts):
                uri = _vbar(labels, counts, "Anomalies Detected: Model vs Baseline", "Count")
                if uri:
                    charts["model_vs_baseline"] = uri

    # ── Error analysis charts ─────────────────────────────────────────
    if error_analysis and error_analysis.get("has_labels"):
        fp_cats = error_analysis.get("false_positives", {}).get("by_category", {})
        fn_cats = error_analysis.get("false_negatives", {}).get("by_category", {})
        if fp_cats:
            uri = _error_bar_chart(fp_cats, "False Positives by Category", "Count", "#fbbf24")
            if uri:
                charts["fp_by_category"] = uri
        if fn_cats:
            uri = _error_bar_chart(fn_cats, "False Negatives by Category", "Count", "#ff6b6b")
            if uri:
                charts["fn_by_category"] = uri

    return charts
