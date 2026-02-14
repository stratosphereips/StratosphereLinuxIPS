#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""
Create a local HTML report from anomaly_detection_https.log.

Usage:
  python3 modules/anomaly_detection_https/analyze_ad_log.py \
    --log output/.../anomaly_detection_https.log \
    --out output/.../anomaly_detection_https_report.html
"""

from __future__ import annotations

import argparse
import json
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any, Dict, List, Optional


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
LOG_RE = re.compile(
    r"^(?P<wall>\S+)\s+traffic_ts=(?P<traffic>\S+)\s+.*?\[(?P<event>[^\]]+)\]\s+"
    r"(?P<msg>.*?)\s+metrics=(?P<metrics>\{.*\})$"
)


@dataclass
class Event:
    wall_iso: str
    traffic_ts: Optional[float]
    event_type: str
    message: str
    metrics: Dict[str, Any]
    event_ts: float


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate HTML visual analysis for HTTPS AD operational log."
    )
    parser.add_argument(
        "--log",
        required=True,
        help="Path to anomaly_detection_https.log",
    )
    parser.add_argument(
        "--out",
        default="anomaly_detection_https_report.html",
        help="Output HTML path",
    )
    return parser.parse_args()


def parse_iso_to_ts(iso_str: str) -> float:
    return datetime.fromisoformat(iso_str.replace("Z", "+00:00")).timestamp()


def parse_log(log_path: Path) -> List[Event]:
    events: List[Event] = []
    with log_path.open("r", encoding="utf-8", errors="replace") as f:
        for line_no, raw_line in enumerate(f, start=1):
            line = ANSI_RE.sub("", raw_line.strip())
            if not line:
                continue
            m = LOG_RE.match(line)
            if not m:
                continue
            wall_iso = m.group("wall")
            traffic_raw = m.group("traffic")
            event_type = m.group("event")
            message = m.group("msg")
            try:
                metrics = json.loads(m.group("metrics"))
            except json.JSONDecodeError:
                metrics = {"parse_error": True}

            traffic_ts: Optional[float]
            if traffic_raw == "n/a":
                traffic_ts = None
            else:
                try:
                    traffic_ts = float(traffic_raw.replace("Z", ""))
                except ValueError:
                    traffic_ts = None

            try:
                wall_ts = parse_iso_to_ts(wall_iso)
            except Exception:
                wall_ts = float(line_no)

            event_ts = traffic_ts if traffic_ts is not None else wall_ts
            events.append(
                Event(
                    wall_iso=wall_iso,
                    traffic_ts=traffic_ts,
                    event_type=event_type,
                    message=message,
                    metrics=metrics,
                    event_ts=event_ts,
                )
            )
    return sorted(events, key=lambda e: e.event_ts)


def to_human_ts(ts: float) -> str:
    return (
        datetime.fromtimestamp(ts, tz=timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def bin_events(events: List[Event], n_bins: int = 40) -> Dict[str, Any]:
    if not events:
        return {"bins": [], "series": {}}
    min_ts = events[0].event_ts
    max_ts = events[-1].event_ts
    if max_ts <= min_ts:
        max_ts = min_ts + 1
    n_bins = max(8, min(n_bins, 120))
    width = (max_ts - min_ts) / n_bins
    if width <= 0:
        width = 1.0

    labels = []
    for i in range(n_bins):
        center = min_ts + (i + 0.5) * width
        labels.append(to_human_ts(center))

    series: Dict[str, List[int]] = defaultdict(lambda: [0] * n_bins)
    for e in events:
        idx = int((e.event_ts - min_ts) / width)
        idx = max(0, min(idx, n_bins - 1))
        series["all_events"][idx] += 1
        series[e.event_type][idx] += 1
        if e.event_type in ("flow_detection", "hourly_detection"):
            conf = str(e.metrics.get("confidence", "unknown"))
            series[f"detection_{conf}"][idx] += 1
            series["detections_total"][idx] += 1
    return {"bins": labels, "series": dict(series)}


def svg_polyline_chart(
    title: str,
    x_labels: List[str],
    series_map: Dict[str, List[int]],
    colors: Dict[str, str],
    width: int = 1100,
    height: int = 320,
) -> str:
    if not x_labels:
        return f"<h3>{escape(title)}</h3><p>No data.</p>"

    margin_left = 60
    margin_right = 20
    margin_top = 30
    margin_bottom = 70
    plot_w = width - margin_left - margin_right
    plot_h = height - margin_top - margin_bottom

    max_y = 1
    for vals in series_map.values():
        max_y = max(max_y, max(vals) if vals else 0)
    y_top = int(math.ceil(max_y * 1.1))
    if y_top < 1:
        y_top = 1

    def x_at(i: int) -> float:
        if len(x_labels) == 1:
            return margin_left + plot_w / 2
        return margin_left + (i / (len(x_labels) - 1)) * plot_w

    def y_at(v: float) -> float:
        return margin_top + plot_h - (v / y_top) * plot_h

    lines = []
    # grid and axes
    for k in range(6):
        yv = y_top * (k / 5.0)
        yy = y_at(yv)
        lines.append(
            f'<line x1="{margin_left}" y1="{yy:.1f}" x2="{margin_left+plot_w}" '
            f'y2="{yy:.1f}" stroke="#e5e7eb" stroke-width="1" />'
        )
        lines.append(
            f'<text x="{margin_left-8}" y="{yy+4:.1f}" text-anchor="end" '
            f'font-size="11" fill="#6b7280">{int(yv)}</text>'
        )
    lines.append(
        f'<line x1="{margin_left}" y1="{margin_top+plot_h}" x2="{margin_left+plot_w}" '
        f'y2="{margin_top+plot_h}" stroke="#374151" stroke-width="1.2" />'
    )
    lines.append(
        f'<line x1="{margin_left}" y1="{margin_top}" x2="{margin_left}" '
        f'y2="{margin_top+plot_h}" stroke="#374151" stroke-width="1.2" />'
    )

    # x labels (sampled)
    ticks = min(8, len(x_labels))
    for k in range(ticks):
        idx = int(k * (len(x_labels) - 1) / max(1, ticks - 1))
        xx = x_at(idx)
        lbl = x_labels[idx][11:16] if "T" in x_labels[idx] else x_labels[idx]
        lines.append(
            f'<line x1="{xx:.1f}" y1="{margin_top+plot_h}" x2="{xx:.1f}" '
            f'y2="{margin_top+plot_h+5}" stroke="#374151" stroke-width="1" />'
        )
        lines.append(
            f'<text x="{xx:.1f}" y="{margin_top+plot_h+20}" text-anchor="middle" '
            f'font-size="11" fill="#6b7280">{escape(lbl)}</text>'
        )

    # Hover bands: moving the mouse over the plot shows values for the
    # nearest time-bin (all plotted series).
    for idx in range(len(x_labels)):
        if len(x_labels) == 1:
            left = margin_left
            right = margin_left + plot_w
        elif idx == 0:
            left = margin_left
            right = (x_at(idx) + x_at(idx + 1)) / 2.0
        elif idx == len(x_labels) - 1:
            left = (x_at(idx - 1) + x_at(idx)) / 2.0
            right = margin_left + plot_w
        else:
            left = (x_at(idx - 1) + x_at(idx)) / 2.0
            right = (x_at(idx) + x_at(idx + 1)) / 2.0

        tooltip_lines = [f"time={x_labels[idx]}"]
        for name, vals in series_map.items():
            value = vals[idx] if idx < len(vals) else 0
            tooltip_lines.append(f"{name}={value}")
        tooltip = "\n".join(tooltip_lines)

        lines.append(
            f'<rect x="{left:.1f}" y="{margin_top:.1f}" '
            f'width="{max(0.5, right-left):.1f}" height="{plot_h:.1f}" '
            f'fill="#000000" fill-opacity="0" stroke="none">'
            f"<title>{escape(tooltip)}</title>"
            f"</rect>"
        )

    # series polylines + hoverable points
    legend_y = 14
    legend_x = margin_left
    for i, (name, vals) in enumerate(series_map.items()):
        pts = " ".join(f"{x_at(j):.1f},{y_at(v):.1f}" for j, v in enumerate(vals))
        color = colors.get(name, "#2563eb")
        lines.append(
            f'<polyline points="{pts}" fill="none" stroke="{color}" '
            f'stroke-width="2" stroke-linejoin="round" stroke-linecap="round" />'
        )
        lx = legend_x + i * 220
        lines.append(
            f'<rect x="{lx}" y="{legend_y-9}" width="14" height="4" fill="{color}" />'
        )
        lines.append(
            f'<text x="{lx+20}" y="{legend_y-5}" font-size="12" fill="#374151">{escape(name)}</text>'
        )
        # Add point markers so hovering shows exact bin/value.
        for j, v in enumerate(vals):
            xx = x_at(j)
            yy = y_at(v)
            ts_label = x_labels[j]
            lines.append(
                f'<circle cx="{xx:.1f}" cy="{yy:.1f}" r="3.2" '
                f'fill="{color}" fill-opacity="0.35" stroke="{color}" stroke-width="1">'
                f"<title>{escape(name)} | time={escape(ts_label)} | value={int(v)}</title>"
                f"</circle>"
            )

    svg = (
        f'<h3>{escape(title)}</h3>'
        f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" '
        f'xmlns="http://www.w3.org/2000/svg" role="img">'
        + "".join(lines)
        + "</svg>"
    )
    return svg


def summarize(events: List[Event]) -> Dict[str, Any]:
    summary: Dict[str, Any] = {}
    summary["total_events"] = len(events)
    event_counts = Counter(e.event_type for e in events)
    summary["event_counts"] = event_counts

    detections = [
        e
        for e in events
        if e.event_type in ("flow_detection", "hourly_detection")
    ]
    summary["detections"] = len(detections)
    summary["confidence_counts"] = Counter(
        str(e.metrics.get("confidence", "unknown")) for e in detections
    )

    profile_counts = Counter(
        e.metrics.get("profileid")
        for e in detections
        if e.metrics.get("profileid")
    )
    summary["top_profiles"] = profile_counts.most_common(10)

    reason_counts = Counter()
    hourly_scores = []
    for e in detections:
        if e.event_type == "flow_detection":
            for r in e.metrics.get("flow_anomalies", []):
                reason_counts[str(r.get("feature", "unknown"))] += 1
        else:
            for r in e.metrics.get("anomalies", []):
                reason_counts[str(r.get("feature", "unknown"))] += 1
            if "anomaly_score" in e.metrics:
                try:
                    hourly_scores.append(float(e.metrics["anomaly_score"]))
                except Exception:
                    pass
    summary["top_reasons"] = reason_counts.most_common(12)
    summary["max_hourly_score"] = max(hourly_scores) if hourly_scores else 0.0
    summary["avg_hourly_score"] = (
        sum(hourly_scores) / len(hourly_scores) if hourly_scores else 0.0
    )

    if events:
        summary["start"] = to_human_ts(events[0].event_ts)
        summary["end"] = to_human_ts(events[-1].event_ts)
    else:
        summary["start"] = "n/a"
        summary["end"] = "n/a"
    return summary


def narrative(summary: Dict[str, Any]) -> List[str]:
    bullets = []
    bullets.append(
        f"Observed {summary['total_events']} module events from {summary['start']} to {summary['end']}."
    )
    bullets.append(
        f"Detected {summary['detections']} anomalies "
        f"(confidence: {dict(summary['confidence_counts'])})."
    )
    if summary["top_profiles"]:
        p, n = summary["top_profiles"][0]
        bullets.append(
            f"Most affected host profile was {p} with {n} detections."
        )
    if summary["top_reasons"]:
        r, n = summary["top_reasons"][0]
        bullets.append(f"Most frequent anomaly reason was '{r}' ({n} times).")
    bullets.append(
        "Interpretation: spikes in detection lines indicate behavior shifts "
        "from learned baseline; confidence rises when deviation is strong, persistent, "
        "and backed by stable baseline history."
    )
    return bullets


def table_rows(rows: List[tuple]) -> str:
    if not rows:
        return "<tr><td colspan='2'>No data</td></tr>"
    return "".join(
        f"<tr><td>{escape(str(k))}</td><td>{escape(str(v))}</td></tr>"
        for k, v in rows
    )


def build_html(
    log_path: Path,
    summary: Dict[str, Any],
    bins: Dict[str, Any],
    events: List[Event],
) -> str:
    labels = bins["bins"]
    series = bins["series"]

    chart_events = svg_polyline_chart(
        "Event Volume Over Time (traffic time)",
        labels,
        {
            "all_events": series.get("all_events", [0] * len(labels)),
            "flow_arrival": series.get("flow_arrival", [0] * len(labels)),
        },
        colors={"all_events": "#2563eb", "flow_arrival": "#0ea5e9"},
    )
    chart_detections = svg_polyline_chart(
        "Detections Over Time (by confidence)",
        labels,
        {
            "detections_total": series.get("detections_total", [0] * len(labels)),
            "detection_high": series.get("detection_high", [0] * len(labels)),
            "detection_medium": series.get("detection_medium", [0] * len(labels)),
            "detection_low": series.get("detection_low", [0] * len(labels)),
        },
        colors={
            "detections_total": "#dc2626",
            "detection_high": "#b91c1c",
            "detection_medium": "#d97706",
            "detection_low": "#f59e0b",
        },
    )
    chart_hourly = svg_polyline_chart(
        "Hourly Detection Events Over Time",
        labels,
        {
            "hourly_detection": series.get("hourly_detection", [0] * len(labels)),
            "flow_detection": series.get("flow_detection", [0] * len(labels)),
        },
        colors={"hourly_detection": "#7c3aed", "flow_detection": "#ef4444"},
    )

    top_events = summary["event_counts"].most_common(15)
    recent = events[-20:]
    recent_rows = []
    for e in recent:
        recent_rows.append(
            (
                f"{to_human_ts(e.event_ts)} [{e.event_type}]",
                f"{e.message} | metrics={json.dumps(e.metrics)}",
            )
        )

    bullets = narrative(summary)
    bullets_html = "".join(f"<li>{escape(b)}</li>" for b in bullets)

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>HTTPS AD Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 20px; color: #111827; background: #f8fafc; }}
    h1, h2, h3 {{ margin: 0 0 10px 0; }}
    .card {{ background: #fff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 16px; margin-bottom: 16px; }}
    .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
    th, td {{ border: 1px solid #e5e7eb; padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background: #f3f4f6; }}
    code {{ background: #f3f4f6; padding: 2px 4px; border-radius: 4px; }}
    .small {{ color: #6b7280; font-size: 13px; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>HTTPS AD Visual Analysis</h1>
    <p class="small">Source log: <code>{escape(str(log_path))}</code></p>
    <p class="small">Generated: {escape(to_human_ts(datetime.now(tz=timezone.utc).timestamp()))}</p>
  </div>

    <div class="card">
    <h2>What Happened</h2>
    <ul>{bullets_html}</ul>
    <p class="small">
      Confidence meaning: based on severity + persistence + baseline quality + multi-signal agreement.
      Levels are <code>low</code>, <code>medium</code>, and <code>high</code>.
    </p>
  </div>

  <div class="card">{chart_events}</div>
  <div class="card">{chart_detections}</div>
  <div class="card">{chart_hourly}</div>
  <div class="card">
    <p class="small">Tip: move your mouse anywhere inside the plot area to see exact values for that time-bin.</p>
  </div>

  <div class="grid">
    <div class="card">
      <h3>Event Counts</h3>
      <table>
        <thead><tr><th>Event type</th><th>Count</th></tr></thead>
        <tbody>{table_rows(top_events)}</tbody>
      </table>
    </div>
    <div class="card">
      <h3>Top Anomaly Reasons</h3>
      <table>
        <thead><tr><th>Reason</th><th>Count</th></tr></thead>
        <tbody>{table_rows(summary["top_reasons"])}</tbody>
      </table>
    </div>
  </div>

  <div class="grid">
    <div class="card">
      <h3>Detections by Profile</h3>
      <table>
        <thead><tr><th>Profile</th><th>Detections</th></tr></thead>
        <tbody>{table_rows(summary["top_profiles"])}</tbody>
      </table>
    </div>
    <div class="card">
      <h3>Score Summary</h3>
      <table>
        <tbody>
          <tr><td>Total detections</td><td>{summary["detections"]}</td></tr>
          <tr><td>Confidence counts</td><td>{escape(str(dict(summary["confidence_counts"])))}</td></tr>
          <tr><td>Max hourly anomaly score</td><td>{summary["max_hourly_score"]:.3f}</td></tr>
          <tr><td>Avg hourly anomaly score</td><td>{summary["avg_hourly_score"]:.3f}</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <div class="card">
    <h3>Recent Events (latest 20)</h3>
    <table>
      <thead><tr><th>Timestamp + Event</th><th>Details</th></tr></thead>
      <tbody>{table_rows(recent_rows)}</tbody>
    </table>
  </div>
</body>
</html>
"""


def main():
    args = parse_args()
    log_path = Path(args.log)
    out_path = Path(args.out)
    if not log_path.exists():
        raise FileNotFoundError(f"Log file not found: {log_path}")

    events = parse_log(log_path)
    summary = summarize(events)
    bins = bin_events(events)
    html = build_html(log_path, summary, bins, events)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")
    print(f"Report written to: {out_path}")


if __name__ == "__main__":
    main()
