#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""
Generate a multi-page offline HTML site from Slips alerts.json (+ flows.sqlite).

Hierarchy:
  index (IPs) -> IP pages (evidences) -> evidence pages (related flows)

Usage:
  python3 modules/anomaly_detection_https/analyze_alerts_json.py \
    --alerts /path/to/alerts.json \
    --flows /path/to/flows.sqlite \
    --out-dir /path/to/alerts_site
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sqlite3
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any, Dict, List

THREAT_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "unknown": 0,
}

FLOW_KEYS = (
    "ts",
    "starttime",
    "dur",
    "proto",
    "appproto",
    "saddr",
    "sport",
    "daddr",
    "dport",
    "state",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "server_name",
    "sni",
    "subject",
    "issuer",
    "ja3",
    "ja3s",
)

FLOW_LABELS = {
    "ts": "Timestamp",
    "starttime": "Start time",
    "dur": "Duration (s)",
    "proto": "L4 protocol",
    "appproto": "App protocol",
    "saddr": "Source IP",
    "sport": "Source port",
    "daddr": "Destination IP",
    "dport": "Destination port",
    "state": "State",
    "spkts": "Source packets",
    "dpkts": "Destination packets",
    "sbytes": "Source bytes",
    "dbytes": "Destination bytes",
    "server_name": "Server name",
    "sni": "SNI",
    "subject": "Certificate subject",
    "issuer": "Certificate issuer",
    "ja3": "JA3",
    "ja3s": "JA3S",
    "trans_id": "DNS transaction ID",
    "query": "DNS query",
    "qclass": "DNS qclass",
    "qclass_name": "DNS qclass name",
    "qtype": "DNS qtype",
    "qtype_name": "DNS qtype name",
    "AA": "DNS AA flag",
    "TC": "DNS TC flag",
    "RD": "DNS RD flag",
    "RA": "DNS RA flag",
    "Z": "DNS Z flag",
    "rejected": "DNS rejected",
    "answers": "DNS answers",
    "TTLs": "DNS TTLs",
    "rcode": "DNS rcode",
    "rcode_name": "DNS rcode name",
    "rtt": "DNS RTT",
    "version": "TLS version",
    "cipher": "TLS cipher",
    "resumed": "TLS resumed",
    "established": "TLS established",
    "cert_chain_fps": "Certificate chain fingerprints",
    "client": "TLS client metadata",
    "server": "TLS server metadata",
}

EVIDENCE_FLOW_COLUMNS = [
    "starttime",
    "ts",
    "appproto",
    "proto",
    "saddr",
    "sport",
    "daddr",
    "dport",
    "dur",
    "state",
    "sbytes",
    "dbytes",
    "spkts",
    "dpkts",
    "server_name",
    "sni",
    "query",
    "qtype_name",
    "rcode_name",
    "ja3",
    "ja3s",
    "subject",
    "issuer",
]

COMMON_COLUMN_ORDER = [
    "starttime",
    "ts",
    "appproto",
    "proto",
    "saddr",
    "sport",
    "daddr",
    "dport",
    "dur",
    "state",
    "sbytes",
    "dbytes",
    "spkts",
    "dpkts",
]


@dataclass
class EvidenceRecord:
    idx: int
    event_id: str
    start_time: str
    create_time: str
    src_ip: str
    dst_ip: str
    severity: str
    confidence: float
    description: str
    uids: List[str]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate offline report from alerts.json + flows.sqlite")
    parser.add_argument("--alerts", required=True, help="Path to alerts.json (JSON lines).")
    parser.add_argument("--flows", required=True, help="Path to flows.sqlite.")
    parser.add_argument("--out-dir", required=True, help="Output folder.")
    parser.add_argument("--ip-page-size", type=int, default=600, help="Evidences per IP page.")
    parser.add_argument(
        "--max-string-len",
        type=int,
        default=96,
        help="Max string length for flow values in HTML.",
    )
    return parser.parse_args()


def parse_note_uids(note: Any) -> List[str]:
    if not note:
        return []
    payload = None
    if isinstance(note, dict):
        payload = note
    elif isinstance(note, str):
        try:
            payload = json.loads(note)
        except json.JSONDecodeError:
            return []
    if not isinstance(payload, dict):
        return []
    uids = payload.get("uids", [])
    if not isinstance(uids, list):
        return []
    return [str(u) for u in uids if isinstance(u, str) and u]


def first_ip(field: Any) -> str:
    if isinstance(field, list) and field and isinstance(field[0], dict):
        val = field[0].get("IP")
        if isinstance(val, str):
            return val
    return "unknown"


def parse_alerts(alerts_path: Path) -> List[EvidenceRecord]:
    records: List[EvidenceRecord] = []
    with alerts_path.open("r", encoding="utf-8", errors="replace") as handle:
        for i, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            severity = str(obj.get("Severity", "unknown")).lower()
            if severity not in THREAT_RANK:
                severity = "unknown"

            try:
                confidence = float(obj.get("Confidence", 0.0))
            except (TypeError, ValueError):
                confidence = 0.0
            confidence = max(0.0, min(1.0, confidence))

            records.append(
                EvidenceRecord(
                    idx=i,
                    event_id=str(obj.get("ID", f"event_{i}")),
                    start_time=str(obj.get("StartTime", "")),
                    create_time=str(obj.get("CreateTime", "")),
                    src_ip=first_ip(obj.get("Source")),
                    dst_ip=first_ip(obj.get("Target")),
                    severity=severity,
                    confidence=confidence,
                    description=str(obj.get("Description", "")),
                    uids=parse_note_uids(obj.get("Note")),
                )
            )
    return records


def sort_records(records: List[EvidenceRecord]) -> List[EvidenceRecord]:
    return sorted(
        records,
        key=lambda r: (-THREAT_RANK.get(r.severity, 0), -r.confidence, r.start_time, r.event_id),
    )


def chunked(items: List[str], size: int = 1000) -> List[List[str]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def trim_value(value: Any, max_string_len: int) -> Any:
    if isinstance(value, str):
        if len(value) <= max_string_len:
            return value
        return value[:max_string_len] + "..."
    if isinstance(value, list):
        if len(value) > 10:
            return [trim_value(v, max_string_len) for v in value[:10]] + [f"... ({len(value)} total)"]
        return [trim_value(v, max_string_len) for v in value]
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        for k, v in value.items():
            out[k] = trim_value(v, max_string_len)
        return out
    return value


def compact_flow(flow_obj: Dict[str, Any], max_string_len: int) -> Dict[str, Any]:
    # Keep all decoded keys so protocol-specific fields (e.g. DNS query) are not lost.
    return trim_value(flow_obj, max_string_len)


def fetch_flow_data(sqlite_path: Path, uids: List[str], max_string_len: int) -> Dict[str, List[Dict[str, Any]]]:
    by_uid: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    if not uids:
        return by_uid

    con = sqlite3.connect(str(sqlite_path))
    cur = con.cursor()
    try:
        for part in chunked(sorted(set(uids))):
            placeholders = ",".join("?" for _ in part)
            cur.execute(
                f"SELECT uid, flow, profileid, twid, '' AS flow_type FROM flows WHERE uid IN ({placeholders})",
                part,
            )
            for uid, flow_raw, profileid, twid, flow_type in cur.fetchall():
                try:
                    flow_obj = json.loads(flow_raw)
                except json.JSONDecodeError:
                    flow_obj = {"raw": str(flow_raw)}
                by_uid[str(uid)].append(
                    {
                        "table": "flows",
                        "flow_type": flow_type,
                        "profileid": profileid,
                        "twid": twid,
                        "flow": compact_flow(flow_obj, max_string_len),
                    }
                )

            cur.execute(
                f"SELECT uid, flow, profileid, twid, flow_type FROM altflows WHERE uid IN ({placeholders})",
                part,
            )
            for uid, flow_raw, profileid, twid, flow_type in cur.fetchall():
                try:
                    flow_obj = json.loads(flow_raw)
                except json.JSONDecodeError:
                    flow_obj = {"raw": str(flow_raw)}
                by_uid[str(uid)].append(
                    {
                        "table": "altflows",
                        "flow_type": flow_type,
                        "profileid": profileid,
                        "twid": twid,
                        "flow": compact_flow(flow_obj, max_string_len),
                    }
                )
    finally:
        con.close()
    return by_uid


def ip_slug(ip: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", ip)


def evidence_slug(rec: EvidenceRecord) -> str:
    safe_id = re.sub(r"[^a-zA-Z0-9_-]", "_", rec.event_id)[:40]
    return f"ev_{rec.idx:07d}_{safe_id}"


def write_text(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def header(title: str, rel_root: str) -> str:
    return (
        "<!doctype html><html lang='en'><head>"
        "<meta charset='utf-8' /><meta name='viewport' content='width=device-width, initial-scale=1' />"
        f"<title>{escape(title)}</title>"
        f"<link rel='stylesheet' href='{escape(rel_root)}assets/style.css' />"
        "</head><body>"
    )


def footer() -> str:
    return "</body></html>"


def write_assets(out_dir: Path):
    css = """
body { font-family: Arial, sans-serif; margin: 20px; color: #111827; background: #f8fafc; }
h1, h2, h3 { margin: 0 0 10px 0; }
.card { background: #fff; border: 1px solid #e5e7eb; border-radius: 10px; padding: 12px; margin-bottom: 14px; }
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th, td { border: 1px solid #e5e7eb; padding: 6px; text-align: left; vertical-align: top; }
th { background: #f3f4f6; }
a { color: #1d4ed8; text-decoration: none; }
a:hover { text-decoration: underline; }
.small { color: #6b7280; font-size: 12px; }
pre { margin: 0; white-space: pre-wrap; word-break: break-word; max-height: 320px; overflow: auto; }
.badge { border-radius: 6px; padding: 2px 6px; font-size: 12px; display: inline-block; }
.badge.critical { background: #fee2e2; color: #991b1b; }
.badge.high { background: #ffedd5; color: #9a3412; }
.badge.medium { background: #fef9c3; color: #854d0e; }
.badge.low { background: #dcfce7; color: #166534; }
.badge.info, .badge.unknown { background: #e5e7eb; color: #374151; }
""".strip()
    write_text(out_dir / "assets" / "style.css", css)


def threat_badge(level: str) -> str:
    lvl = level if level in THREAT_RANK else "unknown"
    return f"<span class='badge {escape(lvl)}'>{escape(lvl)}</span>"


def render_cell_value(value: Any) -> str:
    if value in (None, "", [], {}):
        return ""
    return escape(str(value))


def infer_group_type(item: Dict[str, Any]) -> str:
    flow_type = str(item.get("flow_type", "") or "").strip()
    if flow_type:
        return flow_type
    appproto = str(item.get("flow", {}).get("appproto", "") or "").strip()
    if appproto:
        return appproto
    return "generic"


def ordered_columns_for_records(records: List[Dict[str, Any]]) -> List[str]:
    keys = set()
    for rec in records:
        flow = rec.get("flow", {})
        if isinstance(flow, dict):
            keys.update(flow.keys())

    ordered: List[str] = []
    for key in COMMON_COLUMN_ORDER:
        if key in keys:
            ordered.append(key)
            keys.remove(key)

    for key in EVIDENCE_FLOW_COLUMNS:
        if key in keys:
            ordered.append(key)
            keys.remove(key)

    ordered.extend(sorted(keys))
    return ordered


def build_index_page(
    out_dir: Path,
    alerts_path: Path,
    sqlite_path: Path,
    records: List[EvidenceRecord],
    records_by_ip: Dict[str, List[EvidenceRecord]],
    ip_page_size: int,
):
    threat_counts = Counter(r.severity for r in records)
    avg_conf = sum(r.confidence for r in records) / max(1, len(records))
    now = datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")

    rows = []
    for ip, ip_records in sorted(records_by_ip.items(), key=lambda kv: len(kv[1]), reverse=True):
        ctr = Counter(r.severity for r in ip_records)
        ip_avg = sum(r.confidence for r in ip_records) / max(1, len(ip_records))
        page_count = max(1, math.ceil(len(ip_records) / ip_page_size))
        pages = " ".join(
            f"<a href='ip/{escape(ip_slug(ip))}_p{p}.html'>p{p}</a>" for p in range(1, page_count + 1)
        )
        rows.append(
            "<tr>"
            f"<td>{escape(ip)}</td>"
            f"<td>{len(ip_records)}</td>"
            f"<td>{ip_avg:.3f}</td>"
            f"<td>critical={ctr.get('critical',0)}, high={ctr.get('high',0)}, medium={ctr.get('medium',0)}, low={ctr.get('low',0)}, info={ctr.get('info',0)}</td>"
            f"<td>{pages}</td>"
            "</tr>"
        )

    html = (
        header("Alerts Analysis - Index", "")
        + "<div class='card'><h1>Alerts Analysis (Index)</h1>"
        + f"<p class='small'>Generated (wall-time): {escape(now)}</p>"
        + f"<p class='small'>alerts: <code>{escape(str(alerts_path))}</code></p>"
        + f"<p class='small'>flows sqlite: <code>{escape(str(sqlite_path))}</code></p>"
        + f"<p><b>Total evidences:</b> {len(records)} | <b>Average confidence:</b> {avg_conf:.3f}</p>"
        + f"<p><b>Threat counts:</b> {escape(str(dict(threat_counts)))}</p></div>"
        + "<div class='card'><h2>By Source IP</h2>"
        + "<table><thead><tr><th>Source IP</th><th>Total evidences</th><th>Avg confidence</th><th>Threat summary</th><th>Pages</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table></div>"
        + footer()
    )
    write_text(out_dir / "index.html", html)


def paginate(items: List[EvidenceRecord], size: int) -> List[List[EvidenceRecord]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def build_ip_pages(out_dir: Path, records_by_ip: Dict[str, List[EvidenceRecord]], ip_page_size: int):
    for ip, ip_records in records_by_ip.items():
        ip_pages = paginate(ip_records, ip_page_size)
        slug = ip_slug(ip)
        for page_num, page_records in enumerate(ip_pages, start=1):
            nav = []
            for p in range(1, len(ip_pages) + 1):
                if p == page_num:
                    nav.append(f"<b>p{p}</b>")
                else:
                    nav.append(f"<a href='{escape(slug)}_p{p}.html'>p{p}</a>")
            nav_html = " | ".join(nav)

            rows = []
            for idx, rec in enumerate(page_records, start=1):
                ev = evidence_slug(rec)
                rows.append(
                    "<tr>"
                    f"<td>{idx}</td>"
                    f"<td><a href='../evidence/{escape(ev)}.html'>{escape(rec.event_id)}</a></td>"
                    f"<td>{threat_badge(rec.severity)}</td>"
                    f"<td>{rec.confidence:.3f}</td>"
                    f"<td>{escape(rec.start_time)}</td>"
                    f"<td>{len(rec.uids)}</td>"
                    f"<td>{escape(rec.description)}</td>"
                    "</tr>"
                )

            html = (
                header(f"Alerts by IP - {ip} (p{page_num})", "../")
                + "<div class='card'>"
                + f"<h1>Source IP: {escape(ip)}</h1>"
                + "<p><a href='../index.html'>← Back to index</a></p>"
                + f"<p><b>Pages:</b> {nav_html}</p></div>"
                + "<div class='card'><h2>Evidences (sorted by threat, confidence)</h2>"
                + "<table><thead><tr><th>#</th><th>Evidence ID</th><th>Threat</th><th>Confidence</th><th>StartTime</th><th>UIDs</th><th>Description</th></tr></thead><tbody>"
                + "".join(rows)
                + "</tbody></table></div>"
                + footer()
            )
            write_text(out_dir / "ip" / f"{slug}_p{page_num}.html", html)


def build_evidence_pages(
    out_dir: Path,
    records: List[EvidenceRecord],
    flows_by_uid: Dict[str, List[Dict[str, Any]]],
    ip_page_size: int,
    records_by_ip: Dict[str, List[EvidenceRecord]],
):
    ip_page_map: Dict[int, int] = {}
    for ip, ip_records in records_by_ip.items():
        for i, rec in enumerate(ip_records):
            ip_page_map[rec.idx] = (i // ip_page_size) + 1

    for rec in records:
        flow_sections: List[str] = []
        for uid in rec.uids:
            flow_records = flows_by_uid.get(uid, [])
            if not flow_records:
                flow_sections.append(
                    "<div class='card'>"
                    f"<h3>UID: {escape(uid)}</h3>"
                    "<p>No related flow found in sqlite.</p>"
                    "</div>"
                )
                continue
            grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
            for item in flow_records:
                group_key = f"{item.get('table', '')}:{infer_group_type(item)}"
                grouped[group_key].append(item)

            uid_blocks: List[str] = [f"<h3>UID: {escape(uid)}</h3>"]
            for group_key, group_items in sorted(grouped.items()):
                table_name, flow_kind = group_key.split(":", 1)
                cols = ordered_columns_for_records(group_items)
                header_cols = (
                    "<th>Profile</th><th>Timewindow</th>"
                    + "".join(f"<th>{escape(FLOW_LABELS.get(c, c))}</th>" for c in cols)
                )
                rows = []
                for item in group_items:
                    flow_obj = item.get("flow", {})
                    rows.append(
                        "<tr>"
                        f"<td>{escape(str(item.get('profileid', '')))}</td>"
                        f"<td>{escape(str(item.get('twid', '')))}</td>"
                        + "".join(f"<td>{render_cell_value(flow_obj.get(c))}</td>" for c in cols)
                        + "</tr>"
                    )

                uid_blocks.append(
                    "<div class='card'>"
                    f"<h4>Table: {escape(str(table_name))} | Type: {escape(str(flow_kind))}</h4>"
                    + "<table><thead><tr>"
                    + header_cols
                    + "</tr></thead><tbody>"
                    + "".join(rows)
                    + "</tbody></table></div>"
                )

            flow_sections.append("<div class='card'>" + "".join(uid_blocks) + "</div>")

        if not flow_sections:
            flow_sections.append("<p>No UIDs in this evidence.</p>")

        ip_page = ip_page_map.get(rec.idx, 1)
        back_link = f"../ip/{ip_slug(rec.src_ip)}_p{ip_page}.html"

        html = (
            header(f"Evidence {rec.event_id}", "../")
            + "<div class='card'>"
            + f"<h1>Evidence: {escape(rec.event_id)}</h1>"
            + f"<p><a href='{escape(back_link)}'>← Back to IP {escape(rec.src_ip)}</a> | <a href='../index.html'>Index</a></p>"
            + f"<p><b>Threat:</b> {escape(rec.severity)} | <b>Confidence:</b> {rec.confidence:.3f}</p>"
            + f"<p><b>StartTime:</b> {escape(rec.start_time)} | <b>CreateTime:</b> {escape(rec.create_time)}</p>"
            + f"<p><b>Source:</b> {escape(rec.src_ip)} | <b>Target:</b> {escape(rec.dst_ip)}</p>"
            + f"<p><b>Description:</b> {escape(rec.description)}</p>"
            + "</div>"
            + "<div class='card'><h2>Related flows by UID</h2>"
            + "".join(flow_sections)
            + "</div>"
            + footer()
        )
        write_text(out_dir / "evidence" / f"{evidence_slug(rec)}.html", html)


def main():
    args = parse_args()
    alerts_path = Path(args.alerts)
    sqlite_path = Path(args.flows)
    out_dir = Path(args.out_dir)

    if not alerts_path.exists():
        raise FileNotFoundError(f"alerts file not found: {alerts_path}")
    if not sqlite_path.exists():
        raise FileNotFoundError(f"flows sqlite not found: {sqlite_path}")

    records = sort_records(parse_alerts(alerts_path))
    records_by_ip: Dict[str, List[EvidenceRecord]] = defaultdict(list)
    all_uids: List[str] = []
    for rec in records:
        records_by_ip[rec.src_ip].append(rec)
        all_uids.extend(rec.uids)

    flows_by_uid = fetch_flow_data(sqlite_path, all_uids, max_string_len=max(16, args.max_string_len))

    page_size = max(1, args.ip_page_size)
    write_assets(out_dir)
    build_index_page(out_dir, alerts_path, sqlite_path, records, records_by_ip, page_size)
    build_ip_pages(out_dir, records_by_ip, page_size)
    build_evidence_pages(out_dir, records, flows_by_uid, page_size, records_by_ip)

    print(f"Site written to: {out_dir}")
    print(f"Open: {out_dir / 'index.html'}")


if __name__ == "__main__":
    main()
