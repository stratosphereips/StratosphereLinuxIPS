#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""
Generate a standalone local HTML report for a T Cell module run.

Usage:
  python3 modules/t_cell/analyze_t_cell.py \
    --run-output-dir output/<run>

By default the script writes:
  output/<run>/t_cell_report.html
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sqlite3
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any, Iterable

try:
    import yaml
except ImportError:  # pragma: no cover - optional runtime dependency
    yaml = None


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
STATE_LABELS = {
    0: "0 - mature",
    1: "1 - antigen-recognized",
    2: "2 - anergic",
    3: "3 - activated",
    4: "4 - effector",
    5: "5 - memory",
}
STATE_CLASS = {
    0: "state-mature",
    1: "state-recognized",
    2: "state-anergic",
    3: "state-activated",
    4: "state-effector",
    5: "state-memory",
}
STATE_COLORS = {
    "state-mature": "#0f766e",
    "state-recognized": "#d97706",
    "state-anergic": "#2563eb",
    "state-activated": "#a21caf",
    "state-effector": "#b91c1c",
    "state-memory": "#15803d",
}
SIGNAL_COLORS = {"PAMP": "#c2410c", "DAMP": "#0369a1"}
TRACE_STAGE_COLORS = {"co_stimulation": "#b45309", "context": "#7c3aed"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate an offline T Cell HTML report."
    )
    parser.add_argument(
        "--run-output-dir",
        required=True,
        help="Slips run output directory containing t_cell/t_cell.sqlite.",
    )
    parser.add_argument(
        "--out",
        default="",
        help="Output HTML path. Default: <run-output-dir>/t_cell_report.html",
    )
    parser.add_argument(
        "--max-observations",
        type=int,
        default=200,
        help="Maximum recent observations to render in the report.",
    )
    parser.add_argument(
        "--max-log-lines",
        type=int,
        default=400,
        help="Maximum recent module log lines to embed in the report.",
    )
    parser.add_argument(
        "--max-trace-rows",
        type=int,
        default=200,
        help="Maximum recent trace rows to render in the report.",
    )
    return parser.parse_args()


def load_json(raw_value: str, fallback):
    try:
        return json.loads(raw_value)
    except (TypeError, ValueError):
        return fallback


def parse_alerts_timestamp(raw_value: str | None) -> float | None:
    if not raw_value:
        return None
    text = str(raw_value).strip()
    if not text:
        return None

    fmts = (
        "%Y/%m/%d %H:%M:%S.%f%z",
        "%Y/%m/%d %H:%M:%S.%f",
        "%Y/%m/%d %H:%M:%S%z",
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
    )
    for fmt in fmts:
        try:
            value = datetime.strptime(text, fmt)
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            return value.timestamp()
        except ValueError:
            continue
    try:
        return float(text)
    except (TypeError, ValueError):
        return None


def ts_to_iso(ts: float | None) -> str:
    if ts is None:
        return "n/a"
    return (
        datetime.fromtimestamp(float(ts), tz=timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def state_label(state: int | None) -> str:
    return STATE_LABELS.get(state, f"unknown:{state}")


def state_class(state: int | None) -> str:
    return STATE_CLASS.get(state, "state-unknown")


def shorten(value: Any, limit: int = 96) -> str:
    text = str(value or "")
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def format_float(value: Any, digits: int = 3) -> str:
    if value is None or value == "":
        return "n/a"
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return str(value)
    if math.isfinite(numeric) and abs(numeric - round(numeric)) < 1e-9:
        return str(int(round(numeric)))
    return f"{numeric:.{digits}f}"


def load_yaml_config(metadata_path: Path) -> dict:
    if not metadata_path.exists() or yaml is None:
        return {}
    try:
        return yaml.safe_load(metadata_path.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}


def _row_to_observation(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "evidence_id": row["evidence_id"],
        "evidence_type": row["evidence_type"],
        "evidence_signal": row["evidence_signal"],
        "responsible_ip": row["profile_ip"],
        "timewindow_number": row["timewindow_number"],
        "timestamp": row["timestamp"],
        "observed_at": row["observed_at"],
        "confidence": row["confidence"],
        "threat_level": row["threat_level"],
        "threat_level_value": row["threat_level_value"],
        "interface": row["interface"],
        "uids": load_json(row["uid_json"], []),
        "antigen_count": row["antigen_count"],
        "antigens": load_json(row["antigens_json"], []),
        "matched_regexes": load_json(row["matched_regexes_json"], []),
        "raw_evidence": load_json(row["raw_evidence_json"], {}),
    }


def _row_to_cell(row: sqlite3.Row) -> dict:
    return {
        "cell_key": row["cell_key"],
        "responsible_ip": row["profile_ip"],
        "regex_type": row["regex_type"],
        "antigen_value": row["antigen_value"],
        "state": row["state"],
        "state_name": row["state_name"],
        "matched_regex_hash": row["matched_regex_hash"],
        "matched_regex": row["matched_regex"],
        "matched_value": row["matched_value"],
        "anergic_until": row["anergic_until"],
        "effector_cooldown_until": row["effector_cooldown_until"],
        "last_observation_id": row["last_observation_id"],
        "last_evidence_id": row["last_evidence_id"],
        "last_transition_at": row["last_transition_at"],
        "last_co_stimulation": row["last_co_stimulation"],
        "last_effector_score": row["last_effector_score"],
        "last_memory_score": row["last_memory_score"],
        "context": load_json(row["context_json"], {}),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _row_to_transition(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "cell_key": row["cell_key"],
        "responsible_ip": row["profile_ip"],
        "regex_type": row["regex_type"],
        "antigen_value": row["antigen_value"],
        "evidence_id": row["evidence_id"],
        "observation_id": row["observation_id"],
        "from_state": row["from_state"],
        "to_state": row["to_state"],
        "reason": row["reason"],
        "matched_regex_hash": row["matched_regex_hash"],
        "matched_regex": row["matched_regex"],
        "matched_value": row["matched_value"],
        "scores": load_json(row["scores_json"], {}),
        "created_at": row["created_at"],
    }


def _row_to_memory(row: sqlite3.Row) -> dict:
    return {
        "cell_key": row["cell_key"],
        "responsible_ip": row["profile_ip"],
        "regex_type": row["regex_type"],
        "antigen_value": row["antigen_value"],
        "regex_hash": row["regex_hash"],
        "regex": row["regex"],
        "matched_value": row["matched_value"],
        "context": load_json(row["context_json"], {}),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def load_db_records(db_path: Path) -> dict:
    if not db_path.exists():
        raise FileNotFoundError(f"T Cell DB not found: {db_path}")

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        observations = [
            _row_to_observation(row)
            for row in conn.execute(
                "SELECT * FROM observations ORDER BY observed_at ASC, id ASC"
            )
        ]
        cells = [
            _row_to_cell(row)
            for row in conn.execute(
                "SELECT * FROM cells ORDER BY updated_at DESC, created_at DESC"
            )
        ]
        transitions = [
            _row_to_transition(row)
            for row in conn.execute(
                "SELECT * FROM transitions ORDER BY created_at ASC, id ASC"
            )
        ]
        memories = [
            _row_to_memory(row)
            for row in conn.execute(
                "SELECT * FROM memories ORDER BY updated_at DESC, created_at DESC"
            )
        ]
    return {
        "observations": observations,
        "cells": cells,
        "transitions": transitions,
        "memories": memories,
    }


def parse_log_line(raw_line: str) -> dict | None:
    line = ANSI_RE.sub("", raw_line.strip())
    if not line:
        return None

    parts = [part.strip() for part in line.split(" | ")]
    record = {"raw": line, "wall": parts[0], "ts": parse_alerts_timestamp(parts[0])}
    extras = []
    for part in parts[1:]:
        if "=" in part:
            key, value = part.split("=", 1)
            record[key] = value
        else:
            extras.append(part)
    if extras:
        record["details"] = " | ".join(extras)
    return record


def load_log_entries(log_path: Path, max_lines: int) -> dict:
    if not log_path.exists():
        return {"entries": [], "tail": []}

    entries = []
    tail = deque(maxlen=max(1, max_lines))
    with log_path.open("r", encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.rstrip("\n")
            tail.append(ANSI_RE.sub("", line))
            parsed = parse_log_line(line)
            if parsed:
                entries.append(parsed)
    return {"entries": entries, "tail": list(tail)}


def load_trace_entries(trace_path: Path) -> list[dict]:
    if not trace_path.exists():
        return []
    entries = []
    with trace_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            text = line.strip()
            if not text:
                continue
            try:
                entry = json.loads(text)
            except json.JSONDecodeError:
                continue
            entry["_ts"] = parse_alerts_timestamp(entry.get("ts"))
            entries.append(entry)
    return entries


def entity_ip(entity: dict | None) -> str:
    if not isinstance(entity, dict):
        return ""
    raw_type = str(entity.get("ioc_type") or "").upper()
    if raw_type.endswith("IP") or raw_type == "IP":
        return str(entity.get("value") or "")
    return ""


def observation_related_profile(observation: dict) -> str:
    raw = observation.get("raw_evidence") or {}
    profile = raw.get("profile") or {}
    if isinstance(profile, dict) and profile.get("ip"):
        return str(profile.get("ip"))
    return observation.get("responsible_ip") or ""


def observation_target_ip(observation: dict) -> str:
    raw = observation.get("raw_evidence") or {}
    return entity_ip(raw.get("victim"))


def observation_description(observation: dict) -> str:
    raw = observation.get("raw_evidence") or {}
    return str(raw.get("description") or "")


def summarize_antigens(antigens: list[dict], limit: int = 4) -> str:
    if not antigens:
        return "none"
    return ", ".join(
        f"{item.get('regex_type')}:{item.get('value')}"
        for item in antigens[:limit]
    )


def summarize_matched_regexes(matches: list[dict], limit: int = 2) -> str:
    if not matches:
        return "none"
    return ", ".join(
        f"{item.get('regex_type')}:{item.get('value')}"
        for item in matches[:limit]
    )


def categorize_observation(observation: dict, transition_map: dict[int, list[dict]]) -> str:
    signal = observation.get("evidence_signal")
    if signal != "PAMP":
        if observation.get("antigen_count", 0) > 0:
            return "DAMP with extracted antigens"
        return "DAMP ignored for activation"

    if observation.get("antigen_count", 0) <= 0:
        return "PAMP with no antigen"

    matches = observation.get("matched_regexes") or []
    if matches:
        return "PAMP with regex match"

    transitions = transition_map.get(observation["id"], [])
    if any(item.get("reason") == "no_regex_match" for item in transitions):
        return "PAMP with no regex match"
    return "PAMP with antigens but no stored match"


def top_counts(counter: Counter, limit: int = 12) -> list[dict]:
    return [
        {"label": label, "count": count}
        for label, count in counter.most_common(limit)
    ]


def safe_div(num: float, den: float) -> float:
    if not den:
        return 0.0
    return num / den


def build_findings(report: dict) -> list[str]:
    totals = report["totals"]
    categories = report["observation_categories"]
    current_states = report["cell_states"]
    findings = []

    if totals["observations"] == 0:
        findings.append("No T-cell observations were stored for this run.")
        return findings

    damp_count = totals["signals"].get("DAMP", 0)
    pamp_count = totals["signals"].get("PAMP", 0)
    if damp_count:
        ratio = safe_div(damp_count, totals["observations"]) * 100.0
        findings.append(
            f"Most evidence was DAMP: {damp_count}/{totals['observations']} "
            f"observations ({ratio:.1f}%)."
        )
    if pamp_count and categories.get("PAMP with no antigen", 0):
        findings.append(
            f"{categories['PAMP with no antigen']} PAMP observations stopped before "
            "regex matching because no supported antigen could be extracted."
        )
    if categories.get("PAMP with no regex match", 0):
        findings.append(
            f"{categories['PAMP with no regex match']} PAMP observations reached "
            "antigen extraction but did not match any accepted regex."
        )
    if totals["cells"] == 0 and totals["transitions"] == 0:
        findings.append(
            "No T-cell was ever created, so no state transition, effector action, "
            "or memory write could happen."
        )
    if totals["transitions_to_state"].get("3 - activated", 0):
        findings.append(
            f"{totals['transitions_to_state']['3 - activated']} activation "
            "transition(s) reached state 3."
        )
    if totals["transitions_to_state"].get("4 - effector", 0):
        findings.append(
            f"{totals['transitions_to_state']['4 - effector']} effector "
            "transition(s) requested containment."
        )
    if totals["memories"]:
        findings.append(
            f"{totals['memories']} memory cell(s) were stored for later reuse."
        )
    if current_states.get("1 - antigen-recognized", 0):
        findings.append(
            f"{current_states['1 - antigen-recognized']} cell(s) are currently waiting "
            "for co-stimulation."
        )
    if current_states.get("3 - activated", 0):
        findings.append(
            f"{current_states['3 - activated']} cell(s) are currently waiting "
            "for context."
        )
    if report["sources"]["trace_enabled"] and not report["trace"]["rows"]:
        findings.append(
            "Decision tracing was enabled, but no trace rows were written."
        )
    if not report["sources"]["trace_enabled"]:
        findings.append(
            "Decision trace was off for this run, so threshold-by-threshold "
            "explanations are not available."
        )
    return findings[:8]


def build_timelines(
    observations: list[dict],
    transitions: list[dict],
    trace_rows: list[dict],
) -> dict:
    observation_items = [
        {"ts": item["observed_at"], "signal": item["evidence_signal"]}
        for item in observations
        if item.get("observed_at") is not None
    ]
    transition_items = [
        {"ts": item["created_at"], "to_state": state_label(item.get("to_state"))}
        for item in transitions
        if item.get("created_at") is not None
    ]
    trace_items = [
        {
            "ts": item.get("_ts"),
            "stage": item.get("stage"),
            "action": item.get("action"),
        }
        for item in trace_rows
        if item.get("_ts") is not None
    ]

    return {
        "observations": bucket_items(
            observation_items,
            {
                "PAMP observations": lambda item: item["signal"] == "PAMP",
                "DAMP observations": lambda item: item["signal"] == "DAMP",
            },
        ),
        "transitions": bucket_items(
            transition_items,
            {
                "recognized": lambda item: item["to_state"] == "1 - antigen-recognized",
                "anergic": lambda item: item["to_state"] == "2 - anergic",
                "activated": lambda item: item["to_state"] == "3 - activated",
                "effector": lambda item: item["to_state"] == "4 - effector",
                "memory": lambda item: item["to_state"] == "5 - memory",
            },
        ),
        "trace": bucket_items(
            trace_items,
            {
                "co-stimulation": lambda item: item["stage"] == "co_stimulation",
                "context": lambda item: item["stage"] == "context",
            },
        ),
    }


def bucket_items(
    items: list[dict], series_predicates: dict[str, Any], bin_count: int = 36
) -> dict:
    timed = [item for item in items if item.get("ts") is not None]
    if not timed:
        return {}

    min_ts = min(float(item["ts"]) for item in timed)
    max_ts = max(float(item["ts"]) for item in timed)
    if max_ts <= min_ts:
        max_ts = min_ts + 1.0
    bin_count = max(8, min(bin_count, 72))
    width = (max_ts - min_ts) / bin_count
    if width <= 0:
        width = 1.0

    labels = []
    series = {name: [0] * bin_count for name in series_predicates}
    for index in range(bin_count):
        center = min_ts + ((index + 0.5) * width)
        labels.append(ts_to_iso(center))

    for item in timed:
        idx = int((float(item["ts"]) - min_ts) / width)
        idx = max(0, min(idx, bin_count - 1))
        for name, predicate in series_predicates.items():
            if predicate(item):
                series[name][idx] += 1

    return {
        "labels": labels,
        "series": series,
        "min_ts": min_ts,
        "max_ts": max_ts,
        "width": width,
        "bin_count": bin_count,
    }


def build_report_payload(
    run_output_dir: Path,
    max_observations: int = 200,
    max_log_lines: int = 400,
    max_trace_rows: int = 200,
) -> dict:
    run_output_dir = run_output_dir.expanduser().resolve()
    db_path = run_output_dir / "t_cell" / "t_cell.sqlite"
    log_path = run_output_dir / "t_cell.log"
    trace_path = run_output_dir / "t_cell_trace.jsonl"
    metadata_path = run_output_dir / "metadata" / "slips.yaml"

    db_records = load_db_records(db_path)
    observations = db_records["observations"]
    cells = db_records["cells"]
    transitions = db_records["transitions"]
    memories = db_records["memories"]
    log_data = load_log_entries(log_path, max_log_lines)
    trace_rows = load_trace_entries(trace_path)
    config = load_yaml_config(metadata_path).get("t_cell", {})

    transitions_by_observation: dict[int, list[dict]] = defaultdict(list)
    for transition in transitions:
        observation_id = transition.get("observation_id")
        if observation_id is not None:
            transitions_by_observation[int(observation_id)].append(transition)

    signal_counts = Counter()
    evidence_type_counts = Counter()
    observation_categories = Counter()
    responsible_ip_counts = Counter()
    related_profile_counts = Counter()
    target_ip_counts = Counter()
    antigen_counts = Counter()
    unmatched_pamp_antigens = Counter()
    matched_regex_counts = Counter()

    recent_observations = []
    for observation in observations:
        signal_counts[observation["evidence_signal"]] += 1
        evidence_type_counts[
            (observation["evidence_type"], observation["evidence_signal"])
        ] += 1
        responsible_ip_counts[observation["responsible_ip"]] += 1

        related_profile = observation_related_profile(observation)
        target_ip = observation_target_ip(observation)
        if related_profile:
            related_profile_counts[related_profile] += 1
        if target_ip:
            target_ip_counts[target_ip] += 1

        category = categorize_observation(observation, transitions_by_observation)
        observation_categories[category] += 1

        for antigen in observation["antigens"]:
            key = f"{antigen.get('regex_type')}:{antigen.get('value')}"
            antigen_counts[key] += 1
            if (
                observation["evidence_signal"] == "PAMP"
                and not observation["matched_regexes"]
            ):
                unmatched_pamp_antigens[key] += 1
        for match in observation["matched_regexes"]:
            matched_regex_counts[
                f"{match.get('regex_type')}:{match.get('value')}"
            ] += 1

        recent_observations.append(
            {
                "ts": observation["observed_at"],
                "wall": ts_to_iso(observation["observed_at"]),
                "evidence_id": observation["evidence_id"],
                "evidence_type": observation["evidence_type"],
                "signal": observation["evidence_signal"],
                "responsible_ip": observation["responsible_ip"],
                "related_profile": related_profile,
                "target_ip": target_ip,
                "category": category,
                "antigens": summarize_antigens(observation["antigens"]),
                "matched_regexes": summarize_matched_regexes(
                    observation["matched_regexes"]
                ),
                "description": observation_description(observation),
                "timewindow": observation["timewindow_number"],
                "confidence": observation["confidence"],
            }
        )

    recent_observations.sort(
        key=lambda item: (float(item["ts"]), item["evidence_id"]), reverse=True
    )

    transition_reason_counts = Counter()
    transition_path_counts = Counter()
    transitions_to_state = Counter()
    recent_transitions = []
    for transition in transitions:
        transition_reason_counts[transition["reason"]] += 1
        from_label = state_label(transition.get("from_state"))
        to_label = state_label(transition.get("to_state"))
        transition_path_counts[f"{from_label} -> {to_label}"] += 1
        transitions_to_state[to_label] += 1
        recent_transitions.append(
            {
                "ts": transition["created_at"],
                "wall": ts_to_iso(transition["created_at"]),
                "cell_key": transition["cell_key"],
                "responsible_ip": transition["responsible_ip"],
                "regex_type": transition["regex_type"],
                "antigen_value": transition["antigen_value"],
                "evidence_id": transition["evidence_id"],
                "from_state": from_label,
                "to_state": to_label,
                "from_state_order": transition.get("from_state", -1),
                "to_state_order": transition.get("to_state", -1),
                "reason": transition["reason"],
                "matched_value": transition.get("matched_value") or "",
                "scores": transition.get("scores") or {},
            }
        )
    recent_transitions.sort(
        key=lambda item: (
            item["cell_key"].lower(),
            float(item["ts"]),
            int(item["from_state_order"]),
            int(item["to_state_order"]),
            item["evidence_id"],
        )
    )

    current_state_counts = Counter()
    recent_cells = []
    for cell in cells:
        label = state_label(cell["state"])
        current_state_counts[label] += 1
        recent_cells.append(
            {
                "ts": cell["updated_at"],
                "wall": ts_to_iso(cell["updated_at"]),
                "cell_key": cell["cell_key"],
                "responsible_ip": cell["responsible_ip"],
                "state": label,
                "state_class": state_class(cell["state"]),
                "regex_type": cell["regex_type"],
                "antigen_value": cell["antigen_value"],
                "matched_value": cell.get("matched_value") or "",
                "last_co_stimulation": cell.get("last_co_stimulation"),
                "last_effector_score": cell.get("last_effector_score"),
                "last_memory_score": cell.get("last_memory_score"),
                "last_evidence_id": cell.get("last_evidence_id") or "",
            }
        )
    recent_cells.sort(key=lambda item: item["ts"], reverse=True)

    recent_memories = []
    for memory in memories:
        recent_memories.append(
            {
                "ts": memory["updated_at"],
                "wall": ts_to_iso(memory["updated_at"]),
                "cell_key": memory["cell_key"],
                "responsible_ip": memory["responsible_ip"],
                "regex_type": memory["regex_type"],
                "antigen_value": memory["antigen_value"],
                "matched_value": memory["matched_value"],
                "regex_hash": memory["regex_hash"],
                "context": memory.get("context") or {},
            }
        )
    recent_memories.sort(key=lambda item: item["ts"], reverse=True)

    trace_action_counts = Counter()
    recent_trace_rows = []
    for entry in trace_rows:
        trace_action_counts[entry.get("action") or "unknown"] += 1
        formula = entry.get("formula") or {}
        recent_trace_rows.append(
            {
                "ts": entry.get("_ts"),
                "wall": entry.get("ts") or ts_to_iso(entry.get("_ts")),
                "stage": entry.get("stage") or "",
                "action": entry.get("action") or "",
                "from_state": entry.get("from_state") or "",
                "to_state": entry.get("to_state") or "",
                "responsible_ip": entry.get("responsible_ip") or "",
                "candidate": entry.get("candidate") or {},
                "match": entry.get("match") or {},
                "formula": formula,
                "score_summary": summarize_trace_formula(formula, entry.get("stage")),
            }
        )
    recent_trace_rows.sort(
        key=lambda item: (item["ts"] is None, item["ts"] or 0.0), reverse=True
    )

    log_action_counts = Counter(
        entry.get("action", "unknown") for entry in log_data["entries"] if entry
    )
    recent_log_rows = [
        {
            "ts": entry.get("ts"),
            "wall": entry.get("wall") or "",
            "action": entry.get("action", ""),
            "signal": entry.get("signal", ""),
            "evidence": entry.get("evidence", ""),
            "responsible": entry.get("responsible", ""),
            "raw": entry.get("raw", ""),
        }
        for entry in log_data["entries"][-max(1, max_log_lines) :]
    ]

    report = {
        "generated_at": now_iso(),
        "run_output_dir": str(run_output_dir),
        "sources": {
            "db_path": str(db_path),
            "log_path": str(log_path),
            "trace_path": str(trace_path),
            "metadata_path": str(metadata_path),
            "trace_enabled": bool(trace_path.exists()),
            "log_present": log_path.exists(),
            "metadata_present": metadata_path.exists(),
        },
        "config": {
            "enabled": config.get("enabled"),
            "log_verbosity": config.get("log_verbosity"),
            "decision_trace_mode": config.get("decision_trace_mode"),
            "related_lookback_seconds": config.get("related_lookback_seconds"),
            "co_stimulation_threshold": config.get("co_stimulation_threshold"),
            "effector_threshold": config.get("effector_threshold"),
            "memory_threshold": config.get("memory_threshold"),
            "anergy_ttl_seconds": config.get("anergy_ttl_seconds"),
            "effector_cooldown_seconds": config.get("effector_cooldown_seconds"),
        },
        "totals": {
            "observations": len(observations),
            "cells": len(cells),
            "transitions": len(transitions),
            "memories": len(memories),
            "trace_rows": len(trace_rows),
            "log_rows": len(log_data["entries"]),
            "observations_with_antigens": sum(
                1 for item in observations if item["antigen_count"] > 0
            ),
            "observations_with_matches": sum(
                1 for item in observations if item["matched_regexes"]
            ),
            "signals": dict(signal_counts),
            "transitions_to_state": dict(transitions_to_state),
        },
        "observation_categories": dict(observation_categories),
        "cell_states": dict(current_state_counts),
        "top_signals_by_type": [
            {
                "evidence_type": evidence_type,
                "signal": signal,
                "count": count,
            }
            for (evidence_type, signal), count in evidence_type_counts.most_common(20)
        ],
        "top_responsible_ips": top_counts(responsible_ip_counts),
        "top_related_profiles": top_counts(related_profile_counts),
        "top_targets": top_counts(target_ip_counts),
        "top_antigens": top_counts(antigen_counts, limit=20),
        "top_unmatched_pamp_antigens": top_counts(unmatched_pamp_antigens, limit=20),
        "top_matched_regexes": top_counts(matched_regex_counts, limit=20),
        "transition_reasons": top_counts(transition_reason_counts, limit=20),
        "transition_paths": top_counts(transition_path_counts, limit=20),
        "trace_action_counts": top_counts(trace_action_counts, limit=20),
        "log_action_counts": top_counts(log_action_counts, limit=20),
        "recent_observations": recent_observations[: max(1, max_observations)],
        "recent_transitions": recent_transitions[: max(1, max_observations)],
        "recent_cells": recent_cells[: max(1, max_observations)],
        "recent_memories": recent_memories[: max(1, max_observations)],
        "trace": {
            "rows": recent_trace_rows[: max(1, max_trace_rows)],
            "total_rows": len(trace_rows),
        },
        "log": {
            "rows": recent_log_rows,
            "tail_text": "\n".join(log_data["tail"]),
        },
    }
    report["timelines"] = build_timelines(observations, transitions, trace_rows)
    report["findings"] = build_findings(report)
    return report


def summarize_trace_formula(formula: dict, stage: str | None) -> str:
    if not isinstance(formula, dict):
        return "n/a"
    if stage == "co_stimulation":
        return (
            f"value={format_float(formula.get('value'))} / "
            f"threshold={format_float(formula.get('threshold'))}"
        )
    if stage == "context":
        return (
            f"effector={format_float(formula.get('effector_score'))}/"
            f"{format_float(formula.get('effector_threshold'))}, "
            f"memory={format_float(formula.get('memory_score'))}/"
            f"{format_float(formula.get('memory_threshold'))}"
        )
    return "n/a"


def render_badge(text: str, css_class: str) -> str:
    return f'<span class="badge {css_class}">{escape(text)}</span>'


def render_counter_cards(report: dict) -> str:
    totals = report["totals"]
    signals = totals["signals"]
    cards = [
        ("Observations", totals["observations"], "warm"),
        ("PAMP", signals.get("PAMP", 0), "pamp"),
        ("DAMP", signals.get("DAMP", 0), "damp"),
        ("With Antigens", totals["observations_with_antigens"], "neutral"),
        ("Regex Matches", totals["observations_with_matches"], "neutral"),
        ("Cells", totals["cells"], "neutral"),
        ("Transitions", totals["transitions"], "neutral"),
        ("Memories", totals["memories"], "memory"),
    ]
    return "".join(
        f"""
        <article class="stat-card {css_class}">
          <p class="kicker">{escape(label)}</p>
          <p class="value">{escape(str(value))}</p>
        </article>
        """
        for label, value, css_class in cards
    )


def render_simple_table(columns: list[str], rows: list[dict], empty_text: str) -> str:
    if not rows:
        return f'<p class="empty">{escape(empty_text)}</p>'
    head = "".join(f"<th>{escape(column)}</th>" for column in columns)
    body_rows = []
    for row in rows:
        body_cells = "".join(
            f"<td>{row.get(column, '')}</td>" for column in columns
        )
        body_rows.append(f"<tr>{body_cells}</tr>")
    body = "".join(body_rows)
    return (
        '<div class="table-wrap"><table class="report-table">'
        f"<thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"
    )


def render_sortable_observation_table(rows: list[dict]) -> str:
    if not rows:
        return '<p class="empty">No observations available.</p>'

    columns = [
        "Observed at",
        "Category",
        "Signal",
        "Evidence",
        "Responsible",
        "Related profile",
        "Target",
        "Antigens",
        "Matches",
    ]
    head = "".join(
        (
            "<th scope='col'>"
            f"<button type='button' class='sort-button' data-column='{index}' aria-label='Sort by {escape(column)}'>"
            f"{escape(column)}"
            "<span class='sort-indicator' aria-hidden='true'>↕</span>"
            "</button>"
            "</th>"
        )
        for index, column in enumerate(columns)
    )

    body_rows = []
    for index, row in enumerate(rows):
        cells = [
            (escape(row["wall"]), row["ts"]),
            (escape(row["category"]), row["category"]),
            (render_badge(row["signal"], row["signal"].lower()), row["signal"]),
            (
                escape(f"{row['evidence_type']} · {shorten(row['evidence_id'], 16)}"),
                f"{row['evidence_type']} {row['evidence_id']}",
            ),
            (escape(row["responsible_ip"]), row["responsible_ip"]),
            (escape(row["related_profile"]), row["related_profile"]),
            (escape(row["target_ip"]), row["target_ip"]),
            (escape(shorten(row["antigens"], 120)), row["antigens"]),
            (escape(shorten(row["matched_regexes"], 120)), row["matched_regexes"]),
        ]
        body_cells = "".join(
            f"<td data-sort-value='{escape(str(sort_value))}'>{html_value}</td>"
            for html_value, sort_value in cells
        )
        body_rows.append(f"<tr data-row-index='{index}'>{body_cells}</tr>")

    body = "".join(body_rows)
    return (
        "<div class='table-wrap'>"
        "<table class='report-table sortable-table' data-sortable-table='recent-observations' "
        "data-default-sort-column='0' data-default-sort-direction='desc'>"
        f"<thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"
    )


def render_sortable_transition_table(rows: list[dict]) -> str:
    if not rows:
        return '<p class="empty">No state transitions were recorded.</p>'

    columns = [
        "When",
        "Path",
        "Reason",
        "Responsible",
        "T Cell",
        "Evidence",
        "Scores",
    ]
    head = "".join(
        (
            "<th scope='col'>"
            f"<button type='button' class='sort-button' data-column='{index}' aria-label='Sort by {escape(column)}'>"
            f"{escape(column)}"
            "<span class='sort-indicator' aria-hidden='true'>↕</span>"
            "</button>"
            "</th>"
        )
        for index, column in enumerate(columns)
    )

    body_rows = []
    for index, row in enumerate(rows):
        score_summary = ", ".join(
            f"{key}={value}" for key, value in sorted((row["scores"] or {}).items())
        ) or "n/a"
        cells = [
            (escape(row["wall"]), row["ts"]),
            (
                f"{render_badge(row['from_state'], state_class_name(row['from_state']))} "
                f"→ {render_badge(row['to_state'], state_class_name(row['to_state']))}",
                f"{row['from_state_order']:02d}->{row['to_state_order']:02d}",
            ),
            (escape(row["reason"]), row["reason"]),
            (escape(row["responsible_ip"]), row["responsible_ip"]),
            (escape(shorten(row["cell_key"], 54)), row["cell_key"]),
            (escape(shorten(row["evidence_id"], 20)), row["evidence_id"]),
            (
                f"<details><summary>show</summary><pre>{render_pretty_json(row['scores'])}</pre></details>",
                score_summary,
            ),
        ]
        body_cells = "".join(
            f"<td data-sort-value='{escape(str(sort_value))}'>{html_value}</td>"
            for html_value, sort_value in cells
        )
        body_rows.append(f"<tr data-row-index='{index}'>{body_cells}</tr>")

    body = "".join(body_rows)
    return (
        "<div class='table-wrap'>"
        "<table class='report-table sortable-table' data-sortable-table='recent-transitions' "
        "data-default-sort-column='4' data-default-sort-direction='asc'>"
        f"<thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"
    )


def render_svg_timeline(title: str, timeline: dict, series_order: list[str], color_map: dict[str, str]) -> str:
    if not timeline:
        return (
            f"<section class='panel'><h3>{escape(title)}</h3>"
            "<p class='empty'>No timed data available.</p></section>"
        )

    labels = timeline["labels"]
    series = timeline["series"]
    width = 960
    height = 220
    padding_top = 18
    padding_bottom = 28
    padding_side = 20
    plot_width = width - (padding_side * 2)
    plot_height = height - padding_top - padding_bottom
    bars = []

    max_total = 0
    for idx in range(len(labels)):
        total = sum(series.get(name, [0] * len(labels))[idx] for name in series_order)
        max_total = max(max_total, total)
    max_total = max(max_total, 1)
    bar_width = plot_width / max(1, len(labels))

    for idx, label in enumerate(labels):
        x = padding_side + (idx * bar_width)
        stack_height = 0.0
        tooltip_lines = [label]
        for name in series_order:
            value = series.get(name, [0] * len(labels))[idx]
            tooltip_lines.append(f"{name}: {value}")
            if value <= 0:
                continue
            rect_height = (float(value) / float(max_total)) * plot_height
            y = padding_top + (plot_height - stack_height - rect_height)
            bars.append(
                "<rect "
                f"x='{x:.2f}' y='{y:.2f}' width='{max(1.0, bar_width - 1.0):.2f}' "
                f"height='{max(1.0, rect_height):.2f}' fill='{color_map.get(name, '#334155')}' "
                "rx='2' ry='2'>"
                f"<title>{escape(' | '.join(tooltip_lines))}</title>"
                "</rect>"
            )
            stack_height += rect_height

    legend = "".join(
        f"<li><span class='legend-swatch' style='background:{escape(color_map.get(name, '#334155'))}'></span>{escape(name)}</li>"
        for name in series_order
    )
    return f"""
    <section class="panel">
      <div class="panel-head">
        <h3>{escape(title)}</h3>
        <p class="meta">{escape(ts_to_iso(timeline['min_ts']))} to {escape(ts_to_iso(timeline['max_ts']))}
        · {int(round(timeline['width']))}s per bucket</p>
      </div>
      <svg viewBox="0 0 {width} {height}" class="timeline-svg" role="img" aria-label="{escape(title)}">
        <rect x="0" y="0" width="{width}" height="{height}" fill="#fffdf8" />
        <line x1="{padding_side}" y1="{padding_top + plot_height}" x2="{width - padding_side}" y2="{padding_top + plot_height}" stroke="#d6d3d1" />
        {''.join(bars)}
      </svg>
      <ul class="legend">{legend}</ul>
    </section>
    """


def hex_to_rgba(hex_color: str, alpha: float) -> str:
    color = hex_color.lstrip("#")
    if len(color) != 6:
        return f"rgba(31, 41, 55, {alpha})"
    red = int(color[0:2], 16)
    green = int(color[2:4], 16)
    blue = int(color[4:6], 16)
    return f"rgba({red}, {green}, {blue}, {alpha})"


def render_state_machine_graph(report: dict) -> str:
    node_layout = {
        0: {"x": 40, "y": 122},
        1: {"x": 320, "y": 44},
        2: {"x": 320, "y": 244},
        3: {"x": 600, "y": 122},
        4: {"x": 880, "y": 30},
        5: {"x": 880, "y": 214},
    }
    node_width = 210
    node_height = 68
    transition_counts = {
        row["label"]: row["count"] for row in report.get("transition_paths", [])
    }
    current_state_counts = report.get("cell_states", {})

    edges = [
        {
            "from": 0,
            "to": 1,
            "trigger": "regex match",
            "path": "M 250 156 C 275 156, 286 120, 320 104",
            "label_x": 272,
            "label_y": 116,
        },
        {
            "from": 0,
            "to": 2,
            "trigger": "no regex",
            "path": "M 250 156 C 275 156, 286 286, 320 278",
            "label_x": 268,
            "label_y": 252,
        },
        {
            "from": 2,
            "to": 0,
            "trigger": "anergy TTL",
            "path": "M 320 306 C 248 338, 178 322, 146 190",
            "label_x": 182,
            "label_y": 330,
        },
        {
            "from": 1,
            "to": 1,
            "trigger": "wait",
            "path": "M 392 44 C 350 4, 502 4, 460 44",
            "label_x": 426,
            "label_y": 12,
        },
        {
            "from": 1,
            "to": 3,
            "trigger": "co-stimulation",
            "path": "M 530 78 L 600 156",
            "label_x": 542,
            "label_y": 94,
        },
        {
            "from": 1,
            "to": 2,
            "trigger": "timeout",
            "path": "M 425 112 L 425 244",
            "label_x": 438,
            "label_y": 184,
        },
        {
            "from": 3,
            "to": 3,
            "trigger": "wait",
            "path": "M 672 122 C 630 82, 782 82, 740 122",
            "label_x": 706,
            "label_y": 90,
        },
        {
            "from": 3,
            "to": 4,
            "trigger": "contain",
            "path": "M 810 144 L 880 86",
            "label_x": 828,
            "label_y": 112,
        },
        {
            "from": 3,
            "to": 5,
            "trigger": "remember",
            "path": "M 810 168 L 880 248",
            "label_x": 824,
            "label_y": 214,
        },
        {
            "from": 3,
            "to": 0,
            "trigger": "context timeout",
            "path": "M 600 156 C 536 236, 286 236, 250 156",
            "label_x": 430,
            "label_y": 260,
        },
        {
            "from": 4,
            "to": 4,
            "trigger": "cooldown",
            "path": "M 952 30 C 914 -8, 1088 -8, 1050 30",
            "label_x": 1000,
            "label_y": 2,
        },
        {
            "from": 5,
            "to": 5,
            "trigger": "retained",
            "path": "M 952 282 C 914 320, 1088 320, 1050 282",
            "label_x": 998,
            "label_y": 334,
        },
    ]

    node_svg = []
    for state_id, label in STATE_LABELS.items():
        node = node_layout[state_id]
        color = STATE_COLORS[state_class(state_id)]
        count = current_state_counts.get(label, 0)
        node_svg.append(
            f"""
            <g>
              <rect x="{node['x']}" y="{node['y']}" width="{node_width}" height="{node_height}"
                    rx="18" ry="18" fill="{hex_to_rgba(color, 0.10)}" stroke="{color}" stroke-width="2" />
              <text x="{node['x'] + 16}" y="{node['y'] + 26}" fill="#1f2937" font-size="15" font-weight="700">{escape(label)}</text>
              <text x="{node['x'] + 16}" y="{node['y'] + 48}" fill="#665c54" font-size="12">current cells: {count}</text>
            </g>
            """
        )

    edge_svg = []
    for edge in edges:
        from_label = STATE_LABELS[edge["from"]]
        to_label = STATE_LABELS[edge["to"]]
        path_key = f"{from_label} -> {to_label}"
        count = int(transition_counts.get(path_key, 0))
        active = count > 0
        stroke = STATE_COLORS[state_class(edge["to"])]
        edge_svg.append(
            f"""
            <g>
              <path d="{edge['path']}" fill="none" stroke="{stroke}" stroke-width="{3 if active else 1.6}"
                    stroke-opacity="{0.95 if active else 0.30}" stroke-dasharray="{'none' if active else '5 5'}"
                    marker-end="url(#state-arrow)" />
              <text x="{edge['label_x']}" y="{edge['label_y']}" fill="#5b4633" font-size="12" font-weight="700">
                {escape(edge['trigger'])} · {count}
              </text>
            </g>
            """
        )

    return f"""
    <section class="panel" style="margin-top: 14px;">
      <div class="panel-head">
        <h2>T Cell State Machine</h2>
        <p class="meta">Node badges show current cells in each state. Arrow labels show how many times each transition happened in this run.</p>
      </div>
      <svg viewBox="0 0 1120 360" class="timeline-svg" role="img" aria-label="T Cell state machine">
        <defs>
          <marker id="state-arrow" viewBox="0 0 10 10" refX="9" refY="5"
                  markerWidth="8" markerHeight="8" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="#7c2d12"></path>
          </marker>
        </defs>
        <rect x="0" y="0" width="1120" height="360" fill="#fffdf8" />
        {''.join(edge_svg)}
        {''.join(node_svg)}
      </svg>
    </section>
    """


def render_pretty_json(value: Any) -> str:
    return escape(json.dumps(value, indent=2, sort_keys=True))


def render_html(report: dict) -> str:
    findings_html = "".join(
        f"<li>{escape(item)}</li>" for item in report.get("findings", [])
    ) or "<li>No notable findings.</li>"

    config_rows = []
    for key, value in report["config"].items():
        if value in (None, "", {}):
            continue
        config_rows.append(
            {
                "Key": escape(str(key)),
                "Value": escape(str(value)),
            }
        )

    signals_table = render_simple_table(
        ["Signal", "Count", "Share"],
        [
            {
                "Signal": render_badge(signal, signal.lower()),
                "Count": escape(str(count)),
                "Share": escape(
                    f"{safe_div(count, report['totals']['observations']) * 100.0:.1f}%"
                ),
            }
            for signal, count in sorted(
                report["totals"]["signals"].items(), key=lambda item: item[0]
            )
        ],
        "No observations were stored.",
    )

    evidence_type_table = render_simple_table(
        ["Evidence type", "Signal", "Count"],
        [
            {
                "Evidence type": escape(row["evidence_type"]),
                "Signal": render_badge(row["signal"], row["signal"].lower()),
                "Count": escape(str(row["count"])),
            }
            for row in report["top_signals_by_type"]
        ],
        "No evidence rows available.",
    )

    observation_table = render_sortable_observation_table(
        report["recent_observations"]
    )

    transition_table = render_sortable_transition_table(
        report["recent_transitions"]
    )

    cell_table = render_simple_table(
        [
            "Updated",
            "State",
            "Responsible",
            "Cell",
            "Antigen",
            "Matched value",
            "Scores",
        ],
        [
            {
                "Updated": escape(row["wall"]),
                "State": render_badge(row["state"], row["state_class"]),
                "Responsible": escape(row["responsible_ip"]),
                "Cell": escape(shorten(row["cell_key"], 56)),
                "Antigen": escape(f"{row['regex_type']}:{shorten(row['antigen_value'], 40)}"),
                "Matched value": escape(shorten(row["matched_value"], 48)),
                "Scores": escape(
                    ", ".join(
                        part
                        for part in [
                            f"co={format_float(row['last_co_stimulation'])}"
                            if row["last_co_stimulation"] is not None
                            else "",
                            f"eff={format_float(row['last_effector_score'])}"
                            if row["last_effector_score"] is not None
                            else "",
                            f"mem={format_float(row['last_memory_score'])}"
                            if row["last_memory_score"] is not None
                            else "",
                        ]
                        if part
                    )
                    or "n/a"
                ),
            }
            for row in report["recent_cells"]
        ],
        "No cells are stored.",
    )

    memory_table = render_simple_table(
        ["Updated", "Responsible", "Cell", "Regex", "Matched value", "Context"],
        [
            {
                "Updated": escape(row["wall"]),
                "Responsible": escape(row["responsible_ip"]),
                "Cell": escape(shorten(row["cell_key"], 56)),
                "Regex": escape(shorten(row["regex_hash"], 24)),
                "Matched value": escape(shorten(row["matched_value"], 40)),
                "Context": (
                    f"<details><summary>show</summary><pre>{render_pretty_json(row['context'])}</pre></details>"
                ),
            }
            for row in report["recent_memories"]
        ],
        "No memories are stored.",
    )

    trace_section = render_simple_table(
        ["When", "Stage", "Action", "Path", "Responsible", "Candidate", "Scores"],
        [
            {
                "When": escape(row["wall"]),
                "Stage": render_badge(
                    row["stage"] or "unknown",
                    f"trace-{(row['stage'] or 'unknown').replace('_', '-')}",
                ),
                "Action": escape(row["action"]),
                "Path": escape(f"{row['from_state']} → {row['to_state']}"),
                "Responsible": escape(row["responsible_ip"]),
                "Candidate": escape(
                    f"{row['candidate'].get('regex_type', '')}:"
                    f"{shorten(row['candidate'].get('value', ''), 48)}"
                ),
                "Scores": (
                    f"<details><summary>{escape(row['score_summary'])}</summary>"
                    f"<pre>{render_pretty_json(row['formula'])}</pre></details>"
                ),
            }
            for row in report["trace"]["rows"]
        ],
        "No decision trace rows were stored.",
    )

    action_tables = {
        "Top responsible IPs": render_simple_table(
            ["Label", "Count"],
            [
                {"Label": escape(row["label"]), "Count": escape(str(row["count"]))}
                for row in report["top_responsible_ips"]
            ],
            "No responsible IP data.",
        ),
        "Top related profiles": render_simple_table(
            ["Label", "Count"],
            [
                {"Label": escape(row["label"]), "Count": escape(str(row["count"]))}
                for row in report["top_related_profiles"]
            ],
            "No related profile data.",
        ),
        "Top targets": render_simple_table(
            ["Label", "Count"],
            [
                {"Label": escape(row["label"]), "Count": escape(str(row["count"]))}
                for row in report["top_targets"]
            ],
            "No target data.",
        ),
        "Top antigens": render_simple_table(
            ["Label", "Count"],
            [
                {"Label": escape(row["label"]), "Count": escape(str(row["count"]))}
                for row in report["top_antigens"]
            ],
            "No extracted antigens.",
        ),
        "Top unmatched PAMP antigens": render_simple_table(
            ["Label", "Count"],
            [
                {"Label": escape(row["label"]), "Count": escape(str(row["count"]))}
                for row in report["top_unmatched_pamp_antigens"]
            ],
            "No unmatched PAMP antigens.",
        ),
        "Transition reasons": render_simple_table(
            ["Label", "Count"],
            [
                {"Label": escape(row["label"]), "Count": escape(str(row["count"]))}
                for row in report["transition_reasons"]
            ],
            "No transition reasons available.",
        ),
        "Log action counts": render_simple_table(
            ["Label", "Count"],
            [
                {"Label": escape(row["label"]), "Count": escape(str(row["count"]))}
                for row in report["log_action_counts"]
            ],
            "No module log actions available.",
        ),
    }

    action_sections = "".join(
        f"""
        <section class="panel">
          <h3>{escape(title)}</h3>
          {html}
        </section>
        """
        for title, html in action_tables.items()
    )

    config_section = render_simple_table(
        ["Key", "Value"],
        config_rows,
        "No metadata configuration found.",
    )

    observation_timeline = render_svg_timeline(
        "Observation Timeline",
        report["timelines"]["observations"],
        ["PAMP observations", "DAMP observations"],
        {
            "PAMP observations": SIGNAL_COLORS["PAMP"],
            "DAMP observations": SIGNAL_COLORS["DAMP"],
        },
    )
    transition_timeline = render_svg_timeline(
        "Transition Timeline",
        report["timelines"]["transitions"],
        ["recognized", "anergic", "activated", "effector", "memory"],
        {
            "recognized": STATE_COLORS["state-recognized"],
            "anergic": STATE_COLORS["state-anergic"],
            "activated": STATE_COLORS["state-activated"],
            "effector": STATE_COLORS["state-effector"],
            "memory": STATE_COLORS["state-memory"],
        },
    )
    trace_timeline = render_svg_timeline(
        "Decision Trace Timeline",
        report["timelines"]["trace"],
        ["co-stimulation", "context"],
        TRACE_STAGE_COLORS,
    )
    state_machine_graph = render_state_machine_graph(report)

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>T Cell Report</title>
  <style>
    :root {{
      --bg: #f7efe2;
      --panel: #fffdf8;
      --panel-2: #f2e8d7;
      --ink: #1f2937;
      --muted: #665c54;
      --line: #ded4c7;
      --warm: #b45309;
      --pamp: {SIGNAL_COLORS["PAMP"]};
      --damp: {SIGNAL_COLORS["DAMP"]};
      --mature: {STATE_COLORS["state-mature"]};
      --recognized: {STATE_COLORS["state-recognized"]};
      --anergic: {STATE_COLORS["state-anergic"]};
      --activated: {STATE_COLORS["state-activated"]};
      --effector: {STATE_COLORS["state-effector"]};
      --memory: {STATE_COLORS["state-memory"]};
      --shadow: 0 22px 40px rgba(80, 52, 21, 0.10);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-size: 14px;
      font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(181, 83, 9, 0.16), transparent 28%),
        radial-gradient(circle at top right, rgba(3, 105, 161, 0.12), transparent 30%),
        linear-gradient(180deg, #f5efe6 0%, #f7efe2 45%, #f3e6d6 100%);
    }}
    main {{
      max-width: 1560px;
      margin: 0 auto;
      padding: 24px 18px 52px;
    }}
    .hero {{
      background: linear-gradient(140deg, rgba(255, 253, 248, 0.96), rgba(248, 238, 223, 0.98));
      border: 1px solid rgba(123, 83, 44, 0.16);
      border-radius: 22px;
      box-shadow: var(--shadow);
      padding: 22px;
      display: grid;
      gap: 14px;
    }}
    .hero h1 {{
      margin: 0;
      font-size: clamp(1.85rem, 2.5vw, 2.55rem);
      line-height: 1;
      letter-spacing: -0.04em;
    }}
    .hero p {{
      margin: 0;
      color: var(--muted);
      font-size: 0.88rem;
    }}
    .hero code {{
      font-size: 0.80rem;
      word-break: break-all;
    }}
    .summary-grid, .panel-grid, .stats-grid {{
      display: grid;
      gap: 14px;
    }}
    .stats-grid {{
      grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
    }}
    .panel-grid {{
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      margin-top: 14px;
    }}
    .panel {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 18px;
      box-shadow: 0 18px 34px rgba(66, 43, 17, 0.08);
      padding: 15px;
      overflow: hidden;
    }}
    .panel-head {{
      display: flex;
      justify-content: space-between;
      gap: 10px;
      align-items: baseline;
      margin-bottom: 10px;
    }}
    .panel h2, .panel h3 {{
      margin: 0 0 10px;
      letter-spacing: -0.02em;
    }}
    .panel h2 {{
      font-size: 1.05rem;
    }}
    .panel h3 {{
      font-size: 0.96rem;
    }}
    .panel .meta {{
      margin: 0;
      color: var(--muted);
      font-size: 0.78rem;
    }}
    .kicker {{
      margin: 0 0 4px;
      text-transform: uppercase;
      letter-spacing: 0.14em;
      font-size: 0.64rem;
      color: var(--muted);
    }}
    .stat-card {{
      background: linear-gradient(180deg, rgba(255, 253, 248, 0.98), rgba(242, 232, 215, 0.92));
      border: 1px solid rgba(123, 83, 44, 0.14);
      border-radius: 16px;
      padding: 14px;
    }}
    .stat-card .value {{
      margin: 0;
      font-size: 1.45rem;
      line-height: 1;
      font-weight: 700;
      letter-spacing: -0.04em;
    }}
    .stat-card.warm .value {{ color: var(--warm); }}
    .stat-card.pamp .value {{ color: var(--pamp); }}
    .stat-card.damp .value {{ color: var(--damp); }}
    .stat-card.memory .value {{ color: var(--memory); }}
    ul.findings {{
      margin: 0;
      padding-left: 20px;
      display: grid;
      gap: 10px;
    }}
    .badge {{
      display: inline-flex;
      align-items: center;
      border-radius: 999px;
      padding: 3px 8px;
      font-size: 0.70rem;
      font-weight: 700;
      border: 1px solid rgba(0, 0, 0, 0.08);
      white-space: nowrap;
    }}
    .badge.pamp {{ background: rgba(194, 65, 12, 0.12); color: var(--pamp); }}
    .badge.damp {{ background: rgba(3, 105, 161, 0.12); color: var(--damp); }}
    .badge.state-mature {{ background: rgba(15, 118, 110, 0.12); color: var(--mature); }}
    .badge.state-recognized {{ background: rgba(217, 119, 6, 0.14); color: var(--recognized); }}
    .badge.state-anergic {{ background: rgba(37, 99, 235, 0.12); color: var(--anergic); }}
    .badge.state-activated {{ background: rgba(162, 28, 175, 0.12); color: var(--activated); }}
    .badge.state-effector {{ background: rgba(185, 28, 28, 0.12); color: var(--effector); }}
    .badge.state-memory {{ background: rgba(21, 128, 61, 0.12); color: var(--memory); }}
    .badge.trace-co-stimulation {{ background: rgba(180, 83, 9, 0.12); color: #92400e; }}
    .badge.trace-context {{ background: rgba(124, 58, 237, 0.12); color: #6d28d9; }}
    .badge.trace-unknown {{ background: rgba(100, 116, 139, 0.12); color: #475569; }}
    .table-wrap {{
      overflow: auto;
      border: 1px solid var(--line);
      border-radius: 12px;
      background: rgba(255, 253, 248, 0.85);
    }}
    .report-table {{
      width: 100%;
      border-collapse: collapse;
      min-width: 720px;
      table-layout: fixed;
    }}
    .report-table th,
    .report-table td {{
      padding: 7px 8px;
      border-bottom: 1px solid var(--line);
      vertical-align: top;
      text-align: left;
      font-size: 0.76rem;
      overflow-wrap: anywhere;
    }}
    .report-table th {{
      position: sticky;
      top: 0;
      background: #f4ecdd;
      z-index: 1;
      font-size: 0.66rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--muted);
    }}
    .report-table tr:last-child td {{
      border-bottom: none;
    }}
    .sort-button {{
      display: inline-flex;
      align-items: center;
      gap: 6px;
      width: 100%;
      padding: 0;
      border: 0;
      background: transparent;
      color: inherit;
      font: inherit;
      text-transform: inherit;
      letter-spacing: inherit;
      cursor: pointer;
    }}
    .sort-button:hover {{
      color: #7c2d12;
    }}
    .sort-button.is-active {{
      color: #7c2d12;
    }}
    .sort-indicator {{
      font-size: 0.72rem;
      opacity: 0.65;
    }}
    .timeline-svg {{
      width: 100%;
      height: auto;
      border: 1px solid var(--line);
      border-radius: 12px;
      background: #fffdf8;
    }}
    .legend {{
      list-style: none;
      padding: 0;
      margin: 10px 0 0;
      display: flex;
      flex-wrap: wrap;
      gap: 10px 14px;
      color: var(--muted);
      font-size: 0.78rem;
    }}
    .legend li {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
    }}
    .legend-swatch {{
      width: 14px;
      height: 14px;
      border-radius: 4px;
      display: inline-block;
    }}
    pre {{
      margin: 0;
      padding: 12px;
      background: #171717;
      color: #f8fafc;
      border-radius: 12px;
      overflow: auto;
      font-size: 0.74rem;
      line-height: 1.5;
    }}
    details summary {{
      cursor: pointer;
      color: #92400e;
      font-weight: 600;
      font-size: 0.82rem;
    }}
    .empty {{
      margin: 0;
      color: var(--muted);
      font-size: 0.80rem;
    }}
    .source-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 10px;
    }}
    .source-grid code {{
      display: block;
      padding: 8px 10px;
      border-radius: 10px;
      background: rgba(255,255,255,0.7);
      border: 1px solid var(--line);
    }}
    .footer-panel {{
      margin-top: 12px;
      padding: 10px 12px;
      background: rgba(255, 253, 248, 0.78);
    }}
    .footer-panel .meta {{
      margin-bottom: 8px;
    }}
    .footer-panel .report-table {{
      min-width: 480px;
    }}
    .footer-panel .report-table th,
    .footer-panel .report-table td {{
      font-size: 0.70rem;
      padding: 5px 7px;
    }}
    @media (max-width: 900px) {{
      body {{ font-size: 13px; }}
      main {{ padding: 16px 12px 40px; }}
      .panel-grid {{ grid-template-columns: 1fr; }}
      .report-table {{ min-width: 680px; }}
    }}
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <p class="kicker">T Cell HTML Report</p>
      <div>
        <h1>T Cell Run Report</h1>
        <p>Static analysis of observations, signals, transitions, memories, and optional decision traces. Generated at {escape(report['generated_at'])}</p>
      </div>
      <div class="source-grid">
        <div><p class="kicker">Run Output</p><code>{escape(report['run_output_dir'])}</code></div>
        <div><p class="kicker">Database</p><code>{escape(report['sources']['db_path'])}</code></div>
        <div><p class="kicker">Module Log</p><code>{escape(report['sources']['log_path'])}</code></div>
        <div><p class="kicker">Decision Trace</p><code>{escape(report['sources']['trace_path'])}</code></div>
      </div>
    </section>

    <section class="panel-grid" style="margin-top: 18px;">
      <section class="panel">
        <h2>Quick Summary</h2>
        <div class="stats-grid">
          {render_counter_cards(report)}
        </div>
      </section>
      <section class="panel">
        <h2>Run Findings</h2>
        <ul class="findings">{findings_html}</ul>
      </section>
    </section>

    <section class="panel-grid">
      {observation_timeline}
      {transition_timeline}
      {trace_timeline}
    </section>

    {state_machine_graph}

    <section class="panel-grid">
      <section class="panel">
        <h2>Signals</h2>
        {signals_table}
      </section>
      <section class="panel">
        <h2>Evidence Types</h2>
        {evidence_type_table}
      </section>
    </section>

    <section class="panel-grid">
      {action_sections}
    </section>

    <section class="panel" style="margin-top: 18px;">
      <h2>Transitions</h2>
      <p class="meta">Click a column header to sort. Default order groups rows by T cell so each cell's path stays together.</p>
      {transition_table}
    </section>

    <section class="panel-grid">
      <section class="panel">
        <h2>Current Cells</h2>
        {cell_table}
      </section>
      <section class="panel">
        <h2>Stored Memories</h2>
        {memory_table}
      </section>
    </section>

    <section class="panel" style="margin-top: 18px;">
      <h2>Decision Trace</h2>
      <p class="meta">If decision tracing was off for the run, this section will stay empty even when the rest of the report is populated.</p>
      {trace_section}
    </section>

    <section class="panel" style="margin-top: 18px;">
      <h2>Recent Observations</h2>
      <p class="meta">These rows come from the T Cell SQLite DB, so they remain available even when module log verbosity was low. Click a column header to sort.</p>
      {observation_table}
    </section>

    <section class="panel footer-panel">
      <details>
        <summary>Run configuration snapshot</summary>
        <p class="meta">Compact copy of the T Cell-related metadata used for this report.</p>
        {config_section}
      </details>
    </section>
  </main>
  <script>
    (() => {{
      const collator = new Intl.Collator(undefined, {{ numeric: true, sensitivity: "base" }});
      const tables = document.querySelectorAll("[data-sortable-table]");

      const compareValues = (left, right) => {{
        const leftNumber = Number(left);
        const rightNumber = Number(right);
        const leftIsNumber = Number.isFinite(leftNumber) && left.trim() !== "";
        const rightIsNumber = Number.isFinite(rightNumber) && right.trim() !== "";
        if (leftIsNumber && rightIsNumber) {{
          return leftNumber - rightNumber;
        }}
        return collator.compare(left, right);
      }};

      tables.forEach((table) => {{
        const tbody = table.tBodies[0];
        if (!tbody) {{
          return;
        }}

        let activeColumn = Number(table.dataset.defaultSortColumn || 0);
        let activeDirection = table.dataset.defaultSortDirection || "desc";
        const buttons = Array.from(table.querySelectorAll(".sort-button"));

        const updateIndicators = () => {{
          buttons.forEach((button, index) => {{
            const indicator = button.querySelector(".sort-indicator");
            const isActive = index === activeColumn;
            button.classList.toggle("is-active", isActive);
            if (!indicator) {{
              return;
            }}
            if (!isActive) {{
              indicator.textContent = "↕";
            }} else {{
              indicator.textContent = activeDirection === "asc" ? "↑" : "↓";
            }}
          }});
        }};

        const sortRows = () => {{
          const rows = Array.from(tbody.rows);
          rows.sort((leftRow, rightRow) => {{
            const leftValue = (
              leftRow.cells[activeColumn]?.dataset.sortValue ||
              leftRow.cells[activeColumn]?.textContent ||
              ""
            ).trim();
            const rightValue = (
              rightRow.cells[activeColumn]?.dataset.sortValue ||
              rightRow.cells[activeColumn]?.textContent ||
              ""
            ).trim();
            let result = compareValues(leftValue, rightValue);
            if (result === 0) {{
              result =
                Number(leftRow.dataset.rowIndex || 0) -
                Number(rightRow.dataset.rowIndex || 0);
            }}
            return activeDirection === "asc" ? result : -result;
          }});
          rows.forEach((row) => tbody.appendChild(row));
          updateIndicators();
        }};

        buttons.forEach((button, index) => {{
          button.addEventListener("click", () => {{
            if (activeColumn === index) {{
              activeDirection = activeDirection === "asc" ? "desc" : "asc";
            }} else {{
              activeColumn = index;
              activeDirection = index === 0 ? "desc" : "asc";
            }}
            sortRows();
          }});
        }});

        sortRows();
      }});
    }})();
  </script>
</body>
</html>
"""


def state_class_name(label: str) -> str:
    mapping = {value: STATE_CLASS[key] for key, value in STATE_LABELS.items()}
    return mapping.get(label, "state-unknown")


def write_report(run_output_dir: Path, output_html: Path, args: argparse.Namespace) -> Path:
    report = build_report_payload(
        run_output_dir,
        max_observations=args.max_observations,
        max_log_lines=args.max_log_lines,
        max_trace_rows=args.max_trace_rows,
    )
    output_html.parent.mkdir(parents=True, exist_ok=True)
    output_html.write_text(render_html(report), encoding="utf-8")
    return output_html


def main() -> int:
    args = parse_args()
    run_output_dir = Path(args.run_output_dir).expanduser().resolve()
    output_html = (
        Path(args.out).expanduser().resolve()
        if args.out
        else run_output_dir / "t_cell_report.html"
    )
    report_path = write_report(run_output_dir, output_html, args)
    print(f"Report written to: {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
