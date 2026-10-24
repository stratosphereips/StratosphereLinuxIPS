"""Replay conn logs or saved Slips flows with the runtime detector features."""

import argparse
import hashlib
import json
import sqlite3
import time
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from typing import Any, Iterator

from modules.beaconing.detector import Detector, Observation
from modules.beaconing.model import PatternModel
from modules.beaconing.settings import Settings


def read_flows(path: Path) -> Iterator[dict[str, Any]]:
    """Stream Zeek JSON/TSV conn logs or read-only Slips SQLite records.

    Parameters:
        path: Existing conn.log or flows.sqlite filename.

    Yields:
        Original-direction Slips conn records.
    """
    if path.suffix == ".sqlite":
        connection = sqlite3.connect(
            path.resolve().as_uri() + "?mode=ro", uri=True
        )
        try:
            for (data,) in connection.execute(
                "SELECT flow FROM flows ORDER BY rowid"
            ):
                yield json.loads(data)
        finally:
            connection.close()
        return
    fields: list[str] = []
    with path.open() as source:
        for line in source:
            if line.startswith("#fields\t"):
                fields = line.rstrip().split("\t")[1:]
                continue
            if line.startswith("#") or not line.strip():
                continue
            row = (
                json.loads(line)
                if line.startswith("{")
                else dict(zip(fields, line.rstrip().split("\t")))
            )
            if "type_" in row:
                yield row
                continue

            def number(key: str) -> float:
                """Read one optional Zeek number.

                Parameters:
                    key: Conn field name.

                Returns:
                    Numeric value, or zero for unset fields.
                """
                value = row.get(key)
                return 0.0 if value in (None, "-", "(empty)") else float(value)

            yield {
                "type_": "conn",
                "uid": row["uid"],
                "starttime": number("ts"),
                "saddr": row["id.orig_h"],
                "daddr": row["id.resp_h"],
                "sport": row["id.orig_p"],
                "dport": row["id.resp_p"],
                "proto": row["proto"],
                "dur": number("duration"),
                "sbytes": number("orig_bytes"),
                "dbytes": number("resp_bytes"),
                "spkts": number("orig_pkts"),
                "dpkts": number("resp_pkts"),
                "state": row.get("conn_state", ""),
            }


def replay(
    path: Path, settings: Settings, model: PatternModel | None = None
) -> dict[str, Any]:
    """Replay arrival order without sorting away Zeek's completion ordering.

    Parameters:
        path: Zeek conn log or saved flow database.
        settings: Runtime cadence and bounded state settings.
        model: Optional trained pattern classifier for independent evaluation.

    Returns:
        Per-window features, channel counts and processing measurements.
    """
    detector = Detector(settings)
    count = accepted = 0
    windows = []
    recurring: set[str] = set()
    alerted: Counter[str] = Counter()
    clock = 0.0
    digest = hashlib.sha256()
    start = time.perf_counter()
    cpu = time.process_time()
    for flow in read_flows(path):
        count += 1
        digest.update(
            json.dumps(flow, sort_keys=True, separators=(",", ":")).encode()
        )
        digest.update(b"\n")
        observation = Observation.from_flow(flow)
        if observation is None:
            continue
        accepted += 1
        clock = max(clock, observation.timestamp)
        result = detector.process(observation, "offline", clock)
        if not result:
            continue
        key, stats = result
        recurring.add(key)
        score = (
            model.score(stats)
            if model and observation.proto in model.protocols
            else 0.0
        )
        suspected = bool(
            model
            and observation.proto in model.protocols
            and score
            >= max(model.minimum_threshold, settings.c2_score_threshold)
            and stats["answered"] >= 0.8
        )
        kind = "c2" if suspected else "periodic"
        if detector.should_alert(key, kind, observation.timestamp):
            alerted[kind] += 1
        windows.append(
            {
                "channel": key,
                "timestamp": observation.timestamp,
                "features": stats,
                "score": score,
                "suspected": suspected,
            }
        )
    return {
        "sha256": digest.hexdigest(),
        "flows": count,
        "accepted": accepted,
        "channels_retained": len(detector.channels),
        "recurring_channels": len(recurring),
        "findings": dict(alerted),
        "evictions": detector.evictions,
        "out_of_order": detector.late_flows,
        "wall_seconds": time.perf_counter() - start,
        "cpu_seconds": time.process_time() - cpu,
        "windows": windows,
    }


def main() -> None:
    """Run an explicit offline corpus manifest and write a reproducible report."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "manifest",
        type=Path,
        help="JSON list with name, path, split, label and optional c2_endpoints",
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--model", default="", help="Optional reviewed model.json"
    )
    args = parser.parse_args()
    settings = Settings()
    model = PatternModel(args.model) if args.model else None
    result = {"settings": asdict(settings), "captures": []}
    for item in json.loads(args.manifest.read_text()):
        path = Path(item["path"])
        print(f"Replaying {item['name']}", flush=True)
        report = replay(path, settings, model)
        report.update({k: v for k, v in item.items() if k != "path"})
        result["captures"].append(report)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(result, indent=2, allow_nan=False) + "\n"
        )
        print({k: v for k, v in report.items() if k != "windows"}, flush=True)


if __name__ == "__main__":
    main()
