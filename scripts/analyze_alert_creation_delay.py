#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""
Analyze alert creation delay from Slips alerts exports.

This script measures the delay between each alert's CreateTime and StartTime,
then summarizes the distribution and how it evolves over time. It supports the
newline-delimited JSON format used by alerts.json as well as plain JSON arrays.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path


DEFAULT_RESOLUTIONS = ("day", "hour", "minute")
VALID_RESOLUTIONS = set(DEFAULT_RESOLUTIONS)
DELAY_BANDS = (
    ("negative", None, 0.0),
    ("0s-1s", 0.0, 1.0),
    ("1s-10s", 1.0, 10.0),
    ("10s-60s", 10.0, 60.0),
    ("1m-5m", 60.0, 300.0),
    ("5m-1h", 300.0, 3600.0),
    ("1h-1d", 3600.0, 86400.0),
    (">=1d", 86400.0, None),
)


@dataclass(frozen=True)
class AlertDelayRecord:
    record_number: int
    alert_id: str
    severity: str
    create_time: str
    start_time: str
    delay_seconds: float
    description: str


@dataclass(frozen=True)
class SummaryStats:
    count: int
    min_seconds: float
    mean_seconds: float
    p50_seconds: float
    p90_seconds: float
    p95_seconds: float
    p99_seconds: float
    max_seconds: float


@dataclass(frozen=True)
class BucketSummary:
    bucket_start: str
    count: int
    min_seconds: float
    mean_seconds: float
    p50_seconds: float
    p95_seconds: float
    p99_seconds: float
    max_seconds: float


def parse_args() -> argparse.Namespace:
    class HelpFormatter(
        argparse.ArgumentDefaultsHelpFormatter,
        argparse.RawDescriptionHelpFormatter,
    ):
        pass

    parser = argparse.ArgumentParser(
        description=(
            "Analyze alert creation delay in Slips alerts exports.\n\n"
            "The script reads alerts.json, computes the per-alert delay as\n"
            "CreateTime - StartTime, then summarizes the overall distribution\n"
            "and how that delay evolves over time by day, hour, and minute."
        ),
        epilog=(
            "Input format:\n"
            "  alerts.json can be newline-delimited JSON (one alert per line)\n"
            "  or a regular JSON array of alert objects.\n\n"
            "Outputs:\n"
            "  The terminal output shows overall statistics, delay bands,\n"
            "  the alerts with the largest delays, and trend tables.\n"
            "  If --output-dir is given, the script also writes CSV files for\n"
            "  each selected time resolution plus a summary.json file.\n\n"
            "Example:\n"
            "  python3 scripts/analyze_alert_creation_delay.py \\\n"
            "    output/test-tcell-8/alerts.json \\\n"
            "    --output-dir output/test-tcell-8/alert_creation_delay_report"
        ),
        formatter_class=HelpFormatter,
    )
    parser.add_argument(
        "alerts_path",
        help="Path to alerts.json (JSONL or JSON array).",
    )
    parser.add_argument(
        "--bucket-time",
        choices=("create", "start"),
        default="create",
        help=(
            "Which timestamp to use for trend buckets. Default: create "
            "(group by CreateTime)."
        ),
    )
    parser.add_argument(
        "--resolution",
        action="append",
        choices=sorted(VALID_RESOLUTIONS),
        help=(
            "Trend resolution to emit. Repeat to select a subset. "
            "Default: day, hour, minute."
        ),
    )
    parser.add_argument(
        "--output-dir",
        default="",
        help=(
            "Optional directory where CSV trend files, top-delays CSV, and "
            "summary.json will be written."
        ),
    )
    parser.add_argument(
        "--print-limit",
        type=int,
        default=120,
        help=(
            "Print all buckets when a resolution has at most this many buckets. "
            "Default: 120."
        ),
    )
    parser.add_argument(
        "--top-buckets",
        type=int,
        default=10,
        help=(
            "When a resolution has many buckets, print this many worst buckets "
            "and this many most recent buckets. Default: 10."
        ),
    )
    parser.add_argument(
        "--top-alerts",
        type=int,
        default=10,
        help="Show this many alerts with the largest delays. Default: 10.",
    )
    parser.add_argument(
        "--description-width",
        type=int,
        default=110,
        help="Maximum description width in the top-alerts section. Default: 110.",
    )
    return parser.parse_args()


def detect_input_format(path: Path) -> str:
    with path.open(encoding="utf-8") as handle:
        while True:
            char = handle.read(1)
            if not char:
                raise ValueError(f"{path} is empty")
            if char.isspace():
                continue
            return "json-array" if char == "[" else "jsonl"


def iter_alert_records(path: Path):
    input_format = detect_input_format(path)
    if input_format == "json-array":
        with path.open(encoding="utf-8") as handle:
            payload = json.load(handle)
        if not isinstance(payload, list):
            raise ValueError(f"{path} is a JSON array file but did not contain a list")
        for index, alert in enumerate(payload, start=1):
            if not isinstance(alert, dict):
                raise ValueError(f"Record {index} is not a JSON object")
            yield input_format, index, alert
        return

    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                alert = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSON on line {line_number}: {exc.msg}"
                ) from exc
            if not isinstance(alert, dict):
                raise ValueError(f"Line {line_number} is not a JSON object")
            yield input_format, line_number, alert


def parse_timestamp(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    return datetime.fromisoformat(normalized)


def truncate_datetime(value: datetime, resolution: str) -> datetime:
    if resolution == "day":
        return value.replace(hour=0, minute=0, second=0, microsecond=0)
    if resolution == "hour":
        return value.replace(minute=0, second=0, microsecond=0)
    if resolution == "minute":
        return value.replace(second=0, microsecond=0)
    raise ValueError(f"Unsupported resolution: {resolution}")


def percentile(sorted_values: list[float], fraction: float) -> float:
    if not sorted_values:
        raise ValueError("percentile() requires at least one value")
    if len(sorted_values) == 1:
        return sorted_values[0]
    position = (len(sorted_values) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return sorted_values[lower]
    lower_value = sorted_values[lower]
    upper_value = sorted_values[upper]
    return lower_value + (upper_value - lower_value) * (position - lower)


def build_summary(values: list[float]) -> SummaryStats:
    if not values:
        raise ValueError("No values available to summarize")
    ordered = sorted(values)
    return SummaryStats(
        count=len(ordered),
        min_seconds=ordered[0],
        mean_seconds=sum(ordered) / len(ordered),
        p50_seconds=percentile(ordered, 0.50),
        p90_seconds=percentile(ordered, 0.90),
        p95_seconds=percentile(ordered, 0.95),
        p99_seconds=percentile(ordered, 0.99),
        max_seconds=ordered[-1],
    )


def build_bucket_summaries(
    bucket_values: dict[datetime, list[float]]
) -> list[BucketSummary]:
    summaries: list[BucketSummary] = []
    for bucket_start, values in sorted(bucket_values.items()):
        ordered = sorted(values)
        summaries.append(
            BucketSummary(
                bucket_start=bucket_start.isoformat(),
                count=len(ordered),
                min_seconds=ordered[0],
                mean_seconds=sum(ordered) / len(ordered),
                p50_seconds=percentile(ordered, 0.50),
                p95_seconds=percentile(ordered, 0.95),
                p99_seconds=percentile(ordered, 0.99),
                max_seconds=ordered[-1],
            )
        )
    return summaries


def delay_band_label(delay_seconds: float) -> str:
    for label, lower, upper in DELAY_BANDS:
        if lower is None and delay_seconds < upper:
            return label
        if upper is None and delay_seconds >= lower:
            return label
        if lower is not None and upper is not None and lower <= delay_seconds < upper:
            return label
    return "unclassified"


def ellipsize(text: str, width: int) -> str:
    if width <= 3 or len(text) <= width:
        return text
    return text[: width - 3] + "..."


def print_summary_stats(summary: SummaryStats):
    print("Overall delay statistics (CreateTime - StartTime, in seconds)")
    print(f"  alerts: {summary.count:,}")
    print(f"  min_s:  {summary.min_seconds:.6f}")
    print(f"  mean_s: {summary.mean_seconds:.6f}")
    print(f"  p50_s:  {summary.p50_seconds:.6f}")
    print(f"  p90_s:  {summary.p90_seconds:.6f}")
    print(f"  p95_s:  {summary.p95_seconds:.6f}")
    print(f"  p99_s:  {summary.p99_seconds:.6f}")
    print(f"  max_s:  {summary.max_seconds:.6f}")


def print_delay_bands(band_counts: dict[str, int], total: int):
    print("\nDelay bands")
    for label, _, _ in DELAY_BANDS:
        count = band_counts.get(label, 0)
        percentage = (count / total * 100) if total else 0.0
        print(f"  {label:>8}: {count:>9,}  ({percentage:6.2f}%)")


def print_top_alerts(top_alerts: list[AlertDelayRecord], description_width: int):
    if not top_alerts:
        return
    print("\nLargest per-alert delays")
    for rank, item in enumerate(top_alerts, start=1):
        description = ellipsize(item.description.replace("\n", " "), description_width)
        print(
            f"  {rank:>2}. delay_s={item.delay_seconds:>12.6f} "
            f"record={item.record_number:<8} severity={item.severity or '-':<6} "
            f"id={item.alert_id or '-'}"
        )
        print(
            f"      start={item.start_time} create={item.create_time} "
            f"description={description}"
        )


def print_bucket_table(rows: list[BucketSummary]):
    if not rows:
        print("  no buckets")
        return
    header = (
        f"{'bucket_start':<25} {'count':>8} {'min_s':>12} {'mean_s':>12} "
        f"{'p50_s':>12} {'p95_s':>12} {'p99_s':>12} {'max_s':>12}"
    )
    print(header)
    print("-" * len(header))
    for row in rows:
        print(
            f"{row.bucket_start:<25} {row.count:>8,} "
            f"{row.min_seconds:>12.3f} {row.mean_seconds:>12.3f} "
            f"{row.p50_seconds:>12.3f} {row.p95_seconds:>12.3f} "
            f"{row.p99_seconds:>12.3f} {row.max_seconds:>12.3f}"
        )


def print_resolution_summary(
    resolution: str,
    rows: list[BucketSummary],
    print_limit: int,
    top_buckets: int,
    csv_path: Path | None,
):
    print(f"\nBy {resolution}")
    if not rows:
        print("  no data")
        return

    first_row = rows[0]
    last_row = rows[-1]
    print(
        f"  buckets: {len(rows):,}; first={first_row.bucket_start}; "
        f"last={last_row.bucket_start}"
    )
    print(
        f"  first mean/p50/p95: {first_row.mean_seconds:.3f} / "
        f"{first_row.p50_seconds:.3f} / {first_row.p95_seconds:.3f} seconds"
    )
    print(
        f"  last  mean/p50/p95: {last_row.mean_seconds:.3f} / "
        f"{last_row.p50_seconds:.3f} / {last_row.p95_seconds:.3f} seconds"
    )
    if csv_path is not None:
        print(f"  csv: {csv_path}")

    if len(rows) <= print_limit:
        print_bucket_table(rows)
        return

    worst_rows = sorted(
        rows,
        key=lambda row: (row.p95_seconds, row.max_seconds, row.mean_seconds),
        reverse=True,
    )[:top_buckets]
    recent_rows = rows[-top_buckets:]

    print(f"  {len(rows):,} buckets exceed --print-limit={print_limit}.")
    print(f"  Worst {len(worst_rows)} buckets by p95_s")
    print_bucket_table(sorted(worst_rows, key=lambda row: row.bucket_start))
    print(f"\n  Most recent {len(recent_rows)} buckets")
    print_bucket_table(recent_rows)


def write_bucket_csv(path: Path, rows: list[BucketSummary]):
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "bucket_start",
                "count",
                "min_s",
                "mean_s",
                "p50_s",
                "p95_s",
                "p99_s",
                "max_s",
            ]
        )
        for row in rows:
            writer.writerow(
                [
                    row.bucket_start,
                    row.count,
                    f"{row.min_seconds:.6f}",
                    f"{row.mean_seconds:.6f}",
                    f"{row.p50_seconds:.6f}",
                    f"{row.p95_seconds:.6f}",
                    f"{row.p99_seconds:.6f}",
                    f"{row.max_seconds:.6f}",
                ]
            )


def write_top_alerts_csv(path: Path, rows: list[AlertDelayRecord]):
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "record_number",
                "alert_id",
                "severity",
                "create_time",
                "start_time",
                "delay_s",
                "description",
            ]
        )
        for row in rows:
            writer.writerow(
                [
                    row.record_number,
                    row.alert_id,
                    row.severity,
                    row.create_time,
                    row.start_time,
                    f"{row.delay_seconds:.6f}",
                    row.description,
                ]
            )


def ensure_output_dir(output_dir: str) -> Path | None:
    if not output_dir:
        return None
    path = Path(output_dir).expanduser().resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


def main() -> int:
    args = parse_args()
    alerts_path = Path(args.alerts_path).expanduser().resolve()
    if not alerts_path.exists():
        print(f"alerts file not found: {alerts_path}", file=sys.stderr)
        return 1

    resolutions = tuple(args.resolution or DEFAULT_RESOLUTIONS)
    output_dir = ensure_output_dir(args.output_dir)

    overall_delays: list[float] = []
    bucket_values = {
        resolution: defaultdict(list) for resolution in resolutions
    }
    band_counts: dict[str, int] = defaultdict(int)
    top_delay_records: list[AlertDelayRecord] = []
    skipped_missing_timestamps = 0
    skipped_invalid_timestamps = 0
    negative_count = 0
    zero_count = 0
    trend_min: datetime | None = None
    trend_max: datetime | None = None
    input_format: str | None = None

    for current_format, record_number, alert in iter_alert_records(alerts_path):
        input_format = current_format
        create_time_raw = alert.get("CreateTime")
        start_time_raw = alert.get("StartTime")
        if not create_time_raw or not start_time_raw:
            skipped_missing_timestamps += 1
            continue

        try:
            create_time = parse_timestamp(create_time_raw)
            start_time = parse_timestamp(start_time_raw)
        except ValueError:
            skipped_invalid_timestamps += 1
            continue

        delay_seconds = (create_time - start_time).total_seconds()
        overall_delays.append(delay_seconds)
        band_counts[delay_band_label(delay_seconds)] += 1
        if delay_seconds < 0:
            negative_count += 1
        elif delay_seconds == 0:
            zero_count += 1

        top_delay_records.append(
            AlertDelayRecord(
                record_number=record_number,
                alert_id=str(alert.get("ID") or ""),
                severity=str(alert.get("Severity") or ""),
                create_time=create_time_raw,
                start_time=start_time_raw,
                delay_seconds=delay_seconds,
                description=str(alert.get("Description") or ""),
            )
        )

        trend_time = create_time if args.bucket_time == "create" else start_time
        if trend_min is None or trend_time < trend_min:
            trend_min = trend_time
        if trend_max is None or trend_time > trend_max:
            trend_max = trend_time
        for resolution in resolutions:
            bucket_values[resolution][
                truncate_datetime(trend_time, resolution)
            ].append(delay_seconds)

    if not overall_delays:
        print(
            (
                "No alerts with valid CreateTime and StartTime were found in "
                f"{alerts_path}"
            ),
            file=sys.stderr,
        )
        return 1

    overall_summary = build_summary(overall_delays)
    top_delay_records = sorted(
        top_delay_records,
        key=lambda item: item.delay_seconds,
        reverse=True,
    )[: args.top_alerts]
    bucket_summaries = {
        resolution: build_bucket_summaries(bucket_values[resolution])
        for resolution in resolutions
    }

    csv_paths: dict[str, str] = {}
    if output_dir is not None:
        for resolution in resolutions:
            csv_path = output_dir / f"alert_creation_delay_by_{resolution}.csv"
            write_bucket_csv(csv_path, bucket_summaries[resolution])
            csv_paths[resolution] = str(csv_path)

        top_alerts_csv = output_dir / "alert_creation_delay_top_alerts.csv"
        write_top_alerts_csv(top_alerts_csv, top_delay_records)
        csv_paths["top_alerts"] = str(top_alerts_csv)

        summary_json = output_dir / "summary.json"
        summary_payload = {
            "alerts_path": str(alerts_path),
            "input_format": input_format,
            "bucket_time": args.bucket_time,
            "resolutions": list(resolutions),
            "processed_alerts": overall_summary.count,
            "skipped_missing_timestamps": skipped_missing_timestamps,
            "skipped_invalid_timestamps": skipped_invalid_timestamps,
            "negative_delays": negative_count,
            "zero_delays": zero_count,
            "trend_start": trend_min.isoformat() if trend_min else None,
            "trend_end": trend_max.isoformat() if trend_max else None,
            "overall_delay_seconds": asdict(overall_summary),
            "delay_bands": [
                {
                    "label": label,
                    "count": band_counts.get(label, 0),
                    "percentage": (
                        band_counts.get(label, 0) / overall_summary.count * 100
                    ),
                }
                for label, _, _ in DELAY_BANDS
            ],
            "top_delays": [asdict(item) for item in top_delay_records],
            "csv_outputs": csv_paths,
            "bucket_counts": {
                resolution: len(bucket_summaries[resolution])
                for resolution in resolutions
            },
        }
        with summary_json.open("w", encoding="utf-8") as handle:
            json.dump(summary_payload, handle, indent=2)
            handle.write("\n")
        csv_paths["summary_json"] = str(summary_json)

    print(f"Input: {alerts_path}")
    print(f"Input format: {input_format}")
    print(f"Trend bucket timestamp: {args.bucket_time} time")
    print(
        f"Valid alerts: {overall_summary.count:,}; skipped missing timestamps: "
        f"{skipped_missing_timestamps:,}; skipped invalid timestamps: "
        f"{skipped_invalid_timestamps:,}"
    )
    if trend_min is not None and trend_max is not None:
        print(f"Trend range: {trend_min.isoformat()} -> {trend_max.isoformat()}")
    print(
        f"Negative delays: {negative_count:,}; zero delays: {zero_count:,}"
    )
    print_summary_stats(overall_summary)
    print_delay_bands(band_counts, overall_summary.count)
    print_top_alerts(top_delay_records, args.description_width)

    for resolution in resolutions:
        csv_path = Path(csv_paths[resolution]) if resolution in csv_paths else None
        print_resolution_summary(
            resolution=resolution,
            rows=bucket_summaries[resolution],
            print_limit=args.print_limit,
            top_buckets=args.top_buckets,
            csv_path=csv_path,
        )

    if output_dir is not None:
        print(f"\nArtifacts written to: {output_dir}")
        print(f"Summary JSON: {csv_paths['summary_json']}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
