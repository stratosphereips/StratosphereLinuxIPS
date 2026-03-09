#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path

import matplotlib.pyplot as plt


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Plot number of flows over time from a Zeek conn.log (JSON lines)."
        )
    )
    parser.add_argument(
        "--conn-log",
        type=Path,
        help="Path to conn.log (JSON lines).",
    )
    parser.add_argument(
        "--bin-size",
        type=float,
        default=1.0,
        help="Bin size in seconds for counting flows.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional output image path (e.g., flows_over_time.png).",
    )
    return parser.parse_args()


def load_timestamps(conn_log: Path) -> list[float]:
    timestamps: list[float] = []
    with conn_log.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = entry.get("ts")
            if isinstance(ts, (int, float)):
                timestamps.append(float(ts))
    return timestamps


def bin_counts(
    timestamps: list[float], bin_size: float
) -> tuple[list[float], list[int]]:
    start = min(timestamps)
    counts: dict[int, int] = {}
    for ts in timestamps:
        offset = ts - start
        bin_index = int(math.floor(offset / bin_size))
        counts[bin_index] = counts.get(bin_index, 0) + 1

    bins = sorted(counts)
    x_vals = [b * bin_size for b in bins]
    y_vals = [counts[b] for b in bins]
    return x_vals, y_vals


def main() -> None:
    args = parse_args()
    if args.bin_size <= 0:
        raise SystemExit("--bin-size must be positive")

    timestamps = load_timestamps(args.conn_log)
    if not timestamps:
        raise SystemExit(f"No timestamps found in {args.conn_log}")

    x_vals, y_vals = bin_counts(timestamps, args.bin_size)

    plt.figure(figsize=(12, 6))
    plt.step(x_vals, y_vals, where="post", linewidth=1.5)
    plt.xlabel("Time since first flow (seconds)")
    plt.ylabel("Number of flows per bin")
    plt.title(f"Flows over time (bin size = {args.bin_size}s)")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()

    if args.output:
        plt.savefig(args.output, dpi=150)
    else:
        plt.show()


if __name__ == "__main__":
    main()
