#!/usr/bin/env python3
"""
RAM Usage Monitor

This script monitors RAM usage for:
1. A parent process and all its children (using pstree + ps).
2. Redis memory usage (using redis-cli info memory).

Outputs:
- slips_RAM_usage.csv
    columns: ts, ram_usage_of_slips_and_all_children_in_GBs
    sampling interval: every 3 minutes

- redis_RAM_usage.csv
    columns: minute_ts, used_memory_rss_GB, used_memory_GB
    sampling interval: every 1 minute

Usage:
    python ram_monitor.py <parent_pid> <output_dir> <redis_port>
"""

import csv
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional


def get_process_tree_ram_gb(parent_pid: int) -> float:
    r"""
    Returns the RAM usage of a process tree in GB.

    The function replicates the following shell pipeline:

        pstree -p <PID> |
        grep -o '[0-9]\+' |
        xargs ps -o rss= -p |
        awk '{sum+=$1} END {print sum}'

    rss is returned in KB by ps, so it is converted to GB.
    """
    pstree = subprocess.check_output(
        ["pstree", "-p", str(parent_pid)], text=True
    )

    pids = re.findall(r"\d+", pstree)
    if not pids:
        return 0.0

    ps = subprocess.check_output(
        ["ps", "-o", "rss=", "-p", ",".join(pids)],
        text=True,
    )

    total_kb = sum(int(x) for x in ps.split() if x.strip())
    return total_kb / (1024 * 1024)


def get_redis_memory(
    redis_port: int,
) -> tuple[Optional[float], Optional[float]]:
    """
    Extracts Redis memory stats from `redis-cli info memory`.

    Returns:
        tuple(float used_memory_rss_GB, float used_memory_GB)
    """
    try:
        out = subprocess.check_output(
            ["redis-cli", "-p", str(redis_port), "info", "memory"],
            text=True,
            stderr=subprocess.STDOUT,
        )
    except subprocess.CalledProcessError as exc:
        print(
            f"{datetime.now().isoformat()} redis-cli failed on port "
            f"{redis_port}: {exc.output.strip()}",
            file=sys.stderr,
        )
        return None, None

    rss_bytes: Optional[int] = None
    used_bytes: Optional[int] = None

    for line in out.splitlines():
        if line.startswith("used_memory_rss:"):
            rss_bytes = int(line.split(":", 1)[1].strip())
        elif line.startswith("used_memory:"):
            used_bytes = int(line.split(":", 1)[1].strip())

    if rss_bytes is None or used_bytes is None:
        print(
            f"{datetime.now().isoformat()} unable to parse Redis memory "
            f"stats on port {redis_port}",
            file=sys.stderr,
        )
        return None, None

    bytes_per_gb = 1024 * 1024 * 1024
    return rss_bytes / bytes_per_gb, used_bytes / bytes_per_gb


def main():
    if len(sys.argv) != 4:
        print(
            "Usage: python ram_monitor.py <parent_pid> <output_dir> <redis_port>"
        )
        sys.exit(1)

    parent_pid = int(sys.argv[1])
    outdir = Path(sys.argv[2])
    redis_port = int(sys.argv[3])
    outdir.mkdir(parents=True, exist_ok=True)

    slips_csv = outdir / "slips_RAM_usage.csv"
    redis_csv = outdir / "redis_RAM_usage.csv"

    def log_row(row):
        ts = datetime.now().isoformat()
        print(f"{ts} {row}")

    with open(slips_csv, "w", newline="") as f:
        writer = csv.writer(f)
        header = ["ts", "ram_usage_of_slips_and_all_children_in_GBs"]
        log_row(header)
        writer.writerow(header)

    with open(redis_csv, "w", newline="") as f:
        writer = csv.writer(f)
        header = ["minute_ts", "used_memory_rss_GB", "used_memory_GB"]
        log_row(header)
        writer.writerow(header)

    start = time.time()
    last_slips = 0.0
    last_redis = 0.0
    minute_counter = 0

    while True:
        now = time.time()

        if now - last_redis >= 60:
            rss, used = get_redis_memory(redis_port)
            with open(redis_csv, "a", newline="") as f:
                row = [minute_counter, rss, used]
                log_row(row)
                csv.writer(f).writerow(row)

            minute_counter += 1
            last_redis = now

        # Log RAM usage every 3 minutes.
        if now - last_slips >= 180:
            ram_gb = get_process_tree_ram_gb(parent_pid)

            with open(slips_csv, "a", newline="") as f:
                row = [int(now - start), ram_gb]
                log_row(row)
                csv.writer(f).writerow(row)

            last_slips = now

        time.sleep(60)


if __name__ == "__main__":
    main()
