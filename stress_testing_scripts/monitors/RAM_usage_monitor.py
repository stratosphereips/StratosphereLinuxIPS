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


def get_process_tree_ram_gb(parent_pid: int) -> float:
    """
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


def get_redis_memory(redis_port: int):
    """
    Extracts Redis memory stats from `redis-cli info memory`.

    Returns:
        tuple(float used_memory_rss_GB, float used_memory_GB)
    """
    out = subprocess.check_output(
        ["redis-cli", "-p", str(redis_port), "info", "memory"],
        text=True,
    )

    rss = None
    used = None

    for line in out.splitlines():
        if line.startswith("used_memory_rss_human:"):
            rss = line.split(":")[1].strip()
        if line.startswith("used_memory_human:"):
            used = line.split(":")[1].strip()

    def human_to_gb(value: str):
        num = float(re.findall(r"[0-9.]+", value)[0])
        if value.endswith("G"):
            return num
        if value.endswith("M"):
            return num / 1024
        if value.endswith("K"):
            return num / (1024 * 1024)
        return num

    return human_to_gb(rss), human_to_gb(used)


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
    last_slips = 0
    minute_counter = 0

    while True:
        now = time.time()

        # log  RAM usage every 3 minutes
        if now - last_slips >= 180:
            # Redis log every minute
            rss, used = get_redis_memory(redis_port)
            with open(redis_csv, "a", newline="") as f:
                row = [minute_counter, rss, used]
                log_row(row)
                csv.writer(f).writerow(row)

            minute_counter += 1

            ram_gb = get_process_tree_ram_gb(parent_pid)

            with open(slips_csv, "a", newline="") as f:
                row = [int(now - start), ram_gb]
                log_row(row)
                csv.writer(f).writerow(row)

            last_slips = now

        time.sleep(60)


if __name__ == "__main__":
    main()
