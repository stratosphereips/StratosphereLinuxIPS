#!/usr/bin/env python3
"""
CPU Usage Monitor

Monitors CPU usage of a parent process and all its children.

Method:
- Uses pstree to collect all PIDs in the process tree.
- Uses `ps -o %cpu` to retrieve CPU usage.
- Sums CPU percentages.

Output:
- slips_CPU_usage.csv
    columns: ts, cpu_usage_of_slips_and_all_children_percent

Sampling interval:
- every 1 minute

Usage:
    python cpu_monitor.py <parent_pid> <output_dir>
"""

import csv
import re
import subprocess
import sys
import time
from pathlib import Path


def get_process_tree_cpu(parent_pid: int) -> float:
    """
    Returns total CPU usage (%) of a process tree.

    Equivalent shell logic:

        pstree -p <PID> |
        grep -o '[0-9]\+' |
        xargs ps -o %cpu= -p |
        awk '{sum+=$1} END {print sum}'
    """
    pstree = subprocess.check_output(
        ["pstree", "-p", str(parent_pid)], text=True
    )

    pids = re.findall(r"\d+", pstree)
    if not pids:
        return 0.0

    ps = subprocess.check_output(
        ["ps", "-o", "%cpu=", "-p", ",".join(pids)],
        text=True,
    )

    return sum(float(x) for x in ps.split() if x.strip())


def main():
    if len(sys.argv) != 3:
        print("Usage: python cpu_monitor.py <parent_pid> <output_dir>")
        sys.exit(1)

    parent_pid = int(sys.argv[1])
    outdir = Path(sys.argv[2])
    outdir.mkdir(parents=True, exist_ok=True)

    csv_path = outdir / "slips_CPU_usage.csv"

    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["ts", "cpu_usage_of_slips_and_all_children_percent"])

    start = time.time()

    while True:
        cpu = get_process_tree_cpu(parent_pid)

        with open(csv_path, "a", newline="") as f:
            csv.writer(f).writerow([int(time.time() - start), cpu])

        time.sleep(60 * 2)


if __name__ == "__main__":
    main()
