#!/usr/bin/env python3
"""
Plot RAM and CPU usage metrics from Slips experiment outputs.

Expected files inside the input directory:
    redis_RAM_usage.csv
    slips_CPU_usage.csv
    slips_RAM_usage.csv

The script generates a single plot with:
    - Redis RAM usage
    - Slips RAM usage
    - Slips CPU usage

Usage:
    python plot_metrics.py --input-dir <dir> --output <output_png>
"""

import argparse
import csv
import os
from typing import List, Tuple

import matplotlib.pyplot as plt


def parse_csv(file_path: str) -> Tuple[List[float], List[float]]:
    """
    Parse a CSV file containing timestamp and value columns.

    The function tolerates:
        - optional headers
        - malformed rows
        - extra columns

    Returns
    -------
    Tuple[List[float], List[float]]
        timestamps, values
    """
    ts = []
    vals = []

    with open(file_path, "r") as f:
        reader = csv.reader(f)

        for row in reader:
            if not row:
                continue

            try:
                t = float(row[0])
                v = float(row[1])
            except (ValueError, IndexError):
                # skip header or malformed rows
                continue

            ts.append(t)
            vals.append(v)

    return ts, vals


def plot_metrics(input_dir: str, output_path: str) -> None:
    """
    Load the 3 CSV files and generate a single plot.

    Parameters
    ----------
    input_dir : str
        Directory containing the CSV files.
    output_path : str
        Path where the plot image will be saved.
    """

    files = {
        "redis_RAM_usage.csv": "Redis RAM (GB)",
        "slips_RAM_usage.csv": "Slips RAM (GB)",
        # "slips_CPU_usage.csv": "Slips CPU (%)",
    }

    plt.figure(figsize=(10, 6))

    for filename, label in files.items():
        path = os.path.join(input_dir, filename)

        if not os.path.exists(path):
            print(f"Skipping missing file: {path}")
            continue

        ts, vals = parse_csv(path)
        plt.plot(ts, vals, label=label)

    plt.xlabel("Time (s)")
    plt.ylabel("Usage")
    plt.title("Slips Resource Usage")
    plt.legend()
    plt.grid(True)

    plt.tight_layout()
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    plt.savefig(output_path)
    print(f"Plot saved to {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="Plot Slips experiment metrics"
    )

    parser.add_argument(
        "--input-dir",
        required=True,
        help="Directory containing redis_RAM_usage.csv, slips_CPU_usage.csv, slips_RAM_usage.csv",
    )

    parser.add_argument(
        "--output",
        required=True,
        help="Path to save the generated plot (e.g., plot.png)",
    )

    args = parser.parse_args()

    plot_metrics(args.input_dir, args.output)


if __name__ == "__main__":
    main()
