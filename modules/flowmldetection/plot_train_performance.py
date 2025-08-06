import argparse
import os
import re
import sys
from collections import defaultdict

from base_utils import (
    compute_binary_metrics,
    compute_multiclass_metrics,
    extract_braced_dict,
    print_and_save_summary,
    process_file,
    safe_eval_dict,
)
from matplotlib import pyplot as plt


def parse_metrics_line(line: str) -> dict:
    """
    Parses lines with:
    Total labels: 992.0, Testing size: 56, Seen labels: {...}, Predicted labels: {...}, Per-class metrics: {...}
    """
    total_match = re.search(r"Testing size:\s*(\d+)", line)
    seen_dict_str = extract_braced_dict(line, "Seen labels:")
    pred_dict_str = extract_braced_dict(line, "Predicted labels:")
    per_class_dict_str = extract_braced_dict(line, "Per-class metrics:")

    if not (
        total_match and seen_dict_str and pred_dict_str and per_class_dict_str
    ):
        raise ValueError("Line missing one of required components")

    total = int(total_match.group(1))
    seen = safe_eval_dict(seen_dict_str)
    pred = safe_eval_dict(pred_dict_str)
    cls_metrics = safe_eval_dict(per_class_dict_str)

    return {
        "total": total,
        "seen_labels": seen,
        "pred_labels": pred,
        "class_metrics": cls_metrics,
    }


def plot_metrics(metrics: dict, exp: str, training_dir: str) -> None:

    def plot_metrics(metrics: dict, exp: str, training_dir: str) -> None:
        # Initialize data structures
        data_seen = 0
        x_points = []
        binary_metrics = defaultdict(list)
        multiclass_metrics = defaultdict(list)

        # Process each batch
        for batch_metrics in metrics:
            data_seen += batch_metrics["total"]
            x_points.append(data_seen)

            # Calculate and store metrics
            if len(batch_metrics["class_metrics"]) == 2:
                bin_results = compute_binary_metrics(
                    batch_metrics["seen_labels"], batch_metrics["pred_labels"]
                )
                for key, value in bin_results.items():
                    binary_metrics[key].append(value)
            else:
                multi_results = compute_multiclass_metrics(
                    batch_metrics["seen_labels"], batch_metrics["pred_labels"]
                )
                for key, value in multi_results.items():
                    multiclass_metrics[key].append(value)

        # Plot metrics
        metrics_to_plot = (
            binary_metrics if binary_metrics else multiclass_metrics
        )
        plt.figure(figsize=(10, 6))
        for metric_name, values in metrics_to_plot.items():
            plt.plot(x_points, values, label=metric_name)

        plt.xlabel("Number of samples seen")
        plt.ylabel("Metric value")
        plt.title(f"Training Performance - {exp}")
        plt.legend()
        plt.grid(True)
        plt.savefig(os.path.join(training_dir, f"{exp}_training_metrics.png"))
        plt.close()


def main():
    parser = argparse.ArgumentParser(
        description="Plot training performance metrics."
    )
    parser.add_argument(
        "-f", "--file", required=True, help="Path to training log file"
    )
    parser.add_argument(
        "-e", "--exp", required=True, help="Experiment identifier"
    )
    args = parser.parse_args()

    if not args.file.endswith(".log"):
        args.file = os.path.join(args.file, "training.log")
    if not os.path.isfile(args.file):
        raise FileNotFoundError(f"Log file not found: {args.file}")

    base_dir = "performance_metrics"
    training_dir = os.path.join(base_dir, "training")
    os.makedirs(training_dir, exist_ok=True)

    data = process_file(args.file, parse_metrics_line)
    plot_metrics(data["metrics"], args.exp, training_dir)
    print_and_save_summary(
        data["metrics"], data["counters"], args.exp, training_dir
    )


if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(__file__))
    main()
