import argparse
import os
import re
import sys
from collections import Dict, List

from base_utils import (
    extract_braced_dict,
    print_and_save_summary,
    process_file,
    safe_eval_dict,
)
from matplotlib import pyplot as plt


def parse_metrics_line(line: str) -> dict:
    """
    Parses lines with format:
    Total flows: 123, Seen labels: {...}, Predicted labels: {...}, Per-class metrics: {...}
    """
    total_match = re.search(r"Total flows:\s*(\d+)", line)
    seen_dict_str = extract_braced_dict(line, "Seen labels:")
    pred_dict_str = extract_braced_dict(line, "Predicted labels:")
    per_class_dict_str = extract_braced_dict(line, "Per-class metrics:")

    if not (
        total_match and seen_dict_str and pred_dict_str and per_class_dict_str
    ):
        raise ValueError(
            "Line missing one of Total/Seen/Predicted/Per-class sections"
        )

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


def plot_metrics(
    metrics: Dict[str, List[Dict[str, float]]], exp: str, testing_dir: str
) -> None:
    exp_dir = os.path.join(testing_dir, exp)
    os.makedirs(exp_dir, exist_ok=True)
    # Get all classes from the first entry's class metrics
    classes = list(metrics["overall"][0]["class_metrics"].keys())

    # Plot for each class and overall
    for category in classes + ["overall"]:
        entries = (
            metrics["overall"] if category == "overall" else metrics["overall"]
        )
        close0 = {"FPR": [], "FNR": []}
        close1 = {
            "TPR": [],
            "TNR": [],
            "precision": [],
            "recall": [],
            "f1": [],
            "accuracy": [],
        }

        for e in entries:
            if category == "overall":
                metrics_data = e
            else:
                metrics_data = e["class_metrics"][category]

            close0["FPR"].append(metrics_data["FPR"])
            close0["FNR"].append(metrics_data["FNR"])
            for k in close1:
                close1[k].append(metrics_data[k])

        # Close to 0
        plt.figure(figsize=(10, 6))
        for m in ("FPR", "FNR"):
            plt.plot(close0[m], label=m, marker="o")
        plt.yscale("linear")
        plt.xlabel("Index")
        plt.ylabel("Value")
        plt.title(f"{category.capitalize()} Metrics Close to 0")
        plt.legend()
        plt.savefig(
            os.path.join(exp_dir, f"{category}_metrics_to_0_{exp}.png")
        )
        plt.close()

        # Close to 1
        plt.figure(figsize=(10, 6))
        for m in ("TPR", "TNR", "precision", "recall", "f1", "accuracy"):
            plt.plot(close1[m], label=m, marker="o")
        plt.yscale("log")
        plt.xlabel("Index")
        plt.ylabel("Value")
        plt.title(f"{category.capitalize()} Metrics Close to 1")
        plt.legend()
        plt.savefig(
            os.path.join(exp_dir, f"{category}_metrics_to_1_{exp}.png")
        )
        plt.close()


def main():
    parser = argparse.ArgumentParser(
        description="Plot testing performance metrics."
    )
    parser.add_argument(
        "-f", "--file", required=True, help="Path to testing log file"
    )
    parser.add_argument(
        "-e", "--exp", required=True, help="Experiment identifier"
    )
    args = parser.parse_args()

    if not args.file.endswith(".log"):
        args.file = os.path.join(args.file, "testing.log")
    if not os.path.isfile(args.file):
        raise FileNotFoundError(f"Log file not found: {args.file}")

    base_dir = "performance_metrics"
    testing_dir = os.path.join(base_dir, "testing")
    os.makedirs(testing_dir, exist_ok=True)

    data = process_file(args.file, parse_metrics_line)
    plot_metrics(data["metrics"], args.exp, testing_dir)
    print_and_save_summary(
        data["metrics"], data["counters"], args.exp, testing_dir
    )


if __name__ == "__main__":
    # Ensure base_utils is importable
    sys.path.insert(0, os.path.dirname(__file__))
    main()
