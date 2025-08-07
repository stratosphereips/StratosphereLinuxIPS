# plot_test_performance.py

import argparse
import os

import matplotlib.pyplot as plt
from base_utils import (
    compute_binary_metrics,
    compute_multi_metrics,
    ensure_dir,
    parse_testing_log_line,
)


def read_all_tests(logfile):
    entries = []
    with open(logfile) as f:
        for line in f:
            if not line.strip():
                continue
            try:
                data = parse_testing_log_line(line)
                entries.append(data)
            except Exception:
                continue
    return entries


def accumulate_test_metrics(entries):
    """
    Build per-step lists of TP/FP/TN/FN per class and multi metrics.
    """
    per_class_series = []
    multi_series = []
    binary_series = []
    for data in entries:
        pcm = data["per_class"]  # per class metrics
        # unpack for each class, compute metrics and add them to TP, TN etc.
        over_classes = {}
        for cls, metrics in pcm.items():
            metrics_for_class = compute_binary_metrics(metrics)
            metrics_for_class.update(metrics)  # include raw counts
            over_classes[cls] = metrics_for_class
        per_class_series.append(over_classes)

        # compute multi-class metrics at this step
        multi_series.append(compute_multi_metrics(pcm))

        binary_m = data["binary_summary"]
        binary_series.append(compute_binary_metrics(binary_m))

    return per_class_series, multi_series, binary_series


def plot_major_metrics_together(series, outpath, title="Metrics over tests"):
    if series is None or not series or series == []:
        print("No data to plot for", title)
        return
    what_metrics = series[0].keys()
    print_dict = {metric: [] for metric in what_metrics}
    for metric in what_metrics:
        metric_values = [s[metric] for s in series]
        print_dict[metric] = metric_values

    plt.figure()
    for metric, values in print_dict.items():
        plt.plot(range(1, len(values) + 1), values, label=metric)
    plt.xlabel("Test #")
    plt.ylabel("Value")

    # Dynamically adjust y-axis limits to zoom in if possible
    all_values = [v for values in print_dict.values() for v in values]
    min_val = min(all_values)
    max_val = max(all_values)
    margin = 0.05 * (max_val - min_val) if max_val > min_val else 0.05
    lower = max(0, min_val - margin)
    upper = min(1, max_val + margin)
    if upper - lower < 0.5:
        plt.ylim(lower, upper)
    else:
        plt.ylim(0, 1)
    plt.title(title)
    plt.legend()
    plt.tight_layout()
    plt.savefig(outpath)
    plt.close()


def plot_metric_types_over_classes(per_class_series, testing_dir):
    metrics_types = ["TP", "FP", "TN", "FN"]
    for metric in metrics_types:
        plt.figure()
        for cls in per_class_series[0].keys():
            plt.plot([m[cls][metric] for m in per_class_series], label=cls)
        plt.xlabel("Test #")
        plt.ylabel(f"{metric} Count (log scale)")
        plt.yscale("log")
        plt.title(f"{metric} over tests for all classes")
        plt.legend()
        plt.tight_layout()
        plt.savefig(os.path.join(testing_dir, f"all_classes_{metric}_log.png"))
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

    base_dir = ensure_dir("performance_metrics")
    testing_dir = ensure_dir(os.path.join(base_dir, "testing", args.exp))

    entries = read_all_tests(args.file)
    per_class_series, multi_series, binary_series = accumulate_test_metrics(
        entries
    )

    # Plot TP/FP/TN/FN for all classes in one image per metric, log scale on y axis
    print(
        "Plotting TP/FP/TN/FN for all classes (one plot per metric, log scale)..."
    )
    plot_metric_types_over_classes(per_class_series, testing_dir)

    # Plot accuracy, precision, recall, and f1 for all classes in separate images
    print(
        "Plotting per-class main metrics (accuracy, precision, recall, f1)..."
    )
    selected_per_class = ["accuracy", "precision", "recall", "f1"]
    for metric in selected_per_class:
        per_class_flattened = []
        for entry in per_class_series:
            flat = {}
            for cls, metrics in entry.items():
                flat[f"{cls}"] = metrics.get(metric, 0)
            per_class_flattened.append(flat)
        plot_major_metrics_together(
            per_class_flattened,
            os.path.join(testing_dir, f"per_class_{metric}_main_metrics.png"),
            title=f"Per-class {metric.capitalize()} over test instances",
        )

    # Plot micro/macro F1 and accuracy
    print("Plotting multi-class metrics...")
    plot_major_metrics_together(
        multi_series,
        os.path.join(testing_dir, "multiclass_main_metrics.png"),
        title="Multiticlass Metrics over test instances",
    )

    # Plot binary metrics for malicious/benign
    print("Plotting binary metrics (Benign/Malicious)...")
    plot_major_metrics_together(
        binary_series,
        os.path.join(testing_dir, "binary_benign_malicious_main_metrics.png"),
        title="Binary Metrics over test instances",
    )

    # Print final summary
    last = multi_series[-1]
    lines = []
    lines.append("\n=== Multi-class ===")
    lines.append(f"Accuracy: {last.get('accuracy', 0):.4f}")
    lines.append(f"Macro Precision: {last.get('macro_precision', 0):.4f}")
    lines.append(f"Macro Recall:    {last.get('macro_recall', 0):.4f}")
    lines.append(f"Macro F1:        {last.get('macro_f1', 0):.4f}")
    lines.append(f"Micro Precision: {last.get('micro_precision', 0):.4f}")
    lines.append(f"Micro Recall:    {last.get('micro_recall', 0):.4f}")
    lines.append(f"Micro F1:        {last.get('micro_f1', 0):.4f}")

    # Per-class metrics
    lines.append("\n=== Per-class metrics ===")
    final_per_class = per_class_series[-1]
    lines.append(
        f"{'Class':<15} {'TP':>8} {'TN':>8} {'FP':>8} {'FN':>8} {'Acc':>8} {'Prec':>8} {'Rec':>8}"
    )
    for cls, m in final_per_class.items():
        lines.append(
            f"{cls:<15} {m.get('TP', 0):8d} {m.get('TN', 0):8d} {m.get('FP', 0):8d} {m.get('FN', 0):8d} "
            f"{m.get('accuracy', 0.0):8.4f} {m.get('precision', 0.0):8.4f} {m.get('recall', 0.0):8.4f}"
        )

    # Binary summary
    lines.append("\n=== Binary summary (Benign/Malicious) ===")
    last_binary = binary_series[-1]
    lines.append(f"Accuracy: {last_binary.get('accuracy', 0):.4f}")
    lines.append(f"Precision: {last_binary.get('precision', 0):.4f}")
    lines.append(f"Recall:    {last_binary.get('recall', 0):.4f}")
    lines.append(f"F1:        {last_binary.get('f1', 0):.4f}")

    lines.append(f"\nSummary for Experiment {args.exp}:")
    lines.append(f"Total tests processed: {len(entries)}")
    print("\n".join(lines))

    # Save summary to file in the same directory as the plots
    summary_path = os.path.join(testing_dir, "summary.txt")
    summary_text = "\n".join(lines)
    with open(summary_path, "w") as f:
        f.write(summary_text)
    print(summary_text)


if __name__ == "__main__":
    main()
