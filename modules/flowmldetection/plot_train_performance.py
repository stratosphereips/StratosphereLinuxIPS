# plot_train_performance.py

import argparse
import os
import traceback

from base_utils import (
    compute_binary_metrics,
    compute_multi_metrics,
    ensure_dir,
    parse_training_log_line,
    plot_major_metrics_together,
)


def read_all_batches(logfile):
    """Read all lines, return list of parsed dicts."""
    entries = []
    with open(logfile) as f:
        for line in f:
            if not line.strip():
                continue
            try:
                data = parse_training_log_line(line)
                entries.append(data)
            except Exception:
                print(f"Failed to parse line: {line.strip()}")
                traceback.print_exc()
                continue
    return entries


def accumulate_metrics(entries):
    """
    For each batch, compute per-class TP/FP/TN/FN, multi metrics,
    and cumulative metrics up to that batch.
    Returns four lists: batch_metrics_per_class, batch_metrics_multi, cumul_metrics_multi, cumul_metrics_per_class.
    - batch_metrics_per_class: list of dicts, each dict: {class: metrics}
    - batch_metrics_multi: list of overall metrics per batch
    - cumul_metrics_multi: list of overall cumulative metrics
    - cumul_metrics_per_class: list of dicts, each dict: {class: cumulative metrics}
    """
    batch_metrics_per_class = []
    batch_metrics_multi = []
    cumul_metrics_multi = []
    cumul_metrics_per_class = []

    class_names = list(entries[0]["per_class"].keys()) if entries else []
    cumul_class_counters = {
        cls: {"TP": 0, "FP": 0, "TN": 0, "FN": 0} for cls in class_names
    }

    for data in entries:
        per_class = data["per_class"]
        # print(per_class)

        # Store per-batch metrics: {class: metrics}
        # For each class, compute binary metrics for this batch and include raw counts
        batch_metrics_this_batch = {}
        for cls in class_names:
            bin_metrics_per_class = compute_binary_metrics(per_class[cls])
            bin_metrics_per_class.update(per_class[cls])  # include raw counts
            batch_metrics_this_batch[cls] = bin_metrics_per_class
        batch_metrics_per_class.append(batch_metrics_this_batch)

        batch_metrics_multi.append(compute_multi_metrics(per_class))

        # Update cumulative counters per class
        for cls in class_names:
            for k in ["TP", "FP", "TN", "FN"]:
                cumul_class_counters[cls][k] += per_class[cls][k]

        # Compute cumulative binary metrics for each class and store as dict
        cumul_metrics_this_batch = {}
        for cls in class_names:
            bin_metrics_per_class = compute_binary_metrics(
                cumul_class_counters[cls]
            )
            bin_metrics_per_class.update(
                cumul_class_counters[cls]
            )  # include raw counts
            cumul_metrics_this_batch[cls] = bin_metrics_per_class
        cumul_metrics_per_class.append(cumul_metrics_this_batch)

        # Compute cumulative multi-class metrics
        cumul_metrics_multi.append(compute_multi_metrics(cumul_class_counters))

    return (
        batch_metrics_per_class,
        batch_metrics_multi,
        cumul_metrics_multi,
        cumul_metrics_per_class,
    )


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

    base_dir = ensure_dir("performance_metrics")
    training_dir = ensure_dir(os.path.join(base_dir, "training", args.exp))

    entries = read_all_batches(args.file)
    (
        batch_metrics_per_class,
        batch_metrics_multi,
        cumul_metrics_multi,
        cumul_metrics_per_class,
    ) = accumulate_metrics(entries)

    # Calculate cumulative number of samples seen so far for x-axis
    cumulative_sizes = []
    total = 0
    for entry in entries:
        size = entry.get("testing_size", 0)
        total += size
        cumulative_sizes.append(total)

    plot_major_metrics_together(
        batch_metrics_multi,
        os.path.join(training_dir, "per_batch_multiclass_metrics.png"),
        title="Per-batch Multiclass Metrics (by samples)",
        xvals=cumulative_sizes,
    )
    plot_major_metrics_together(
        cumul_metrics_multi,
        os.path.join(training_dir, "cumulative_multiclass_metrics.png"),
        title="Cumulative Multiclass Metrics during training (by samples)",
        xvals=cumulative_sizes,
    )

    print(
        "Plotting per-class batch and cumul. metrics (accuracy, precision, recall, f1)..."
    )
    selected_per_class = ["accuracy", "precision", "recall", "f1"]
    # For each selected metric, plot its evolution for all classes in one image using plot_major_metrics_together
    for metric in selected_per_class:
        per_class_flattened = []
        for entry in cumul_metrics_per_class:
            flat = {}
            for cls in entry.keys():
                flat[cls] = entry[cls].get(metric, 0)
            per_class_flattened.append(flat)
        plot_major_metrics_together(
            per_class_flattened,
            os.path.join(training_dir, f"per_class_{metric}_cumulative.png"),
            title=f"Per-class {metric.capitalize()} cumulative",
        )

    # Plot per-class metrics (accuracy, precision, recall, f1) over time (cumulative, so-far) using plot_major_metrics_together
    for metric in selected_per_class:
        # Flatten cumul_metrics_per_class into a list of dicts: [{class: metric_value, ...}, ...]
        per_class_flattened = []
        for entry in batch_metrics_per_class:
            flat = {}
            for cls in entry.keys():
                flat[cls] = entry[cls].get(metric, 0)
            per_class_flattened.append(flat)
        plot_major_metrics_together(
            per_class_flattened,
            os.path.join(training_dir, f"per_class_{metric}_batches.png"),
            title=f"Per-class {metric.capitalize()} over Batches",
        )

    # Print final summary
    lines = []

    lines.append("\n=== Multi-class ===")
    last = cumul_metrics_multi[-1]
    lines.append(f"Accuracy: {last.get('accuracy', 0):.4f}")
    lines.append(f"Macro Precision: {last.get('macro_precision', 0):.4f}")
    lines.append(f"Macro Recall:    {last.get('macro_recall', 0):.4f}")
    lines.append(f"Macro F1:        {last.get('macro_f1', 0):.4f}")
    lines.append(f"Micro Precision: {last.get('micro_precision', 0):.4f}")
    lines.append(f"Micro Recall:    {last.get('micro_recall', 0):.4f}")
    lines.append(f"Micro F1:        {last.get('micro_f1', 0):.4f}")

    # Per-class metrics (cumulative, last batch)
    lines.append("\n=== Per-class metrics (cumulative) ===")
    lines.append(
        f"{'Class':<15} {'TP':>8} {'TN':>8} {'FP':>8} {'FN':>8} {'Acc':>8} {'Prec':>8} {'Rec':>8} {'F1':>8}"
    )
    cum_metrics_per_class = cumul_metrics_per_class[-1]
    for cls, m in cum_metrics_per_class.items():
        lines.append(
            f"{cls:<15} {m.get('TP', 0):8d} {m.get('TN', 0):8d} {m.get('FP', 0):8d} {m.get('FN', 0):8d} "
            f"{m.get('accuracy', 0.0):8.4f} {m.get('precision', 0.0):8.4f} {m.get('recall', 0.0):8.4f} {m.get('f1', 0.0):8.4f}"
        )

    lines.append(f"\nSummary for Experiment {args.exp}:")
    lines.append(f"Total batches processed: {len(entries)}")
    summary_txt = "\n".join(lines)

    # Save summary to file in the same directory as the plots
    summary_path = os.path.join(training_dir, "summary.txt")
    with open(summary_path, "w") as f:
        f.write(summary_txt)
    print(summary_txt)


if __name__ == "__main__":
    main()
