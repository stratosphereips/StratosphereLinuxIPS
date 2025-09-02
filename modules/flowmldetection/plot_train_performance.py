# plot_train_performance.py
import argparse
import os
import traceback
import matplotlib.pyplot as plt

from base_utils import (
    compute_binary_metrics,
    compute_multi_metrics,
    ensure_dir,
    parse_training_log_line,
    plot_major_metrics_together,
)


def read_all_batches(logfile):
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


def compute_multi_metrics_custom(per_class):
    metrics = compute_multi_metrics(per_class)
    total_tp_fn = 0
    total_tp = 0
    for cls_name, counts in per_class.items():
        if cls_name.lower() not in ["background", "bg"]:
            total_tp_fn += counts["TP"] + counts["FN"]
            total_tp += counts["TP"]
    metrics["benign_malicious_accuracy"] = (
        (total_tp / total_tp_fn) if total_tp_fn > 0 else 0.0
    )
    return metrics


def compute_malware_metrics(per_class):
    malware_metrics = {}
    malware_key = None
    for cls_name in per_class.keys():
        if cls_name.lower() in ["malware", "malicious"]:
            malware_key = cls_name
            break

    if malware_key and malware_key in per_class:
        counts = per_class[malware_key]
        tp = counts.get("TP", 0)
        fp = counts.get("FP", 0)
        tn = counts.get("TN", 0)
        fn = counts.get("FN", 0)

        malware_metrics["malware_fpr"] = (
            fp / (fp + tn) if (fp + tn) > 0 else 0.0
        )
        malware_metrics["malware_fnr"] = (
            fn / (fn + tp) if (fn + tp) > 0 else 0.0
        )
        malware_metrics["malware_fp_over_predicted"] = (
            fp / (tp + fp) if (tp + fp) > 0 else 0.0
        )

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        malware_metrics["malware_f1"] = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )
    else:
        malware_metrics["malware_fpr"] = 0.0
        malware_metrics["malware_fnr"] = 0.0
        malware_metrics["malware_fp_over_predicted"] = 0.0
        malware_metrics["malware_f1"] = 0.0

    return malware_metrics


def process_batch_metrics(per_class, class_names):
    batch_metrics_per_class = {}
    for cls in class_names:
        bin_metrics_per_class = compute_binary_metrics(per_class[cls])
        bin_metrics_per_class.update(per_class[cls])
        batch_metrics_per_class[cls] = bin_metrics_per_class

    batch_multi = compute_multi_metrics_custom(per_class)
    batch_multi.update(compute_malware_metrics(per_class))

    return batch_metrics_per_class, batch_multi


def process_cumulative_metrics(cumul_class_counters, class_names):
    cumul_metrics_per_class = {}
    for cls in class_names:
        bin_metrics_per_class = compute_binary_metrics(
            cumul_class_counters[cls]
        )
        bin_metrics_per_class.update(cumul_class_counters[cls])
        cumul_metrics_per_class[cls] = bin_metrics_per_class

    cumul_multi = compute_multi_metrics_custom(cumul_class_counters)
    cumul_multi.update(compute_malware_metrics(cumul_class_counters))

    return cumul_metrics_per_class, cumul_multi


def accumulate_metrics(entries):
    has_training_data = any(
        "training_seen" in entry for entry in entries if entry
    )

    batch_metrics_per_class = []
    batch_metrics_multi = []
    cumul_metrics_multi = []
    cumul_metrics_per_class = []

    if has_training_data:
        batch_metrics_per_class_training = []
        batch_metrics_multi_training = []
        cumul_metrics_multi_training = []
        cumul_metrics_per_class_training = []

    class_names = list(entries[0]["per_class"].keys()) if entries else []

    cumul_class_counters = {
        cls: {"TP": 0, "FP": 0, "TN": 0, "FN": 0} for cls in class_names
    }
    if has_training_data:
        cumul_class_counters_training = {
            cls: {"TP": 0, "FP": 0, "TN": 0, "FN": 0} for cls in class_names
        }

    for data in entries:
        per_class = data["per_class"]
        batch_per_class, batch_multi = process_batch_metrics(
            per_class, class_names
        )
        batch_metrics_per_class.append(batch_per_class)
        batch_metrics_multi.append(batch_multi)

        for cls in class_names:
            for k in ["TP", "FP", "TN", "FN"]:
                cumul_class_counters[cls][k] += per_class[cls][k]

        cumul_per_class, cumul_multi = process_cumulative_metrics(
            cumul_class_counters, class_names
        )
        cumul_metrics_per_class.append(cumul_per_class)
        cumul_metrics_multi.append(cumul_multi)

        if has_training_data and "training_per_class" in data:
            training_per_class = data["training_per_class"]
            batch_per_class_training, batch_multi_training = (
                process_batch_metrics(training_per_class, class_names)
            )
            batch_metrics_per_class_training.append(batch_per_class_training)
            batch_metrics_multi_training.append(batch_multi_training)

            for cls in class_names:
                for k in ["TP", "FP", "TN", "FN"]:
                    cumul_class_counters_training[cls][
                        k
                    ] += training_per_class[cls][k]

            cumul_per_class_training, cumul_multi_training = (
                process_cumulative_metrics(
                    cumul_class_counters_training, class_names
                )
            )
            cumul_metrics_per_class_training.append(cumul_per_class_training)
            cumul_metrics_multi_training.append(cumul_multi_training)

    if has_training_data:
        return (
            batch_metrics_per_class,
            batch_metrics_multi,
            cumul_metrics_multi,
            cumul_metrics_per_class,
            batch_metrics_per_class_training,
            batch_metrics_multi_training,
            cumul_metrics_multi_training,
            cumul_metrics_per_class_training,
        )
    else:
        return (
            batch_metrics_per_class,
            batch_metrics_multi,
            cumul_metrics_multi,
            cumul_metrics_per_class,
        )


def calculate_class_counts(entries, data_key, class_names):
    batch_class_counts = []
    for entry in entries:
        if data_key in entry and entry[data_key]:
            counts = {
                cls: int(
                    entry[data_key][cls].get("TP", 0)
                    + entry[data_key][cls].get("FN", 0)
                )
                for cls in class_names
            }
        else:
            counts = {cls: 0 for cls in class_names}
        batch_class_counts.append(counts)

    cumul_class_counts = {cls: 0 for cls in class_names}
    cumul_class_counts_per_batch = []
    for counts in batch_class_counts:
        for cls in class_names:
            cumul_class_counts[cls] += counts[cls]
        cumul_class_counts_per_batch.append(cumul_class_counts.copy())

    return batch_class_counts, cumul_class_counts_per_batch


def _choose_sparse_xticks(batch_count, labels):
    if batch_count <= 20:
        return list(range(batch_count)), labels
    max_labels = 15
    step = max(1, batch_count // max_labels)
    indices = list(range(0, batch_count, step))
    if indices[-1] != batch_count - 1:
        indices.append(batch_count - 1)
    sparse_labels = [""] * batch_count
    for i in indices:
        sparse_labels[i] = labels[i]
    return indices, sparse_labels


def plot_counts_series(
    series_of_dicts, outpath, title, xlabels=None, xlabel="Batch"
):
    if series_of_dicts is None or not series_of_dicts:
        print("No data to plot for", title)
        return

    classes = list(next(iter(series_of_dicts)).keys())
    values_per_class = {
        c: [entry[c] for entry in series_of_dicts] for c in classes
    }
    batch_count = len(series_of_dicts)
    x_positions = list(range(batch_count))

    plt.figure(figsize=(9, 4))
    for cls in classes:
        plt.plot(x_positions, values_per_class[cls], label=cls, linewidth=1)

    if xlabels is None:
        labels = [str(i) for i in range(batch_count)]
    else:
        labels = list(xlabels)

    if batch_count >= 10:
        cleaned = []
        for lab in labels:
            if "\n" in lab:
                cleaned.append(lab.split("\n", 1)[0])
            else:
                cleaned.append(lab)
        labels = cleaned

    idxs, sparse_labels = _choose_sparse_xticks(batch_count, labels)
    plt.xticks(idxs, [sparse_labels[i] for i in idxs], rotation=45, ha="right")

    plt.xlabel(xlabel)
    plt.ylabel("Count")
    max_val = max(v for values in values_per_class.values() for v in values)
    top = max_val * 1.05 if max_val > 0 else 1
    plt.ylim(0, top)

    if "\n" in title:
        main, sub = title.split("\n", 1)
        plt.suptitle(main, fontsize=10)
        plt.title(sub, fontsize=9)
    else:
        plt.title(title)
    plt.legend(loc="best", fontsize=8)
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    plt.savefig(outpath)
    plt.close()


def get_stepping_sizes(entries, batch_count, size_key):
    labels = []
    if batch_count < 10:
        for i, entry in enumerate(entries):
            labels.append(f"{i}\n{entry.get(size_key, 0)}")
        return labels

    if batch_count <= 20:
        return [str(i) for i in range(batch_count)]
    else:
        max_labels = 15
        step = max(1, batch_count // max_labels)
        labels = []
        for i, entry in enumerate(entries):
            if i % step == 0 or i == batch_count - 1:
                labels.append(str(i))
            else:
                labels.append("")
        return labels


def sliding_window_aggregated(
    batch_metrics_per_class, class_names, k, trim_to_full_window=True
):
    n = len(batch_metrics_per_class)
    series_per_class = []
    series_multi = []

    for i in range(n):
        start = max(0, i - k + 1)
        agg = {
            cls: {"TP": 0, "FP": 0, "TN": 0, "FN": 0} for cls in class_names
        }
        for j in range(start, i + 1):
            per_cls = batch_metrics_per_class[j]
            for cls in class_names:
                agg[cls]["TP"] += int(per_cls[cls].get("TP", 0))
                agg[cls]["FP"] += int(per_cls[cls].get("FP", 0))
                agg[cls]["TN"] += int(per_cls[cls].get("TN", 0))
                agg[cls]["FN"] += int(per_cls[cls].get("FN", 0))

        per_class_metrics = {}
        for cls in class_names:
            bin_metrics = compute_binary_metrics(agg[cls])
            bin_metrics.update(agg[cls])
            per_class_metrics[cls] = bin_metrics

        multi = compute_multi_metrics_custom(agg)
        multi.update(compute_malware_metrics(agg))

        series_per_class.append(per_class_metrics)
        series_multi.append(multi)

    if trim_to_full_window:
        if n < k:
            return [], [], None
        start_index = k - 1
        return (
            series_per_class[start_index:],
            series_multi[start_index:],
            start_index,
        )
    else:
        return series_per_class, series_multi, 0


def plot_malware_metrics(metrics_data, output_path, title, xvals, xlabel):
    malware_metrics_data = []
    for entry in metrics_data:
        malware_metrics_data.append(
            {
                "Malware FPR": entry.get("malware_fpr", 0),
                "Malware FNR": entry.get("malware_fnr", 0),
                "Malware F1": entry.get("malware_f1", 0),
                "Benign-Malicious Acc": entry.get(
                    "benign_malicious_accuracy", 0
                ),
            }
        )

    if "\n" in title:
        main_title, subtitle = title.split("\n", 1)
        full_title = f"{main_title}\n{subtitle}"
    else:
        full_title = title

    plot_major_metrics_together(
        malware_metrics_data,
        output_path,
        title=full_title,
        xvals=xvals,
        xlabel=xlabel,
    )


def plot_accuracy_metrics(metrics_data, output_path, title, xvals, xlabel):
    accuracy_data = []
    for entry in metrics_data:
        accuracy_data.append(
            {
                "Benign-Malicious Acc": entry.get(
                    "benign_malicious_accuracy", 0
                ),
            }
        )
    plot_major_metrics_together(
        accuracy_data, output_path, title=title, xvals=xvals, xlabel=xlabel
    )


def plot_comparison_metrics(
    batch_metrics_multi,
    cumul_metrics_multi,
    batch_metrics_multi_training,
    cumul_metrics_multi_training,
    base_dir,
    stepping_total_sizes,
    cumulative_total_sizes,
    batch_count,
):
    """
    Save aggregated comparison plots to base_dir/aggregated and per-batch comparisons to base_dir/per_batch.
    base_dir should be the top-level comparison folder for the experiment.
    """
    agg_dir = ensure_dir(os.path.join(base_dir, "aggregated"))
    batch_dir = ensure_dir(os.path.join(base_dir, "per_batch"))

    metrics = [
        (
            "benign_malicious_accuracy",
            "Benign-Malicious Acc",
            "train_val_accuracy.png",
        ),
        ("malware_f1", "Malware F1", "train_val_malware_f1.png"),
    ]

    # Aggregated
    for metric, short_title, filename in metrics:
        combined = []
        for i in range(batch_count):
            combined.append(
                {
                    "Validation": cumul_metrics_multi[i].get(metric, 0),
                    "Training": cumul_metrics_multi_training[i].get(metric, 0),
                }
            )
        plot_major_metrics_together(
            combined,
            os.path.join(agg_dir, filename),
            title=f"{short_title}\n(Validation vs Training — Aggregated)",
            xvals=cumulative_total_sizes,
            xlabel="Aggregated samples",
        )

    # Per-batch
    for metric, short_title, filename in metrics:
        combined = []
        for i in range(batch_count):
            combined.append(
                {
                    "Validation": batch_metrics_multi[i].get(metric, 0),
                    "Training": batch_metrics_multi_training[i].get(metric, 0),
                }
            )
        plot_major_metrics_together(
            combined,
            os.path.join(batch_dir, filename.replace(".png", "_batch.png")),
            title=f"{short_title}\n(Validation vs Training — Per-batch)",
            xvals=stepping_total_sizes,
            xlabel="Batch",
        )


def plot_comparison_metrics_for_series(
    series_val,
    series_train,
    base_dir,
    xvals,
    start_index,
    batch_count,
    name_prefix,
):
    """
    Save comparison plots for last-K into base_dir (which should be comparison/lastK).
    """
    if start_index is None:
        print(f"Skipping comparison {name_prefix}: not enough batches")
        return

    ensure_dir(base_dir)
    metrics = [
        (
            "benign_malicious_accuracy",
            "Benign-Malicious Acc",
            f"train_val_accuracy_{name_prefix}.png",
        ),
        (
            "malware_f1",
            "Malware F1",
            f"train_val_malware_f1_{name_prefix}.png",
        ),
    ]
    length = len(series_val)
    for metric, short_title, filename in metrics:
        combined = []
        for i in range(length):
            combined.append(
                {
                    "Validation": series_val[i].get(metric, 0),
                    "Training": series_train[i].get(metric, 0),
                }
            )
        plot_major_metrics_together(
            combined,
            os.path.join(base_dir, filename),
            title=f"{short_title}\n(Validation vs Training — {name_prefix})",
            xvals=xvals,
            xlabel="Batch",
        )

    fn_data = []
    fp_data = []
    for i in range(length):
        fn_data.append(
            {
                "Validation FN Rate": series_val[i].get("malware_fnr", 0),
                "Training FN Rate": series_train[i].get("malware_fnr", 0),
            }
        )
        fp_data.append(
            {
                "Validation FP Rate": series_val[i].get(
                    "malware_fp_over_predicted", 0
                ),
                "Training FP Rate": series_train[i].get(
                    "malware_fp_over_predicted", 0
                ),
            }
        )
    plot_major_metrics_together(
        fn_data,
        os.path.join(base_dir, f"train_val_fn_rate_{name_prefix}.png"),
        title=f"FN Rate\n(Validation vs Training — {name_prefix})",
        xvals=xvals,
        xlabel="Batch",
    )
    plot_major_metrics_together(
        fp_data,
        os.path.join(base_dir, f"train_val_fp_rate_{name_prefix}.png"),
        title=f"FP Rate (predicted+)\n(Validation vs Training — {name_prefix})",
        xvals=xvals,
        xlabel="Batch",
    )


def plot_malware_fn_rate_comparison(
    cumul_metrics_multi,
    cumul_metrics_multi_training,
    base_dir,
    cumulative_total_sizes,
    batch_count,
):
    agg_dir = ensure_dir(os.path.join(base_dir, "aggregated"))
    fn_rate_data = []
    for i in range(batch_count):
        fn_rate_data.append(
            {
                "Validation FN Rate": cumul_metrics_multi[i].get(
                    "malware_fnr", 0
                ),
                "Training FN Rate": cumul_metrics_multi_training[i].get(
                    "malware_fnr", 0
                ),
            }
        )
    plot_major_metrics_together(
        fn_rate_data,
        os.path.join(agg_dir, "train_val_fn_rate.png"),
        title="FN Rate\n(Validation vs Training — Aggregated)",
        xvals=cumulative_total_sizes,
        xlabel="Aggregated samples",
    )


def plot_malware_fp_over_predicted_comparison(
    cumul_metrics_multi,
    cumul_metrics_multi_training,
    base_dir,
    cumulative_total_sizes,
    batch_count,
):
    agg_dir = ensure_dir(os.path.join(base_dir, "aggregated"))
    fp_over_pred = []
    for i in range(batch_count):
        fp_over_pred.append(
            {
                "Validation FP Rate": cumul_metrics_multi[i].get(
                    "malware_fp_over_predicted", 0
                ),
                "Training FP Rate": cumul_metrics_multi_training[i].get(
                    "malware_fp_over_predicted", 0
                ),
            }
        )
    plot_major_metrics_together(
        fp_over_pred,
        os.path.join(agg_dir, "train_val_fp_rate.png"),
        title="FP Rate\n(Validation vs Training — Aggregated)",
        xvals=cumulative_total_sizes,
        xlabel="Aggregated samples",
    )


def print_summary_section(lines, title, metrics_data):
    lines.append(f"\n=== {title} ===")
    lines.append(
        f"Benign-Malicious Acc: {metrics_data.get('benign_malicious_accuracy', 0):.4f}"
    )
    lines.append(
        f"Malware F1:           {metrics_data.get('malware_f1', 0):.4f}"
    )
    lines.append(
        f"Malware FPR:          {metrics_data.get('malware_fpr', 0):.4f}"
    )
    lines.append(
        f"Malware FNR:          {metrics_data.get('malware_fnr', 0):.4f}"
    )
    lines.append(
        f"Macro F1:             {metrics_data.get('macro_f1', 0):.4f}"
    )


def print_per_class_table(lines, title, cum_metrics_per_class):
    lines.append(f"\n=== {title} ===")
    lines.append(
        f"{'Class':<15} {'TP':>8} {'TN':>8} {'FP':>8} {'FN':>8} {'Acc':>8} {'Prec':>8} {'Rec':>8} {'F1':>8}"
    )

    for cls, m in cum_metrics_per_class.items():
        lines.append(
            f"{cls:<15} {m.get('TP', 0):8d} {m.get('TN', 0):8d} {m.get('FP', 0):8d} {m.get('FN', 0):8d} "
            f"{m.get('accuracy', 0.0):8.4f} {m.get('precision', 0.0):8.4f} {m.get('recall', 0.0):8.4f} {m.get('f1', 0.0):8.4f}"
        )


def ensure_plot_subdirs(base_dir):
    subs = {}
    for name in ["per_batch", "aggregated", "last5", "last10", "last20"]:
        p = ensure_dir(os.path.join(base_dir, name))
        subs[name] = p
    return subs


def _plot_lastk_class_counts(series_per_class_k, outpath, title, xlabels=None):
    """
    Given a sliding-window per-class series (each element: {class: {TP,FP,TN,FN,...}}),
    compute TP+FN per class for each window and plot counts.
    """
    if not series_per_class_k:
        print(f"No class-counts to plot for {outpath}")
        return
    # transform to list of dicts {class: TP+FN}
    counts_series = []
    for entry in series_per_class_k:
        counts_series.append(
            {
                cls: int(entry[cls].get("TP", 0) + entry[cls].get("FN", 0))
                for cls in entry.keys()
            }
        )
    plot_counts_series(
        counts_series, outpath, title=title, xlabels=xlabels, xlabel="Batch"
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
    folder_dir = ensure_dir(os.path.join(base_dir, "training", args.exp))

    entries = read_all_batches(args.file)

    has_training_data = any(
        "training_seen" in entry for entry in entries if entry
    )

    if has_training_data:
        (
            batch_metrics_per_class,
            batch_metrics_multi,
            cumul_metrics_multi,
            cumul_metrics_per_class,
            batch_metrics_per_class_training,
            batch_metrics_multi_training,
            cumul_metrics_multi_training,
            cumul_metrics_per_class_training,
        ) = accumulate_metrics(entries)
    else:
        (
            batch_metrics_per_class,
            batch_metrics_multi,
            cumul_metrics_multi,
            cumul_metrics_per_class,
        ) = accumulate_metrics(entries)

    if has_training_data:
        validation_dir = ensure_dir(os.path.join(folder_dir, "validation"))
        train_dir = ensure_dir(os.path.join(folder_dir, "training"))
        comparison_dir = ensure_dir(os.path.join(folder_dir, "comparison"))
        print(f"Validation plots will be saved to: {validation_dir}")
        print(f"Training plots will be saved to: {train_dir}")
        print(f"Comparison plots will be saved to: {comparison_dir}")
    else:
        train_dir = ensure_dir(os.path.join(folder_dir, "training"))
        validation_dir = None
        comparison_dir = None
        print(f"Training plots will be saved to: {train_dir}")

    def get_dir(data_type):
        if data_type == "validation" and validation_dir is not None:
            return validation_dir
        elif data_type == "training":
            return train_dir
        else:
            return train_dir

    class_names = list(entries[0]["per_class"].keys()) if entries else []
    batch_count = len(entries)

    # Ensure subdirectories exist for validation and training
    if validation_dir:
        ensure_plot_subdirs(validation_dir)
    ensure_plot_subdirs(train_dir)
    if comparison_dir:
        ensure_plot_subdirs(comparison_dir)

    # class counts plots -> per_batch and aggregated folders (validation or training)
    batch_class_counts, cumul_class_counts_per_batch = calculate_class_counts(
        entries, "per_class", class_names
    )
    plot_counts_series(
        batch_class_counts,
        os.path.join(
            get_dir("validation" if has_training_data else "training"),
            "per_batch",
            f"class_counts_batch_{'validation' if has_training_data else 'training'}.png",
        ),
        title="Per-batch class counts\n(Number of samples per batch)",
        xlabels=[str(i) for i in range(batch_count)],
        xlabel="Batch",
    )

    plot_counts_series(
        cumul_class_counts_per_batch,
        os.path.join(
            get_dir("validation" if has_training_data else "training"),
            "aggregated",
            f"class_counts_aggregated_{'validation' if has_training_data else 'training'}.png",
        ),
        title="Aggregated class counts\n(Total samples seen so far)",
        xlabels=[str(i) for i in range(batch_count)],
        xlabel="Batch",
    )

    if has_training_data:
        batch_class_counts_training, cumul_class_counts_training_per_batch = (
            calculate_class_counts(entries, "training_per_class", class_names)
        )
        plot_counts_series(
            batch_class_counts_training,
            os.path.join(
                get_dir("training"),
                "per_batch",
                "class_counts_batch_training.png",
            ),
            title="Per-batch class counts (Training)",
            xlabels=[str(i) for i in range(batch_count)],
            xlabel="Batch",
        )
        plot_counts_series(
            cumul_class_counts_training_per_batch,
            os.path.join(
                get_dir("training"),
                "aggregated",
                "class_counts_aggregated_training.png",
            ),
            title="Aggregated class counts (Training)",
            xlabels=[str(i) for i in range(batch_count)],
            xlabel="Batch",
        )

    # prepare x-axis labels for metric plots
    if has_training_data:
        cumulative_sizes = []
        total = 0
        for entry in entries:
            size = entry.get("testing_size", 0)
            total += size
            cumulative_sizes.append(total)
        stepping_sizes = get_stepping_sizes(
            entries, batch_count, "testing_size"
        )
    else:
        cumulative_sizes = []
        total = 0
        for entry in entries:
            size = entry.get("training_size", entry.get("testing_size", 0))
            total += size
            cumulative_sizes.append(total)
        stepping_sizes = get_stepping_sizes(
            entries, batch_count, "training_size"
        )

    # Per-batch and aggregated (cumulative) plots go to per_batch/ and aggregated/
    plot_malware_metrics(
        batch_metrics_multi,
        os.path.join(
            get_dir("validation" if has_training_data else "training"),
            "per_batch",
            f"malware_metrics_batch_{'validation' if has_training_data else 'training'}.png",
        ),
        f"Malware metrics (per-batch)\n({'Validation' if has_training_data else 'Training'})",
        stepping_sizes,
        "Batch",
    )

    plot_malware_metrics(
        cumul_metrics_multi,
        os.path.join(
            get_dir("validation" if has_training_data else "training"),
            "aggregated",
            f"malware_metrics_aggregated_{'validation' if has_training_data else 'training'}.png",
        ),
        f"Malware metrics (Aggregated)\n({'Validation' if has_training_data else 'Training'})",
        xvals=cumulative_sizes,
        xlabel="Aggregated samples",
    )

    plot_accuracy_metrics(
        batch_metrics_multi,
        os.path.join(
            get_dir("validation" if has_training_data else "training"),
            "per_batch",
            f"accuracy_batch_{'validation' if has_training_data else 'training'}.png",
        ),
        f"Benign-Malicious Acc (per-batch)\n({'Validation' if has_training_data else 'Training'})",
        stepping_sizes,
        "Batch",
    )

    plot_accuracy_metrics(
        cumul_metrics_multi,
        os.path.join(
            get_dir("validation" if has_training_data else "training"),
            "aggregated",
            f"accuracy_aggregated_{'validation' if has_training_data else 'training'}.png",
        ),
        f"Benign-Malicious Acc (Aggregated)\n({'Validation' if has_training_data else 'Training'})",
        xvals=cumulative_sizes,
        xlabel="Aggregated samples",
    )

    # helper to make last-K sliding windows, save metrics and class-counts into base_dir/lastK
    def make_lastk_and_plot(
        k, per_class_batch, multi_batch, base_dir, stepping_sizes_all, label
    ):
        series_per_class_k, series_multi_k, start_idx = (
            sliding_window_aggregated(
                per_class_batch, class_names, k, trim_to_full_window=True
            )
        )
        if start_idx is None or len(series_multi_k) == 0:
            print(
                f"Not enough batches for last-{k} (need at least {k}) for {label}, skipping."
            )
            return None, None, None
        n = len(per_class_batch)
        xvals = list(range(start_idx, n))
        folder = os.path.join(base_dir, f"last{k}")
        ensure_dir(folder)
        # metrics plots
        plot_malware_metrics(
            series_multi_k,
            os.path.join(folder, f"malware_metrics_last{k}_{label}.png"),
            f"Malware metrics (last-{k})\n({label})",
            xvals,
            "Batch",
        )
        plot_accuracy_metrics(
            series_multi_k,
            os.path.join(folder, f"accuracy_last{k}_{label}.png"),
            f"Benign-Malicious Acc (last-{k})\n({label})",
            xvals,
            "Batch",
        )
        # class-counts aggregated over window (TP + FN per class)
        _plot_lastk_class_counts(
            series_per_class_k,
            os.path.join(folder, f"class_counts_last{k}_{label}.png"),
            title=f"Aggregated class counts (last-{k})\n({label})",
            xlabels=[str(i) for i in xvals],
        )
        return series_per_class_k, series_multi_k, start_idx

    # Validation/single-mode last-k
    label_val = "validation" if has_training_data else "training"
    last5_per_class_val, last5_multi_val, last5_start = make_lastk_and_plot(
        5,
        batch_metrics_per_class,
        batch_metrics_multi,
        get_dir("validation" if has_training_data else "training"),
        stepping_sizes,
        label_val,
    )
    last10_per_class_val, last10_multi_val, last10_start = make_lastk_and_plot(
        10,
        batch_metrics_per_class,
        batch_metrics_multi,
        get_dir("validation" if has_training_data else "training"),
        stepping_sizes,
        label_val,
    )
    last20_per_class_val, last20_multi_val, last20_start = make_lastk_and_plot(
        20,
        batch_metrics_per_class,
        batch_metrics_multi,
        get_dir("validation" if has_training_data else "training"),
        stepping_sizes,
        label_val,
    )

    # Training-specific plots & sliding windows
    if has_training_data:
        cumulative_training_sizes = []
        total_training = 0
        for entry in entries:
            size = entry.get("training_size", 0)
            total_training += size
            cumulative_training_sizes.append(total_training)

        stepping_training_sizes = get_stepping_sizes(
            entries, batch_count, "training_size"
        )

        plot_malware_metrics(
            batch_metrics_multi_training,
            os.path.join(
                get_dir("training"),
                "per_batch",
                "malware_metrics_batch_training.png",
            ),
            "Malware metrics (per-batch)\n(Training)",
            stepping_training_sizes,
            "Batch",
        )

        plot_malware_metrics(
            cumul_metrics_multi_training,
            os.path.join(
                get_dir("training"),
                "aggregated",
                "malware_metrics_aggregated_training.png",
            ),
            "Malware metrics (Aggregated)\n(Training)",
            xvals=cumulative_training_sizes,
            xlabel="Aggregated samples",
        )

        plot_accuracy_metrics(
            batch_metrics_multi_training,
            os.path.join(
                get_dir("training"), "per_batch", "accuracy_batch_training.png"
            ),
            "Benign-Malicious Acc (per-batch)\n(Training)",
            stepping_training_sizes,
            "Batch",
        )

        plot_accuracy_metrics(
            cumul_metrics_multi_training,
            os.path.join(
                get_dir("training"),
                "aggregated",
                "accuracy_aggregated_training.png",
            ),
            "Benign-Malicious Acc (Aggregated)\n(Training)",
            xvals=cumulative_training_sizes,
            xlabel="Aggregated samples",
        )

        last5_per_class_train, last5_multi_train, last5_start_train = (
            make_lastk_and_plot(
                5,
                batch_metrics_per_class_training,
                batch_metrics_multi_training,
                get_dir("training"),
                stepping_training_sizes,
                "training",
            )
        )
        last10_per_class_train, last10_multi_train, last10_start_train = (
            make_lastk_and_plot(
                10,
                batch_metrics_per_class_training,
                batch_metrics_multi_training,
                get_dir("training"),
                stepping_training_sizes,
                "training",
            )
        )
        last20_per_class_train, last20_multi_train, last20_start_train = (
            make_lastk_and_plot(
                20,
                batch_metrics_per_class_training,
                batch_metrics_multi_training,
                get_dir("training"),
                stepping_training_sizes,
                "training",
            )
        )

        # comparison x-axis / stepping sizes
        batch_total_sizes = [
            entry.get("training_size", 0) + entry.get("testing_size", 0)
            for entry in entries
        ]
        if batch_count < 10:
            stepping_total_sizes = [
                f"{i}\n{size}" for i, size in enumerate(batch_total_sizes)
            ]
        else:
            stepping_total_sizes = get_stepping_sizes(
                [{"dummy": 0}] * batch_count, batch_count, "dummy"
            )

        cumulative_total_sizes = []
        total_so_far = 0
        for size in batch_total_sizes:
            total_so_far += size
            cumulative_total_sizes.append(total_so_far)

        # comparison plots saved under comparison/aggregated and comparison/per_batch
        plot_comparison_metrics(
            batch_metrics_multi,
            cumul_metrics_multi,
            batch_metrics_multi_training,
            cumul_metrics_multi_training,
            comparison_dir,
            stepping_total_sizes,
            cumulative_total_sizes,
            batch_count,
        )

        # error comparisons (FN and FP-over-predicted) - saved under comparison/aggregated
        plot_malware_fn_rate_comparison(
            cumul_metrics_multi,
            cumul_metrics_multi_training,
            comparison_dir,
            cumulative_total_sizes,
            batch_count,
        )

        plot_malware_fp_over_predicted_comparison(
            cumul_metrics_multi,
            cumul_metrics_multi_training,
            comparison_dir,
            cumulative_total_sizes,
            batch_count,
        )

        # comparison plots for last-5/last-10/last-20 -> saved under comparison/lastk/
        def maybe_plot_compare(
            last_multi_val,
            last_start_val,
            last_multi_train,
            last_start_train,
            kname,
        ):
            if (
                last_multi_val
                and last_start_val is not None
                and last_multi_train
                and last_start_train is not None
            ):
                start = max(last_start_val, last_start_train)
                offset_val = start - last_start_val
                offset_train = start - last_start_train
                len_val = len(last_multi_val) - offset_val
                len_train = len(last_multi_train) - offset_train
                common_len = min(len_val, len_train)
                if common_len <= 0:
                    print(f"No overlapping region for {kname} comparison.")
                    return
                slice_val = last_multi_val[
                    offset_val : offset_val + common_len
                ]
                slice_train = last_multi_train[
                    offset_train : offset_train + common_len
                ]
                xvals = list(range(start, start + common_len))
                base = os.path.join(comparison_dir, kname)
                plot_comparison_metrics_for_series(
                    slice_val,
                    slice_train,
                    base,
                    xvals,
                    start,
                    common_len,
                    kname,
                )

        maybe_plot_compare(
            last5_multi_val,
            last5_start,
            last5_multi_train,
            last5_start_train,
            "last5",
        )
        maybe_plot_compare(
            last10_multi_val,
            last10_start,
            last10_multi_train,
            last10_start_train,
            "last10",
        )
        maybe_plot_compare(
            last20_multi_val,
            last20_start,
            last20_multi_train,
            last20_start_train,
            "last20",
        )

    # summary text (include last-5/10/20)
    lines = []
    if has_training_data:
        print_summary_section(
            lines,
            "VALIDATION Multi-class (Aggregated)",
            cumul_metrics_multi[-1],
        )
        print_summary_section(
            lines,
            "TRAINING Multi-class (Aggregated)",
            cumul_metrics_multi_training[-1],
        )

        print_per_class_table(
            lines,
            "Per-class metrics (Aggregated) - VALIDATION",
            cumul_metrics_per_class[-1],
        )
        print_per_class_table(
            lines,
            "Per-class metrics (Aggregated) - TRAINING",
            cumul_metrics_per_class_training[-1],
        )

        def add_lastk_summary(lines, tag, multi):
            if multi and len(multi) > 0:
                lines.append(f"\n{tag}:")
                lines.append(
                    f"  Benign-Malicious Acc: {multi[-1].get('benign_malicious_accuracy', 0):.4f}"
                )
                lines.append(
                    f"  Malware F1:           {multi[-1].get('malware_f1', 0):.4f}"
                )
                lines.append(
                    f"  Malware FPR:          {multi[-1].get('malware_fpr', 0):.4f}"
                )
                lines.append(
                    f"  Malware FNR:          {multi[-1].get('malware_fnr', 0):.4f}"
                )
            else:
                lines.append(f"\n{tag}: not available (insufficient batches)")

        lines.append("\n=== Last-window summaries (Validation) ===")
        add_lastk_summary(lines, "Last-5", last5_multi_val)
        add_lastk_summary(lines, "Last-10", last10_multi_val)
        add_lastk_summary(lines, "Last-20", last20_multi_val)

        lines.append("\n=== Last-window summaries (Training) ===")
        add_lastk_summary(lines, "Last-5", last5_multi_train)
        add_lastk_summary(lines, "Last-10", last10_multi_train)
        add_lastk_summary(lines, "Last-20", last20_multi_train)

    else:
        print_summary_section(
            lines, "TRAINING Multi-class (Aggregated)", cumul_metrics_multi[-1]
        )
        print_per_class_table(
            lines,
            "Per-class metrics (Aggregated) - TRAINING",
            cumul_metrics_per_class[-1],
        )

        """ def add_lastk_summary(lines, tag, multi):
            if multi and len(multi) > 0:
                lines.append(f"\n{tag}:")
                lines.append(f"  Benign-Malicious Acc: {multi[-1].get('benign_malicious_accuracy', 0):.4f}")
                lines.append(f"  Malware F1:           {multi[-1].get('malware_f1', 0):.4f}")
                lines.append(f"  Malware FPR:          {multi[-1].get('malware_fpr', 0):.4f}")
                lines.append(f"  Malware FNR:          {multi[-1].get('malware_fnr', 0):.4f}")
            else:
                lines.append(f"\n{tag}: not available (insufficient batches)")

        lines.append("\n=== Last-window summaries ===")
        add_lastk_summary(lines, "Last-5", last5_multi_val)
        add_lastk_summary(lines, "Last-10", last10_multi_val)
        add_lastk_summary(lines, "Last-20", last20_multi_val) """

    lines.append(f"\nSummary for Experiment {args.exp}:")
    lines.append(f"Total batches processed: {batch_count}")
    lines.append(
        "Data type: Training/Validation split"
        if has_training_data
        else "Data type: Training only"
    )

    summary_txt = "\n".join(lines)
    summary_path = os.path.join(folder_dir, "summary.txt")
    with open(summary_path, "w") as f:
        f.write(summary_txt)
    print(summary_txt)


if __name__ == "__main__":
    main()
