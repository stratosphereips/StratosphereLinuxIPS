# plot_test_performance.py
import argparse
import os
import traceback

import matplotlib.pyplot as plt

from base_utils import (
    compute_binary_metrics,
    compute_multi_metrics,
    ensure_dir,
    parse_testing_log_line,
    plot_major_metrics_together,
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
                print(f"Skipping line due to parsing error: {line.strip()}")
                traceback.print_exc()
                continue
    return entries


def compute_multi_metrics_custom(per_class):
    """
    Multi-class metrics with 'Background' excluded from benign/malicious accuracy.
    """
    metrics = compute_multi_metrics(per_class)
    total_tp_fn = 0
    total_tp = 0
    for cls_name, counts in per_class.items():
        if cls_name.lower() not in ["background", "bg"]:
            total_tp_fn += counts.get("TP", 0) + counts.get("FN", 0)
            total_tp += counts.get("TP", 0)
    metrics["benign_malicious_accuracy"] = (
        (total_tp / total_tp_fn) if total_tp_fn > 0 else 0.0
    )
    return metrics


def compute_malware_metrics(per_class):
    """
    Extract malware-specific metrics from a per-class counts dictionary.
    Returns malware_fpr, malware_fnr, malware_fp_over_predicted, malware_precision, recall, f1, accuracy
    """
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
        malware_metrics["malware_precision"] = precision
        malware_metrics["malware_recall"] = recall
        malware_metrics["malware_f1"] = (
            (2 * precision * recall / (precision + recall))
            if (precision + recall) > 0
            else 0.0
        )
        malware_metrics["malware_accuracy"] = (
            (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0
        )
    else:
        # default zeros
        keys = [
            "malware_fpr",
            "malware_fnr",
            "malware_fp_over_predicted",
            "malware_precision",
            "malware_recall",
            "malware_f1",
            "malware_accuracy",
        ]
        for k in keys:
            malware_metrics[k] = 0.0

    return malware_metrics


def accumulate_test_metrics_cumulative_snapshots(entries):
    """
    Build series of metrics from cumulative snapshots (one snapshot per log line).
    We DO NOT sum entries here — each entry is already 'so-far' totals.
    Returns:
      - cumul_per_class_series: list of per-class dicts (each class -> binary metrics + raw counts)
      - cumul_multi_series: list of multi-class metrics computed on the snapshot counts
      - cumul_binary_series: list of binary metrics (Benign vs Malicious) computed from snapshot binary_summary if present, otherwise derived
      - cumul_class_counts_series: list of dicts {class: TP+FN} for plotting counts
      - cumulative_total_flows: list of total_flows (x axis)
    """
    if not entries:
        return [], [], [], [], []

    class_names = list(entries[0].get("per_class", {}).keys())

    cumul_per_class_series = []
    cumul_multi_series = []
    cumul_binary_series = []
    cumul_class_counts_series = []
    cumulative_total_flows = []

    for data in entries:
        pcm = data.get("per_class", {})

        # per-class binary metrics built directly from snapshot counts
        per_class_metrics_now = {}
        for cls in class_names:
            counts = {
                k: int(pcm.get(cls, {}).get(k, 0))
                for k in ("TP", "FP", "TN", "FN")
            }
            bin_metrics = compute_binary_metrics(counts)
            bin_metrics.update(counts)  # include raw counts
            per_class_metrics_now[cls] = bin_metrics
        cumul_per_class_series.append(per_class_metrics_now)

        # multi-class metrics from snapshot counts
        snapshot_counts = {
            cls: {
                k: int(pcm.get(cls, {}).get(k, 0))
                for k in ("TP", "FP", "TN", "FN")
            }
            for cls in class_names
        }
        multi_now = compute_multi_metrics_custom(snapshot_counts)
        multi_now.update(compute_malware_metrics(snapshot_counts))
        cumul_multi_series.append(multi_now)

        # binary metrics: prefer explicit binary_summary if present, otherwise derive
        bm = data.get("binary_summary")
        if bm:
            bm_counts = {
                k: int(bm.get(k, 0)) for k in ("TP", "FP", "TN", "FN")
            }
        else:
            mal_key = next(
                (
                    k
                    for k in pcm.keys()
                    if k.lower() in ("malware", "malicious")
                ),
                None,
            )
            tp = int(pcm.get(mal_key, {}).get("TP", 0)) if mal_key else 0
            fp = int(pcm.get(mal_key, {}).get("FP", 0)) if mal_key else 0
            fn = int(pcm.get(mal_key, {}).get("FN", 0)) if mal_key else 0
            tn = 0
            # TN contributions come from other classes' TNs
            for k in pcm.keys():
                if k.lower() not in ("malware", "malicious"):
                    tn += int(pcm[k].get("TN", 0))
            bm_counts = {"TP": tp, "FP": fp, "TN": tn, "FN": fn}
        cumul_binary_series.append(compute_binary_metrics(bm_counts))

        # class counts (TP + FN) for each class in this snapshot
        counts_dict = {
            cls: int(
                pcm.get(cls, {}).get("TP", 0) + pcm.get(cls, {}).get("FN", 0)
            )
            for cls in class_names
        }
        cumul_class_counts_series.append(counts_dict)

        total = int(data.get("total_flows", 0))
        cumulative_total_flows.append(total)

    return (
        cumul_per_class_series,
        cumul_multi_series,
        cumul_binary_series,
        cumul_class_counts_series,
        cumulative_total_flows,
    )


# Small helpers for numeric count plotting
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
    series_of_dicts, outpath, title, xlabels=None, xlabel="Index"
):
    """
    Plot numeric counts for multiple classes over the series.
    series_of_dicts: list of dicts {class: count}
    """
    if series_of_dicts is None or not series_of_dicts:
        print("No data to plot for", title)
        return

    classes = list(next(iter(series_of_dicts)).keys())
    values_per_class = {
        c: [entry[c] for entry in series_of_dicts] for c in classes
    }
    n = len(series_of_dicts)
    x_positions = list(range(n))

    plt.figure(figsize=(9, 4))
    for cls in classes:
        plt.plot(x_positions, values_per_class[cls], label=cls, linewidth=1)

    if xlabels is None:
        labels = [str(i) for i in range(n)]
    else:
        labels = list(xlabels)

    if n >= 10:
        cleaned = []
        for lab in labels:
            if "\n" in lab:
                cleaned.append(lab.split("\n", 1)[0])
            else:
                cleaned.append(lab)
        labels = cleaned

    idxs, sparse_labels = _choose_sparse_xticks(n, labels)
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
    if not entries:
        print("No testing entries found in the log.")
        return

    (
        cumul_per_class_series,
        cumul_multi_series,
        cumul_binary_series,
        cumul_class_counts_series,
        cumulative_total_flows,
    ) = accumulate_test_metrics_cumulative_snapshots(entries)

    n = len(cumul_multi_series)

    # 1) Aggregated class counts (TP+FN per class so-far)
    print("Plotting aggregated class counts (TP+FN per class so-far)...")
    # xlabels: if we have numeric cumulative_total_flows, show them; otherwise use indices
    xlabels = (
        [str(x) for x in cumulative_total_flows]
        if cumulative_total_flows
        else [str(i) for i in range(n)]
    )
    plot_counts_series(
        cumul_class_counts_series,
        os.path.join(testing_dir, "class_counts_aggregated_testing.png"),
        title="Aggregated class counts\n(Total labeled samples seen so-far)",
        xlabels=xlabels,
        xlabel="Cumulative flows seen",
    )

    # 2) Malware metrics aggregated (FPR, FNR, F1, Benign-Malicious Acc)
    print("Plotting malware metrics (Aggregated so-far)...")
    malware_metrics_data = []
    for m in cumul_multi_series:
        malware_metrics_data.append(
            {
                "Malware FPR": m.get("malware_fpr", 0),
                "Malware FNR": m.get("malware_fnr", 0),
                "Malware F1": m.get("malware_f1", 0),
                "Benign-Malicious Acc": m.get("benign_malicious_accuracy", 0),
            }
        )

    # Use numeric x-axis: cumulative_total_flows (monotonic ints)
    xvals = (
        cumulative_total_flows if cumulative_total_flows else list(range(n))
    )
    plot_major_metrics_together(
        malware_metrics_data,
        os.path.join(testing_dir, "malware_metrics_aggregated_testing.png"),
        title="Malware metrics (Aggregated)\n(testing set: so-far)",
        xvals=xvals,
        xlabel="Total flows seen",
    )

    # 3) Binary (Benign vs Malicious) aggregated metrics
    print("Plotting binary metrics (Benign vs Malicious) aggregated so-far...")
    binary_metrics_data = []
    for b in cumul_binary_series:
        binary_metrics_data.append(
            {
                "Accuracy": b.get("accuracy", 0),
                "Precision": b.get("precision", 0),
                "Recall": b.get("recall", 0),
                "F1": b.get("f1", 0),
            }
        )

    plot_major_metrics_together(
        binary_metrics_data,
        os.path.join(testing_dir, "binary_benign_malicious_aggregated.png"),
        title="Binary (Benign vs Malicious) metrics (Aggregated)\n(testing set: so-far)",
        xvals=xvals,
        xlabel="Total flows seen",
    )

    # Summary: main metrics + "Other useful metrics"
    print("Writing summary...")
    last_multi = cumul_multi_series[-1]
    last_binary = cumul_binary_series[-1]
    final_per_class = cumul_per_class_series[-1]

    lines = []
    lines.append("\n=== Main final metrics (Aggregated so-far) ===")
    lines.append(
        f"Benign-Malicious Acc: {last_multi.get('benign_malicious_accuracy', 0):.4f}"
    )
    lines.append(
        f"Malware F1:           {last_multi.get('malware_f1', 0):.4f}"
    )
    lines.append(
        f"Malware Precision:    {last_multi.get('malware_precision', 0):.4f}"
    )
    lines.append(
        f"Malware Recall:       {last_multi.get('malware_recall', 0):.4f}"
    )
    lines.append(
        f"Malware FPR:          {last_multi.get('malware_fpr', 0):.4f}"
    )
    lines.append(
        f"Malware FNR:          {last_multi.get('malware_fnr', 0):.4f}"
    )
    lines.append("")
    lines.append("Binary (Benign vs Malicious):")
    lines.append(f"  Accuracy:  {last_binary.get('accuracy', 0):.4f}")
    lines.append(f"  Precision: {last_binary.get('precision', 0):.4f}")
    lines.append(f"  Recall:    {last_binary.get('recall', 0):.4f}")
    lines.append(f"  F1:        {last_binary.get('f1', 0):.4f}")

    # Other useful (kept in summary)
    lines.append("\n=== Other useful metrics (kept here for debugging) ===")
    lines.append(
        f"Multiclass Accuracy:    {last_multi.get('accuracy', 0):.4f}"
    )
    lines.append(
        f"Macro Precision:        {last_multi.get('macro_precision', 0):.4f}"
    )
    lines.append(
        f"Macro Recall:           {last_multi.get('macro_recall', 0):.4f}"
    )
    lines.append(
        f"Macro F1:               {last_multi.get('macro_f1', 0):.4f}"
    )
    lines.append(
        f"Micro Precision:        {last_multi.get('micro_precision', 0):.4f}"
    )
    lines.append(
        f"Micro Recall:           {last_multi.get('micro_recall', 0):.4f}"
    )
    lines.append(
        f"Micro F1:               {last_multi.get('micro_f1', 0):.4f}"
    )

    # Per-class metrics table (Aggregated so-far)
    lines.append("\n=== Per-class metrics (Aggregated so-far) ===")
    lines.append(
        f"{'Class':<15} {'TP':>8} {'TN':>12} {'FP':>8} {'FN':>8} {'Acc':>8} {'Prec':>8} {'Rec':>8} {'F1':>8}"
    )
    for cls, m in final_per_class.items():
        lines.append(
            f"{cls:<15} {m.get('TP', 0):8d} {m.get('TN', 0):12d} {m.get('FP', 0):8d} {m.get('FN', 0):8d} "
            f"{m.get('accuracy', 0.0):8.4f} {m.get('precision', 0.0):8.4f} {m.get('recall', 0.0):8.4f} {m.get('f1', 0.0):8.4f}"
        )

    lines.append(f"\nSummary for Experiment {args.exp}:")
    lines.append(f"Total test lines processed: {len(entries)}")

    summary_text = "\n".join(lines)
    summary_path = os.path.join(testing_dir, "summary.txt")
    with open(summary_path, "w") as f:
        f.write(summary_text)

    print(summary_text)


if __name__ == "__main__":
    main()
