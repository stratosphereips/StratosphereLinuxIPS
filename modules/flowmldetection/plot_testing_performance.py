#!/usr/bin/env python3
# plot_test_performance.py (drop-in replacement)
import argparse
import os
import traceback

import matplotlib.pyplot as plt
import numpy as np

from base_utils import (
    compute_binary_metrics,
    compute_multi_metrics,
    ensure_dir,
    parse_testing_log_line,
    plot_major_metrics_together,
)


def read_all_tests(logfile):
    entries = []
    print(f"[INFO] Reading testing logfile: {logfile}")
    with open(logfile, "r") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            try:
                data = parse_testing_log_line(line)
                if data is None:
                    print(
                        f"[WARN] Skipping unparsable testing line {i}: {line[:200]}"
                    )
                    continue
                # strip background if exists
                if "per_class" in data:
                    data["per_class"] = {
                        k: v
                        for k, v in data["per_class"].items()
                        if k.lower() not in ("background", "bg")
                    }
                entries.append(data)
            except Exception:
                print(
                    f"[WARN] Skipping line due to parsing error: {line[:200]}"
                )
                traceback.print_exc()
                continue
    # print(f"[INFO] Parsed {len(entries)} testing lines")
    return entries


def accumulate_test_metrics_cumulative_snapshots(entries):
    if not entries:
        return [], [], [], [], []

    class_names = list(entries[0].get("per_class", {}).keys())
    if not class_names:
        class_names = ["Malicious", "Benign"]

    cumul_per_class_series = []
    cumul_multi_series = []
    cumul_binary_series = []
    cumul_class_counts_series = []
    cumulative_total_flows = []

    for data in entries:
        pcm = data.get("per_class", {})

        per_class_metrics_now = {}
        for cls in class_names:
            counts = {
                k: int(pcm.get(cls, {}).get(k, 0))
                for k in ("TP", "FP", "TN", "FN")
            }
            bin_metrics = compute_binary_metrics(counts)
            bin_metrics.update(counts)
            per_class_metrics_now[cls] = bin_metrics
        cumul_per_class_series.append(per_class_metrics_now)

        snapshot_counts = {
            cls: {
                k: int(pcm.get(cls, {}).get(k, 0))
                for k in ("TP", "FP", "TN", "FN")
            }
            for cls in class_names
        }
        multi_now = compute_multi_metrics(snapshot_counts)
        # malware specific
        mal_key = next(
            (
                k
                for k in snapshot_counts
                if k.lower() in ("malware", "malicious")
            ),
            None,
        )
        if mal_key:
            mcounts = snapshot_counts[mal_key]
            # Reuse binary metrics!
            mal_binary = compute_binary_metrics(mcounts)
            multi_now["malware_fpr"] = mal_binary["FPR"]
            multi_now["malware_fnr"] = mal_binary["FNR"]
            multi_now["malware_f1"] = mal_binary["f1"]
        else:
            multi_now["malware_fpr"] = 0.0
            multi_now["malware_fnr"] = 0.0
            multi_now["malware_f1"] = 0.0

        # malware specific
        mal_key = next(
            (
                k
                for k in snapshot_counts
                if k.lower() in ("malware", "malicious")
            ),
            None,
        )
        if mal_key:
            mcounts = snapshot_counts[mal_key]
            tp = mcounts.get("TP", 0)
            fp = mcounts.get("FP", 0)
            tn = mcounts.get("TN", 0)
            fn = mcounts.get("FN", 0)
            multi_now["malware_fpr"] = (
                (fp / (fp + tn)) if (fp + tn) > 0 else 0.0
            )
            multi_now["malware_fnr"] = (
                (fn / (fn + tp)) if (fn + tp) > 0 else 0.0
            )
            prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            multi_now["malware_f1"] = (
                (2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
            )
        else:
            multi_now["malware_fpr"] = 0.0
            multi_now["malware_fnr"] = 0.0
            multi_now["malware_f1"] = 0.0

        cumul_multi_series.append(multi_now)

        # binary summary
        if "binary_summary" in data:
            bm = data["binary_summary"]
            bm_counts = {
                k: int(bm.get(k, 0)) for k in ("TP", "FP", "TN", "FN")
            }
        else:
            mal = pcm.get("Malicious", {})
            tp = int(mal.get("TP", 0))
            fp = int(mal.get("FP", 0))
            fn = int(mal.get("FN", 0))
            tn = 0
            for k in pcm.keys():
                if k.lower() not in ("malware", "malicious"):
                    tn += int(pcm[k].get("TN", 0))
            bm_counts = {"TP": tp, "FP": fp, "TN": tn, "FN": fn}
        cumul_binary_series.append(compute_binary_metrics(bm_counts))

        # class counts TP + FN
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


def _choose_sparse_xticks(batch_count, labels):
    """
    Always return numeric positions for xticks (0..batch_count-1) as the first
    element. The second element is a list of labels where only a limited set
    of positions contain text (sparse labels); other positions are "".

    This prevents accidental use of string labels as x coordinates.
    """
    # full numeric positions for plotting (monotonic)
    positions = list(range(batch_count))

    if batch_count <= 20:
        # keep all labels for small series
        return positions, labels

    max_labels = 15
    step = max(1, batch_count // max_labels)
    indices = list(range(0, batch_count, step))
    if indices[-1] != batch_count - 1:
        indices.append(batch_count - 1)

    sparse_labels = [""] * batch_count
    for i in indices:
        # guard: labels might be shorter than batch_count
        if i < len(labels):
            sparse_labels[i] = labels[i]
        else:
            sparse_labels[i] = str(i)

    # NOTE: first element is the full numeric positions (not the sparse indices)
    return positions, sparse_labels


def plot_counts_series(
    series_of_dicts, outpath, title, xlabels=None, xlabel="Index"
):
    if series_of_dicts is None or not series_of_dicts:
        # print("[INFO] No data to plot for", title)
        return
    classes = list(next(iter(series_of_dicts)).keys())
    values_per_class = {
        c: [entry.get(c, 0) for entry in series_of_dicts] for c in classes
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
    plt.title(title)
    plt.legend(loc="best", fontsize=8)
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    plt.savefig(outpath)
    plt.close()
    # print(f"[SAVED] {outpath}")


def plot_confusion_matrix_from_final(final_per_class, outpath):
    mal = final_per_class.get("Malicious", {})
    tp = int(mal.get("TP", 0))
    fn = int(mal.get("FN", 0))
    fp = int(mal.get("FP", 0))
    tn = int(mal.get("TN", 0))
    cm = np.array([[tp, fn], [fp, tn]])
    labels = np.array([[f"TP\n{tp}", f"FN\n{fn}"], [f"FP\n{fp}", f"TN\n{tn}"]])
    plt.figure(figsize=(4, 4))
    im = plt.imshow(cm, interpolation="nearest", cmap="Blues")
    plt.colorbar(im, fraction=0.046, pad=0.04)
    plt.xticks([0, 1], ["Pred Malicious", "Pred Benign"], rotation=45)
    plt.yticks([0, 1], ["True Malicious", "True Benign"])
    for i in range(2):
        for j in range(2):
            plt.text(
                j, i, labels[i, j], ha="center", va="center", color="black"
            )
    plt.title("Confusion matrix (final snapshot)")
    plt.tight_layout()
    plt.savefig(outpath)
    plt.close()
    # print(f"[SAVED] {outpath}")


def main():
    parser = argparse.ArgumentParser(
        description="Plot testing performance metrics."
    )
    parser.add_argument(
        "-f",
        "--file",
        required=True,
        help="Path to testing log file or directory",
    )
    parser.add_argument(
        "-e", "--exp", required=True, help="Experiment identifier"
    )
    parser.add_argument(
        "--save_folder", required=False, help="Output folder", default=None
    )
    args = parser.parse_args()

    save_folder = args.save_folder
    if save_folder is not None:
        if not os.path.isdir(save_folder):
            raise NotADirectoryError(
                f"Output folder does not exist: {save_folder}"
            )
        base_dir = ensure_dir(save_folder)
    else:
        base_dir = ensure_dir("performance_metrics")

    file_path = args.file
    if os.path.isdir(file_path):
        file_path = os.path.join(file_path, "testing.log")
        print(f"[INFO] -f is a directory, using: {file_path}")

    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Log file not found: {file_path}")

    testing_dir = ensure_dir(os.path.join(base_dir, "testing", args.exp))
    print(f"[INFO] Output folder: {testing_dir}")

    entries = read_all_tests(file_path)
    if not entries:
        print("[ERROR] No testing entries parsed; exiting.")
        return

    (
        cumul_per_class_series,
        cumul_multi_series,
        cumul_binary_series,
        cumul_class_counts_series,
        cumulative_total_flows,
    ) = accumulate_test_metrics_cumulative_snapshots(entries)
    n = len(cumul_multi_series)
    # print(f"[INFO] Building plots for {n} snapshots")

    # aggregated class counts
    xlabels = (
        [str(x) for x in cumulative_total_flows]
        if any(cumulative_total_flows)
        else [str(i) for i in range(n)]
    )
    out_counts = os.path.join(
        testing_dir, "class_counts_aggregated_testing.png"
    )
    print(
        "[INFO] Plotting aggregated class counts (TP+FN per class so-far)..."
    )
    plot_counts_series(
        cumul_class_counts_series,
        out_counts,
        title="Aggregated class counts\n(Total labeled samples seen so-far)",
        xlabels=xlabels,
        xlabel="Cumulative flows seen",
    )

    # malware metrics
    print(
        "[INFO] Plotting malware metrics (FPR, FNR, F1, Accuracy) over snapshots..."
    )
    from base_utils import MALWARE_PLOT_METRICS, extract_metrics_for_plot

    malware_metrics_data = [
        extract_metrics_for_plot(m, MALWARE_PLOT_METRICS)
        for m in cumul_multi_series
    ]
    out_malware = os.path.join(
        testing_dir, "malware_metrics_aggregated_testing.png"
    )
    xvals = (
        cumulative_total_flows
        if any(cumulative_total_flows)
        else list(range(n))
    )
    plot_major_metrics_together(
        malware_metrics_data,
        out_malware,
        title="Malware metrics (Aggregated)\n(testing set: so-far)",
        xvals=xvals,
        xlabel="Total flows seen",
    )

    # FPR/FNR only
    print("[INFO] Saving FPR/FNR-only plot...")
    fpr_fnr_series = [
        {"FPR": m.get("malware_fpr", 0), "FNR": m.get("malware_fnr", 0)}
        for m in cumul_multi_series
    ]
    out_fprfnr = os.path.join(testing_dir, "malware_fpr_fnr_over_time.png")
    plot_major_metrics_together(
        fpr_fnr_series,
        out_fprfnr,
        title="Malware FPR & FNR over time\n(testing snapshots)",
        xvals=xvals,
        xlabel="Total flows seen",
    )

    # predicted vs seen
    print(
        "[INFO] Plotting predicted vs seen counts (per-snapshot) for Malicious & Benign..."
    )
    pred_seen_series = []
    for e in entries:
        seen = e.get("seen", {})
        pred = e.get("predicted", {})
        pred_seen_series.append(
            {
                "Seen Malicious": int(seen.get("Malicious", 0)),
                "Pred Malicious": int(pred.get("Malicious", 0)),
                "Seen Benign": int(seen.get("Benign", 0)),
                "Pred Benign": int(pred.get("Benign", 0)),
            }
        )
    out_predseen = os.path.join(
        testing_dir, "predicted_vs_seen_per_snapshot.png"
    )
    plot_counts_series(
        pred_seen_series,
        out_predseen,
        title="Predicted vs Seen counts per snapshot",
        xlabels=xlabels,
        xlabel="Snapshot / cumulative flows seen",
    )

    # confusion matrix (final snapshot)
    print("[INFO] Plotting final confusion matrix (final snapshot)...")
    final_per_class = cumul_per_class_series[-1]
    out_cm = os.path.join(testing_dir, "confusion_matrix_final.png")
    plot_confusion_matrix_from_final(final_per_class, out_cm)

    # summary
    last_multi = cumul_multi_series[-1]
    last_binary = cumul_binary_series[-1]
    final_per_class_table = cumul_per_class_series[-1]

    # print("[INFO] Writing summary...")
    lines = []
    lines.append("\n=== Main final metrics (Aggregated so-far) ===")
    lines.append(f"Accuracy:             {last_multi.get('accuracy', 0):.4f}")
    lines.append(
        f"Malware F1:           {last_multi.get('malware_f1', 0):.4f}"
    )
    lines.append(
        f"Malware FPR:          {last_multi.get('malware_fpr', 0):.4f}"
    )
    lines.append(
        f"Malware FNR:          {last_multi.get('malware_fnr', 0):.4f}"
    )
    lines.append(f"Macro F1:             {last_multi.get('macro_f1', 0):.4f}")
    lines.append(
        f"Precision:            {last_binary.get('precision', 0):.4f}"
    )
    lines.append(f"Recall:               {last_binary.get('recall', 0):.4f}")

    lines.append("\n=== Per-class metrics (final snapshot) ===")
    lines.append(
        f"{'Class':<15} {'TP':>8} {'TN':>8} {'FP':>8} {'FN':>8} {'Prec':>8} {'Rec':>8} {'F1':>8}"
    )
    for cls, m in final_per_class_table.items():
        lines.append(
            f"{cls:<15} {m.get('TP', 0):8d} {m.get('TN', 0):8d} {m.get('FP', 0):8d} {m.get('FN', 0):8d} {m.get('precision', 0.0):8.4f} {m.get('recall', 0.0):8.4f} {m.get('f1', 0.0):8.4f}"
        )

    lines.append(f"\nSummary for Experiment {args.exp}:")
    lines.append(f"Total test lines processed: {len(entries)}")

    summary_text = "\n".join(lines)
    summary_path = os.path.join(testing_dir, "summary.txt")
    with open(summary_path, "w") as f:
        f.write(summary_text)

    # print(f"[SAVED] {summary_path}")
    print(summary_text)


if __name__ == "__main__":
    main()
