# base_utils.py

import ast
import os

import matplotlib.pyplot as plt
import numpy as np


def ensure_dir(path):
    os.makedirs(path, exist_ok=True)
    return path


def parse_training_log_line(line):
    """
    Parse one line of training log, returning a dict:
      {
        'batch': int,
        'seen': {'Background':…, …},
        'predicted': {…},
        'per_class': {
           'Background': {'TP':…, 'FP':…, 'TN':…, 'FN':…}, …
        }
      }
    """
    result = {}

    try:
        # Extract Total labels
        if "Total labels:" in line:
            total_str = line.split("Total labels:", 1)[1].split(",")[0].strip()
            result["total_labels"] = float(total_str)

        # Extract Testing size
        if "Testing size:" in line:
            test_str = line.split("Testing size:", 1)[1].split(",")[0].strip()
            result["testing_size"] = int(test_str)

        # Extract Seen labels
        if "Seen labels:" in line:
            seen_str = (
                line.split("Seen labels:", 1)[1]
                .split(", Predicted labels:")[0]
                .strip()
            )
            result["seen"] = ast.literal_eval(seen_str)

        # Extract Predicted labels
        if "Predicted labels:" in line:
            pred_str = (
                line.split("Predicted labels:", 1)[1]
                .split(", Per-class metrics:")[0]
                .strip()
            )
            result["predicted"] = ast.literal_eval(pred_str)

        # Extract Per-class metrics
        if "Per-class metrics:" in line:
            per_class_str = line.split("Per-class metrics:", 1)[1].strip()
            result["per_class"] = ast.literal_eval(per_class_str)

    except Exception as e:
        print(f"Failed to parse log line: {e}")
        return None

    return result


def parse_testing_log_line(line):
    """
    Parse one line of testing log, returning a dict:
      {
        'total_flows': int,
        'seen': {...},
        'predicted': {...},
        'per_class': {…},
        'binary_summary': {'TP':…, 'FP':…, 'TN':…, 'FN':…}   # for benign/malicious only
      }
    """
    # split on semicolons
    segments = line.strip().split(";")
    data = {}
    for seg in segments:
        seg = seg.strip()
        if seg.startswith("Total flows:"):
            data["total_flows"] = int(seg.split(":")[1])
        elif seg.startswith("Seen labels:"):
            data["seen"] = eval(seg.split(":", 1)[1].strip())
        elif seg.startswith("Predicted labels:"):
            data["predicted"] = eval(seg.split(":", 1)[1].strip())
        elif seg.startswith("Per-class metrics:"):
            data["per_class"] = eval(seg.split(":", 1)[1].strip())
        elif seg.startswith("Benign/Malicious only:"):
            bm = seg.split(":", 1)[1].strip()
            # e.g. TP=214, FP=0, TN=8, FN=7
            kv = dict(item.split("=") for item in bm.split(", "))
            data["binary_summary"] = {k: int(v) for k, v in kv.items()}
    return data


def compute_multi_metrics(per_class):
    """
    Given per_class dict, return dict with
      accuracy, macro_precision, macro_recall, macro_f1,
      micro_precision, micro_recall, micro_f1
    """
    # accumulate counts
    TP = FP = TN = FN = 0
    precisions = []
    recalls = []
    f1s = []
    for cls, m in per_class.items():
        tp, fp, tn, fn = m["TP"], m["FP"], m["TN"], m["FN"]
        TP += tp
        FP += fp
        TN += tn
        FN += fn
        p = tp / (tp + fp) if tp + fp > 0 else 0.0
        r = tp / (tp + fn) if tp + fn > 0 else 0.0
        f1 = 2 * p * r / (p + r) if p + r > 0 else 0.0
        precisions.append(p)
        recalls.append(r)
        f1s.append(f1)
    accuracy = (
        (TP + TN) / (TP + TN + FP + FN) if TP + TN + FP + FN > 0 else 0.0
    )
    prec = TP / (TP + FP) if TP + FP > 0 else 0.0
    rec = TP / (TP + FN) if TP + FN > 0 else 0.0
    f1 = (2 * prec * rec) / (prec + rec) if prec + rec > 0 else 0.0
    return {
        "accuracy": accuracy,
        "macro_precision": np.mean(precisions),
        "macro_recall": np.mean(recalls),
        "macro_f1": np.mean(f1s),
        "micro_precision": prec,
        "micro_recall": rec,
        "micro_f1": f1,
    }


def compute_binary_metrics(binary_counts_dict):
    """
    Given a dict with keys TP, FP, TN, FN, compute accuracy, precision, recall, f1.
    """
    tp = binary_counts_dict.get("TP", 0)
    fp = binary_counts_dict.get("FP", 0)
    tn = binary_counts_dict.get("TN", 0)
    fn = binary_counts_dict.get("FN", 0)

    accuracy = (
        (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0
    )
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def plot_major_metrics_together(
    series, outpath, title="Metrics over tests", xvals=None
):
    if series is None or not series or series == []:
        print("No data to plot for", title)
        return
    what_metrics = series[0].keys()
    print_dict = {metric: [] for metric in what_metrics}
    for metric in what_metrics:
        metric_values = [s[metric] for s in series]
        print_dict[metric] = metric_values

    plt.figure()
    if xvals is not None:
        x_axis = xvals
    else:
        x_axis = list(range(1, len(next(iter(print_dict.values()))) + 1))

    for metric, values in print_dict.items():
        plt.plot(x_axis, values, label=metric)
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
        for cls, metrics in per_class_series.items():
            plt.plot(metrics[metric], label=cls)
        plt.xlabel("Test #")
        plt.ylabel(f"{metric} Count (log scale)")
        plt.yscale("log")
        plt.title(f"{metric} over tests for all classes")
        plt.legend()
        plt.tight_layout()
        plt.savefig(os.path.join(testing_dir, f"all_classes_{metric}_log.png"))
        plt.close()
