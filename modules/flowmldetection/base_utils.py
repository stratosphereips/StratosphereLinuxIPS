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
        'total_labels': float,
        'testing_size': int,
        'seen': {'Background':…, …},
        'predicted': {…},
        'per_class': {
           'Background': {'TP':…, 'FP':…, 'TN':…, 'FN':…}, …
        },
        'training_size': int (optional, only if train/val split),
        'training_seen': dict (optional, only if train/val split),
        'training_predicted': dict (optional, only if train/val split),
        'training_per_class': dict (optional, only if train/val split)
      }
    """
    result = {}

    try:
        # Check if this line has training data (train/val split format)
        has_training_data = "Training errors:" in line

        if has_training_data:
            # Split the line into test part and training part
            parts = line.split(", Training errors: ")
            test_part = parts[0]
            training_part = parts[1]
        else:
            # Only test data format
            test_part = line
            training_part = None

        # Parse test data (always present)
        parse_section(test_part, result, prefix="")

        # Parse training data if present
        if training_part:
            parse_section(training_part, result, prefix="training_")

    except Exception as e:
        print(f"Failed to parse log line: {e}")
        return None

    return result


def parse_section(section_text, result_dict, prefix=""):
    """
    Helper function to parse a section (either test or training data)
    """
    # Extract Total/Training labels
    labels_key = "Training size:" if prefix else "Total labels:"
    result_key = f"{prefix}total_labels" if not prefix else f"{prefix}size"

    if labels_key in section_text:
        if prefix:  # Training size is an integer
            size_str = (
                section_text.split(labels_key, 1)[1].split(",")[0].strip()
            )
            result_dict[result_key] = int(size_str)
        else:  # Total labels is a float
            total_str = (
                section_text.split(labels_key, 1)[1].split(",")[0].strip()
            )
            result_dict[result_key] = float(total_str)

    # Extract Testing/Training size (only for test section when no training data)
    if not prefix and "Testing size:" in section_text:
        test_str = (
            section_text.split("Testing size:", 1)[1].split(",")[0].strip()
        )
        result_dict["testing_size"] = int(test_str)

    # Extract Seen/Training seen labels
    seen_key = "Training seen labels:" if prefix else "Seen labels:"
    predicted_key = (
        "Training predicted labels:" if prefix else "Predicted labels:"
    )

    if seen_key in section_text:
        if predicted_key in section_text:
            seen_str = (
                section_text.split(seen_key, 1)[1]
                .split(f", {predicted_key}")[0]
                .strip()
            )
        else:
            # Fallback - split on next comma-space pattern that looks like a key
            seen_str = (
                section_text.split(seen_key, 1)[1].split(", ")[0].strip()
            )
            # Remove any trailing comma
            if seen_str.endswith(","):
                seen_str = seen_str[:-1]

        result_dict[f"{prefix}seen"] = ast.literal_eval(seen_str)

    # Extract Predicted/Training predicted labels
    if predicted_key in section_text:
        per_class_key = (
            "Training per-class metrics:" if prefix else "Per-class metrics:"
        )

        if per_class_key in section_text:
            pred_str = (
                section_text.split(predicted_key, 1)[1]
                .split(f", {per_class_key}")[0]
                .strip()
            )
        else:
            # Fallback
            pred_str = (
                section_text.split(predicted_key, 1)[1].split(", ")[0].strip()
            )
            if pred_str.endswith(","):
                pred_str = pred_str[:-1]

        result_dict[f"{prefix}predicted"] = ast.literal_eval(pred_str)

    # Extract Per-class/Training per-class metrics
    per_class_key = (
        "Training per-class metrics:" if prefix else "Per-class metrics:"
    )

    if per_class_key in section_text:
        per_class_str = section_text.split(per_class_key, 1)[1].strip()
        # Remove any trailing content that's not part of the dict
        if per_class_str.endswith("}"):
            # Find the matching closing brace
            brace_count = 0
            end_pos = 0
            for i, char in enumerate(per_class_str):
                if char == "{":
                    brace_count += 1
                elif char == "}":
                    brace_count -= 1
                    if brace_count == 0:
                        end_pos = i + 1
                        break
            per_class_str = per_class_str[:end_pos]

        result_dict[f"{prefix}per_class"] = ast.literal_eval(per_class_str)


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
    series, outpath, title="Metrics over tests", xvals=None, xlabel="Test #"
):
    """
    Plots multiple metrics from a series of dictionaries on a single graph and saves the plot to a file.
    Backwards-compatible, but robust to:
      - xvals being numeric or string labels (including many empty labels),
      - missing metric keys in some series entries,
      - series that represent counts (values > 1).
    """

    if series is None or not series:
        print("No data to plot for", title)
        return

    # collect metric keys and ensure deterministic order
    what_metrics = list(series[0].keys())
    # build a dict metric -> list of values (use np.nan if missing to avoid wrong connections)
    print_dict = {metric: [] for metric in what_metrics}
    n = len(series)
    for metric in what_metrics:
        vals = []
        for s in series:
            # use get to avoid KeyError; if key missing, use np.nan so matplotlib breaks line
            v = s.get(metric, np.nan)
            # ensure numeric or nan
            vals.append(np.nan if v is None else v)
        print_dict[metric] = vals

    # Determine numeric x positions for plotting and tick positions/labels
    # If xvals is None -> use 1..n (1-based to match previous behavior)
    if xvals is None:
        x_positions = list(range(1, n + 1))
        # show all ticks if not too crowded; otherwise sparsify (show subset)
        tick_positions = x_positions
        tick_labels = [str(x) for x in x_positions]
    else:
        # If all elements of xvals are numeric (int/float), use them as x positions
        all_numeric = (
            all(
                isinstance(v, (int, float, np.integer, np.floating))
                for v in xvals
            )
            and len(xvals) == n
        )

        if all_numeric:
            # use numeric x axis exactly as provided
            x_positions = list(map(float, xvals))
            # sparsify ticks if many points
            if n <= 20:
                tick_positions = x_positions
                tick_labels = [
                    str(int(x)) if float(x).is_integer() else str(x)
                    for x in x_positions
                ]
            else:
                # pick ~15 ticks including last
                max_ticks = 15
                step = max(1, n // max_ticks)
                indices = list(range(0, n, step))
                if indices[-1] != n - 1:
                    indices.append(n - 1)
                tick_positions = [x_positions[i] for i in indices]
                tick_labels = [
                    (
                        str(int(x_positions[i]))
                        if float(x_positions[i]).is_integer()
                        else str(x_positions[i])
                    )
                    for i in indices
                ]
        else:
            # xvals are labels (strings or mixed) -> plot at indices 0..n-1
            x_positions = list(range(n))
            # choose tick indices where label is non-empty, or sparsify if none or too many
            provided_labels = ["" if v is None else str(v) for v in xvals]
            non_empty_indices = [
                i for i, lab in enumerate(provided_labels) if lab.strip() != ""
            ]
            if len(non_empty_indices) == 0:
                # no labels provided -> fallback: show a sparse set of batch numbers
                if n <= 20:
                    tick_positions = x_positions
                    tick_labels = [str(i) for i in x_positions]
                else:
                    max_ticks = 15
                    step = max(1, n // max_ticks)
                    indices = list(range(0, n, step))
                    if indices[-1] != n - 1:
                        indices.append(n - 1)
                    tick_positions = indices
                    tick_labels = [str(i) for i in indices]
            else:
                # show only the non-empty labels (this avoids label crowding)
                tick_positions = non_empty_indices
                tick_labels = [provided_labels[i] for i in non_empty_indices]

    # Plotting: always use numeric x_positions for plotting; missing values are np.nan
    plt.figure()
    for metric, values in print_dict.items():
        # ensure length matches n by trunc/pad with np.nan if needed
        vals = list(values)
        if len(vals) < n:
            vals = vals + [np.nan] * (n - len(vals))
        elif len(vals) > n:
            vals = vals[:n]
        # Convert to numpy array (matplotlib will break lines at np.nan)
        y = np.array(vals, dtype=float)
        plt.plot(x_positions, y, label=metric)

    plt.xlabel(xlabel)
    plt.ylabel("Value")

    # compute global min/max ignoring NaNs
    all_values = [
        v
        for values in print_dict.values()
        for v in values
        if (not (isinstance(v, float) and np.isnan(v)))
    ]
    if len(all_values) == 0:
        min_val, max_val = 0.0, 1.0
    else:
        min_val = float(min(all_values))
        max_val = float(max(all_values))

    # y-limits: if values are metrics (<=1) keep previous zoom behaviour; if counts (>1), autoscale to counts
    if max_val <= 1.0:
        margin = 0.05 * (max_val - min_val) if max_val > min_val else 0.05
        lower = max(0.0, min_val - margin)
        upper = min(1.0, max_val + margin)
        # keep tight window only when the spread is small; otherwise keep [0,1]
        if upper - lower < 0.5:
            plt.ylim(lower, upper)
        else:
            plt.ylim(0, 1)
    else:
        # counts / large values: start from 0 up to a little above max
        upper = max_val * 1.05 if max_val > 0 else 1.0
        plt.ylim(0, upper)

    plt.title(title)
    plt.legend()

    # set ticks & labels
    try:
        # if tick_positions were created as indices but x_positions are 1..n, map indices accordingly
        if xvals is None:
            plt.xticks(tick_positions, tick_labels, rotation=45, ha="right")
        else:
            # when x_positions are range(n) (0..n-1) but user expects 1-based, that's handled by caller preparing xvals
            plt.xticks(tick_positions, tick_labels, rotation=45, ha="right")
    except Exception:
        # fallback: default ticks
        plt.xticks(rotation=45, ha="right")

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
