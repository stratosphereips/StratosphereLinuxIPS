# base_utils.py  -- drop-in replacement
import os
import ast
import re
import traceback
from typing import Dict, List, Optional

import numpy as np
import matplotlib.pyplot as plt


# ------------------------
# Filesystem helpers
# ------------------------
def ensure_dir(path: str) -> str:
    """
    Ensure directory exists, return the normalized path.
    """
    p = os.path.abspath(path)
    os.makedirs(p, exist_ok=True)
    return p


# ------------------------
# Parsing helpers
# ------------------------
def _safe_literal_eval(s: str):
    try:
        return ast.literal_eval(s)
    except Exception:
        # fallback: try replacing single quotes with double quotes for malformed JSON-like strings
        try:
            return ast.literal_eval(s.replace("'", '"'))
        except Exception:
            raise


def parse_training_log_line(line: str) -> Optional[Dict]:
    """
    Parse one line of the 'new' training log format you provided.

    Expected example format (single line):
      Total labels: 500, Validation size: 49, Validation seen labels: {'Malicious': 36, 'Benign': 13},
      Validation predicted labels: {'Malicious': 38, 'Benign': 11}, Validation metrics: {'TP': 36, 'FP': 2, 'FN': 0, 'TN': 11},
      Training size: 450, Training seen labels: {...}, Training predicted labels: {...}, Training metrics: {...}

    Returns a dict with keys:
      - 'total_labels' (float) if present
      - 'testing_size' (int) if present
      - 'training_size' (int) if present
      - 'seen' (dict) : validation seen labels (if present)
      - 'predicted' (dict) : validation predicted labels (if present)
      - 'per_class' (dict) : per-class counts for validation in canonical form:
            {'Malicious': {'TP':..., 'FP':..., 'TN':..., 'FN':...}, 'Benign': {...}}
      - 'training_seen', 'training_predicted', 'training_per_class' similarly for training section if present.

    Returns None if parsing fails.
    """
    out = {}
    try:
        s = line.strip()

        # total labels (float or int)
        m_total = re.search(
            r"Total labels\s*:\s*([0-9]+(?:\.[0-9]+)?)", s, re.IGNORECASE
        )
        if m_total:
            val = m_total.group(1)
            out["total_labels"] = float(val) if "." in val else int(val)

        # Testing/Validation size (two variants: 'Validation size' or 'Testing size')
        m_test_size = re.search(
            r"(?:Validation|Testing) size\s*:\s*(\d+)", s, re.IGNORECASE
        )
        if m_test_size:
            out["testing_size"] = int(m_test_size.group(1))

        # Training size (optional)
        m_train_size = re.search(
            r"Training size\s*:\s*(\d+)", s, re.IGNORECASE
        )
        if m_train_size:
            out["training_size"] = int(m_train_size.group(1))

        # Validation Seen labels / Predicted labels
        m_seen = re.search(
            r"(?:Validation|Testing) seen labels\s*:\s*(\{.*?\})", s
        )
        if m_seen:
            out["seen"] = _safe_literal_eval(m_seen.group(1))

        m_pred = re.search(
            r"(?:Validation|Testing) predicted labels\s*:\s*(\{.*?\})", s
        )
        if m_pred:
            out["predicted"] = _safe_literal_eval(m_pred.group(1))

        # Validation metrics: dictionary with TP/FP/TN/FN
        m_metrics = re.search(
            r"(?:Validation|Testing) metrics\s*:\s*(\{.*?\})", s
        )
        if m_metrics:
            metrics = _safe_literal_eval(m_metrics.group(1))
            tp = int(metrics.get("TP", 0))
            fp = int(metrics.get("FP", 0))
            fn = int(metrics.get("FN", 0))
            tn = int(metrics.get("TN", 0))
            # canonical per_class with Malicious entry (and inverted Benign)
            per_class = {
                "Malicious": {"TP": tp, "FP": fp, "TN": tn, "FN": fn},
                "Benign": {"TP": tn, "FP": fn, "TN": tp, "FN": fp},
            }
            out["per_class"] = per_class

        # Training part (if present). Use "Training seen labels", "Training predicted labels", "Training metrics"
        m_seen_tr = re.search(r"Training seen labels\s*:\s*(\{.*?\})", s)
        if m_seen_tr:
            out["training_seen"] = _safe_literal_eval(m_seen_tr.group(1))

        m_pred_tr = re.search(r"Training predicted labels\s*:\s*(\{.*?\})", s)
        if m_pred_tr:
            out["training_predicted"] = _safe_literal_eval(m_pred_tr.group(1))

        m_metrics_tr = re.search(r"Training metrics\s*:\s*(\{.*?\})", s)
        if m_metrics_tr:
            metrics = _safe_literal_eval(m_metrics_tr.group(1))
            tp = int(metrics.get("TP", 0))
            fp = int(metrics.get("FP", 0))
            fn = int(metrics.get("FN", 0))
            tn = int(metrics.get("TN", 0))
            training_per_class = {
                "Malicious": {"TP": tp, "FP": fp, "TN": tn, "FN": fn},
                "Benign": {"TP": tn, "FP": fn, "TN": tp, "FN": fp},
            }
            out["training_per_class"] = training_per_class

        # If per_class is still missing but we have seen/predicted entries with class names,
        # create zero-count placeholders (can't infer TP/FP/TN/FN without explicit metrics).
        if "per_class" not in out and "seen" in out and "predicted" in out:
            seen_keys = set(out["seen"].keys())
            if seen_keys:
                pc = {}
                for k in seen_keys:
                    pc[k] = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
                out["per_class"] = pc

        return out
    except Exception as e:
        print("[WARN] parse_training_log_line failed:", e)
        traceback.print_exc()
        return None


def parse_testing_log_line(line: str) -> Optional[Dict]:
    """
    Parse one line of the testing log (single format).

    Expected example:
    Total flows: 54; Seen labels: {'Malicious': 42, 'Benign': 12}; Predicted labels: {'Malicious': 42, 'Benign': 12}; Malware metrics (TP/FP/TN/FN): {'TP': 42, 'FP': 0, 'TN': 12, 'FN': 0};

    Returns dict with:
      - total_flows (int)
      - seen (dict)
      - predicted (dict)
      - per_class: canonical per-class counts dict (Malicious/Benign)
      - binary_summary: raw TP/FP/TN/FN for Malicious class
    """
    out = {}
    try:
        s = line.strip()
        m_total = re.search(r"Total flows\s*:\s*(\d+)", s, re.IGNORECASE)
        if m_total:
            out["total_flows"] = int(m_total.group(1))

        m_seen = re.search(r"Seen labels\s*:\s*(\{.*?\})", s)
        if m_seen:
            out["seen"] = _safe_literal_eval(m_seen.group(1))

        m_pred = re.search(r"Predicted labels\s*:\s*(\{.*?\})", s)
        if m_pred:
            out["predicted"] = _safe_literal_eval(m_pred.group(1))

        # Malware metrics dict
        m_metrics = re.search(
            r"Malware metrics(?:\s*\(.*?\))?\s*[:=]\s*(\{.*?\})",
            s,
            re.IGNORECASE,
        )
        if m_metrics:
            bm = _safe_literal_eval(m_metrics.group(1))
            tp = int(bm.get("TP", 0))
            fp = int(bm.get("FP", 0))
            tn = int(bm.get("TN", 0))
            fn = int(bm.get("FN", 0))
            out["per_class"] = {
                "Malicious": {"TP": tp, "FP": fp, "TN": tn, "FN": fn},
                "Benign": {"TP": tn, "FP": fn, "TN": tp, "FN": fp},
            }
            out["binary_summary"] = {"TP": tp, "FP": fp, "TN": tn, "FN": fn}
        return out
    except Exception as e:
        print("[WARN] parse_testing_log_line failed:", e)
        traceback.print_exc()
        return None


# ------------------------
# Metric computations
# ------------------------
def compute_binary_metrics(counts: Dict[str, int]) -> Dict[str, float]:
    """
    Given a dict with integer counts: {'TP':..., 'FP':..., 'TN':..., 'FN':...}
    return a dict with:
      accuracy, precision, recall, f1
    """
    tp = int(counts.get("TP", 0))
    fp = int(counts.get("FP", 0))
    tn = int(counts.get("TN", 0))
    fn = int(counts.get("FN", 0))

    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total > 0 else 0.0

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        (2 * precision * recall / (precision + recall))
        if (precision + recall) > 0
        else 0.0
    )

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def compute_multi_metrics(
    per_class: Dict[str, Dict[str, int]],
) -> Dict[str, float]:
    """
    Given a per_class dict:
      {class_name: {'TP':..., 'FP':..., 'TN':..., 'FN':...}, ...}
    returns:
      {
        "accuracy",
        "macro_precision", "macro_recall", "macro_f1",
        "micro_precision", "micro_recall", "micro_f1"
      }
    """
    # accumulate counts
    TP_total = 0
    FP_total = 0
    TN_total = 0
    FN_total = 0
    precisions = []
    recalls = []
    f1s = []

    for cls, c in per_class.items():
        tp = int(c.get("TP", 0))
        fp = int(c.get("FP", 0))
        tn = int(c.get("TN", 0))
        fn = int(c.get("FN", 0))
        TP_total += tp
        FP_total += fp
        TN_total += tn
        FN_total += fn

        p = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        r = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * p * r / (p + r)) if (p + r) > 0 else 0.0
        precisions.append(p)
        recalls.append(r)
        f1s.append(f1)

    total = TP_total + FP_total + TN_total + FN_total
    accuracy = (TP_total + TN_total) / total if total > 0 else 0.0

    micro_precision = (
        TP_total / (TP_total + FP_total) if (TP_total + FP_total) > 0 else 0.0
    )
    micro_recall = (
        TP_total / (TP_total + FN_total) if (TP_total + FN_total) > 0 else 0.0
    )
    micro_f1 = (
        (2 * micro_precision * micro_recall / (micro_precision + micro_recall))
        if (micro_precision + micro_recall) > 0
        else 0.0
    )

    macro_precision = float(np.mean(precisions)) if precisions else 0.0
    macro_recall = float(np.mean(recalls)) if recalls else 0.0
    macro_f1 = float(np.mean(f1s)) if f1s else 0.0

    return {
        "accuracy": accuracy,
        "macro_precision": macro_precision,
        "macro_recall": macro_recall,
        "macro_f1": macro_f1,
        "micro_precision": micro_precision,
        "micro_recall": micro_recall,
        "micro_f1": micro_f1,
    }


# ------------------------
# Plotting helpers
# ------------------------
def plot_major_metrics_together(
    series: List[Dict[str, float]],
    outpath: str,
    title: str = "Metrics over tests",
    xvals: Optional[List] = None,
    xlabel: str = "Index",
):
    """
    Plot multiple named metrics from a series of dicts.
    series: list where each entry is a dict {metric_name: numeric_value, ...}
    Example:
      series = [{'accuracy':0.9,'precision':0.8}, {'accuracy':0.92,'precision':0.85},...]
    or combined series where keys are 'Validation'/'Training' and values numeric.
    """
    if series is None or len(series) == 0:
        print(f"[INFO] plot_major_metrics_together: no data for {outpath}")
        return

    # Ensure output directory exists
    outdir = os.path.dirname(os.path.abspath(outpath))
    if outdir:
        os.makedirs(outdir, exist_ok=True)

    # Determine the full set of metric names across all entries (preserve order from first entry)
    metric_names = []
    first_keys = list(series[0].keys())
    for k in first_keys:
        if k not in metric_names:
            metric_names.append(k)
    # Add any other keys that appear later
    for entry in series[1:]:
        for k in entry.keys():
            if k not in metric_names:
                metric_names.append(k)

    # Build lists of values for each metric
    metric_values = {m: [] for m in metric_names}
    for entry in series:
        for m in metric_names:
            metric_values[m].append(entry.get(m, 0.0))

    # X axis
    n = len(next(iter(metric_values.values())))
    if xvals is None:
        x_axis = list(range(1, n + 1))
    else:
        # if xvals length doesn't match n, fallback to indices
        try:
            if len(xvals) == n:
                x_axis = xvals
            else:
                x_axis = list(range(1, n + 1))
        except Exception:
            x_axis = list(range(1, n + 1))

    # Plot
    plt.figure(figsize=(8, 4.5))
    for m in metric_names:
        vals = metric_values[m]
        plt.plot(x_axis, vals, label=m, linewidth=1.5, marker=None)

    plt.xlabel(xlabel)
    plt.ylabel("Value")
    plt.title(title)
    plt.legend(loc="best", fontsize=8)

    # Adjust y-limits: if values within [0,1] zoom, otherwise allow full range
    all_vals = [v for vals in metric_values.values() for v in vals]
    finite_vals = [float(x) for x in all_vals if np.isfinite(x)]
    if finite_vals:
        min_val = min(finite_vals)
        max_val = max(finite_vals)
        if max_val > min_val:
            margin = 0.05 * (max_val - min_val)
        else:
            margin = 0.05
        lower = min_val - margin
        upper = max_val + margin
        # If metrics mostly probabilities (0..1) and the span is small, restrict axis to [0,1]
        if 0 <= min_val and max_val <= 1:
            if upper - lower < 0.5:
                plt.ylim(max(0, lower), min(1, upper))
            else:
                plt.ylim(0, 1)
        else:
            plt.ylim(lower, upper)

    plt.grid(axis="y", linestyle=":", linewidth=0.5)
    plt.tight_layout()
    plt.savefig(outpath)
    plt.close()
    print(f"[SAVED] {outpath}")
