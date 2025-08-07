# base_utils.py

import os

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
    # split on commas, then on colons/braces
    parts = line.strip().split(";")[0].split(", ")
    data = {}
    # Total labels, testing size we ignore here
    for part in parts:
        if part.startswith("Seen labels:"):
            seen = eval(part.split(":", 1)[1].strip())
            data["seen"] = seen
        elif part.startswith("Predicted labels:"):
            pred = eval(part.split(":", 1)[1].strip())
            data["predicted"] = pred
        elif part.startswith("Per-class metrics:"):
            pcm = eval(part.split(":", 1)[1].strip())
            data["per_class"] = pcm
    # derive batch number by counting previous calls, or embed if log includes it
    return data


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
    return {
        "accuracy": accuracy,
        "macro_precision": np.mean(precisions),
        "macro_recall": np.mean(recalls),
        "macro_f1": np.mean(f1s),
        "micro_precision": TP / (TP + FP) if TP + FP > 0 else 0.0,
        "micro_recall": TP / (TP + FN) if TP + FN > 0 else 0.0,
        "micro_f1": (
            2
            * (TP / (TP + FP))
            * (TP / (TP + FN))
            / ((TP / (TP + FP)) + (TP / (TP + FN)))
            if TP + FP > 0 and TP + FN > 0
            else 0.0
        ),
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
