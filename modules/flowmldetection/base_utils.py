import ast
import os
import traceback
from typing import Any, Dict


def safe_eval_dict(text: str) -> Any:
    try:
        return ast.literal_eval(text)
    except Exception as e:
        raise ValueError(f"Failed to parse dictionary: {e}")


def extract_braced_dict(text: str, start_pattern: str) -> str:
    """Extracts a dictionary string with balanced braces after a given pattern."""
    start = text.find(start_pattern)
    if start == -1:
        return None
    start = text.find("{", start)
    if start == -1:
        return None
    brace_count = 0
    end = start
    while end < len(text):
        if text[end] == "{":
            brace_count += 1
        elif text[end] == "}":
            brace_count -= 1
            if brace_count == 0:
                return text[start : end + 1]
        end += 1
    return None


def compute_binary_metrics(
    TP: int, TN: int, FP: int, FN: int
) -> Dict[str, float]:
    precision = TP / (TP + FP) if TP + FP else 0.0
    recall = TP / (TP + FN) if TP + FN else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0.0
    )
    accuracy = (TP + TN) / (TP + TN + FP + FN) if (TP + TN + FP + FN) else 0.0
    FPR = FP / (FP + TN) if (FP + TN) else 0.0
    FNR = FN / (FN + TP) if (FN + TP) else 0.0
    TPR = recall
    TNR = TN / (TN + FP) if (TN + FP) else 0.0
    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "FPR": FPR,
        "FNR": FNR,
        "TPR": TPR,
        "TNR": TNR,
    }


def compute_multiclass_metrics(
    cls: Dict[str, Dict[str, int]], total: int
) -> Dict[str, float]:
    precisions, recalls, f1s = [], [], []
    sum_TP = sum(v["TP"] for v in cls.values())
    sum_FP = sum(v["FP"] for v in cls.values())
    sum_FN = sum(v["FN"] for v in cls.values())

    for v in cls.values():
        tp, fp, fn = v["TP"], v["FP"], v["FN"]
        p = tp / (tp + fp) if tp + fp else 0.0
        r = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * p * r / (p + r) if (p + r) else 0.0
        precisions.append(p)
        recalls.append(r)
        f1s.append(f1)

    macro_p = sum(precisions) / len(precisions)
    macro_r = sum(recalls) / len(recalls)
    macro_f1 = sum(f1s) / len(f1s)

    micro_p = sum_TP / (sum_TP + sum_FP) if (sum_TP + sum_FP) else 0.0
    micro_r = sum_TP / (sum_TP + sum_FN) if (sum_TP + sum_FN) else 0.0
    micro_f1 = (
        2 * micro_p * micro_r / (micro_p + micro_r)
        if (micro_p + micro_r)
        else 0.0
    )

    accuracy = sum_TP / total if total else 0.0

    return {
        "accuracy": accuracy,
        "macro_precision": macro_p,
        "macro_recall": macro_r,
        "macro_f1": macro_f1,
        "micro_precision": micro_p,
        "micro_recall": micro_r,
        "micro_f1": micro_f1,
    }


def process_file(path: str, parse_fn) -> Dict[str, Any]:
    metrics = {
        "malicious": [],
        "multiclass": [],
        "per_class": [],
    }
    counters = {"total": 0, "errors": 0, "unusual": 0}

    with open(path) as f:
        for line in f:
            if "Per-class metrics:" not in line:
                continue
            counters["total"] += 1
            try:
                parsed = parse_fn(line)
                total = parsed["total"]
                cls = parsed["class_metrics"]
                mal = cls.get("Malicious", {})
                ben = cls.get("Benign", {})

                per_class_acc = {}
                for class_name, metrics_dict in cls.items():
                    tp = metrics_dict.get("TP", 0)
                    fn = metrics_dict.get("FN", 0)
                    per_class_acc[class_name] = (
                        tp / (tp + fn) if (tp + fn) else 0
                    )

                binm = compute_binary_metrics(
                    mal.get("TP", 0),
                    ben.get("TP", 0),
                    mal.get("FP", 0),
                    mal.get("FN", 0),
                )
                multi = compute_multiclass_metrics(cls, total)

                metrics["malicious"].append(binm)
                metrics["multiclass"].append(multi)
                metrics["per_class"].append(per_class_acc)

                for group in (binm, multi, per_class_acc):
                    if any(
                        (v != v) or (v == float("inf")) for v in group.values()
                    ):
                        counters["unusual"] += 1
                        break

            except Exception:
                print(f"Error parsing line: {line.strip()}")
                traceback.print_exc()
                counters["errors"] += 1
                counters["unusual"] += 1

    return {"metrics": metrics, "counters": counters}


def print_and_save_summary(
    metrics: Dict[str, Any],
    counters: Dict[str, int],
    exp: str,
    out_dir: str,
) -> None:
    exp_dir = os.path.join(out_dir, exp)
    os.makedirs(exp_dir, exist_ok=True)
    last_bin = metrics["malicious"][-1] if metrics["malicious"] else {}
    last_mul = metrics["multiclass"][-1] if metrics["multiclass"] else {}

    lines = [f"Final Metric Values for Experiment {exp}\n"]

    lines.append("=== Binary (Benign vs Malicious) ===")
    for name in (
        "FPR",
        "FNR",
        "TNR",
        "TPR",
        "f1",
        "accuracy",
        "precision",
        "recall",
    ):
        v = last_bin.get(name if name != "f1" else "f1", 0)
        lines.append(
            f"Final {name.upper() if name != 'f1' else 'F1 Score'}: {v:.4f}"
        )

    lines.append("\n=== Per Class Stats ===")
    last_per = metrics["per_class"][-1] if metrics["per_class"] else {}
    for class_name, acc in sorted(last_per.items()):
        lines.append(f"{class_name} Accuracy: {acc:.4f}")

    lines.append("\n=== Multi-class ===")
    lines.append(f"Accuracy: {last_mul.get('accuracy', 0):.4f}")
    lines.append(f"Macro Precision: {last_mul.get('macro_precision', 0):.4f}")
    lines.append(f"Macro Recall:    {last_mul.get('macro_recall', 0):.4f}")
    lines.append(f"Macro F1:        {last_mul.get('macro_f1', 0):.4f}")
    lines.append(f"Micro Precision: {last_mul.get('micro_precision', 0):.4f}")
    lines.append(f"Micro Recall:    {last_mul.get('micro_recall', 0):.4f}")
    lines.append(f"Micro F1:        {last_mul.get('micro_f1', 0):.4f}")

    lines.append(f"\nSummary for Experiment {exp}:")
    lines.append(f"Total lines read:        {counters['total']}")
    lines.append(f"Lines with parse errors: {counters['errors']}")
    lines.append(f"Unusual (NaN/Inf):       {counters['unusual']}")

    summary = "\n".join(lines)
    print(summary)
    with open(os.path.join(exp_dir, "final_metrics.txt"), "w") as f:
        f.write(summary)
