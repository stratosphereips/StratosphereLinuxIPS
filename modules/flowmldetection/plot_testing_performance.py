import argparse
import ast
import os
import re
import traceback
from typing import Any, Dict, List

import matplotlib.pyplot as plt


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


def parse_metrics_line(line: str) -> Dict[str, Any]:
    """
    Returns:
        {
            'total': int,
            'seen_labels': {'Background':…, 'Malicious':…, 'Benign':…},
            'pred_labels': {...},
            'class_metrics': {'Background':{TP,FP,TN,FN}, …}
        }
    """
    total_match = re.search(r"Total flows:\s*(\d+)", line)
    seen_dict_str = extract_braced_dict(line, "Seen labels:")
    pred_dict_str = extract_braced_dict(line, "Predicted labels:")
    per_class_dict_str = extract_braced_dict(line, "Per-class metrics:")
    # Optionally parse Benign/Malicious only metrics if needed in future:
    # bm_match = re.search(r"Benign/Malicious only:\s*TP=(\d+), FP=(\d+), TN=(\d+), FN=(\d+)", line)

    if not (
        total_match and seen_dict_str and pred_dict_str and per_class_dict_str
    ):
        raise ValueError(
            "Line missing one of Total/Seen/Predicted/Per-class sections"
        )

    total = int(total_match.group(1))
    seen = safe_eval_dict(seen_dict_str)
    pred = safe_eval_dict(pred_dict_str)
    cls_metrics = safe_eval_dict(per_class_dict_str)

    return {
        "total": total,
        "seen_labels": seen,
        "pred_labels": pred,
        "class_metrics": cls_metrics,
    }


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
    # Per-class values
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

    # micro
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


def process_file(path: str) -> Dict[str, Any]:
    metrics = {
        "malicious": [],  # binary Malicious vs Benign
        "overall": [],  # binary Non-BG vs BG
        "multiclass": [],  # overall multi-class
    }
    counters = {"total": 0, "errors": 0, "unusual": 0}

    with open(path) as f:
        for line in f:
            if "Per-class metrics:" not in line:
                continue
            counters["total"] += 1
            try:
                parsed = parse_metrics_line(line)
                total = parsed["total"]
                cls = parsed["class_metrics"]
                mal = cls.get("Malicious", {})
                ben = cls.get("Benign", {})
                bg = cls.get("Background", {})

                # Malicious vs Benign
                binm = compute_binary_metrics(
                    mal.get("TP", 0),
                    ben.get("TP", 0),
                    mal.get("FP", 0),
                    mal.get("FN", 0),
                )
                # Overall Non-BG vs BG
                overm = compute_binary_metrics(
                    mal.get("TP", 0) + ben.get("TP", 0),
                    bg.get("TN", 0),
                    mal.get("FP", 0) + ben.get("FP", 0),
                    bg.get("FN", 0),
                )
                # True multiclass
                multi = compute_multiclass_metrics(cls, total)

                metrics["malicious"].append(binm)
                metrics["overall"].append(overm)
                metrics["multiclass"].append(multi)

                # count NaN/Inf
                for group in (binm, overm, multi):
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


def plot_metrics(
    metrics: Dict[str, List[Dict[str, float]]], exp: str, testing_dir: str
) -> None:
    exp_dir = os.path.join(testing_dir, exp)
    os.makedirs(exp_dir, exist_ok=True)

    for key in ("malicious", "overall"):
        entries = metrics[key]
        close0 = {"FPR": [], "FNR": []}
        close1 = {
            "TPR": [],
            "TNR": [],
            "precision": [],
            "recall": [],
            "f1": [],
            "accuracy": [],
        }

        for e in entries:
            close0["FPR"].append(e["FPR"])
            close0["FNR"].append(e["FNR"])
            for k in close1:
                close1[k].append(e[k])

        # Close to 0
        plt.figure(figsize=(10, 6))
        for m in ("FPR", "FNR"):
            plt.plot(close0[m], label=m, marker="o")
        plt.yscale("linear")
        plt.xlabel("Index")
        plt.ylabel("Value")
        plt.title(f"{key.capitalize()} Metrics Close to 0")
        plt.legend()
        plt.savefig(os.path.join(exp_dir, f"{key}_metrics_to_0_{exp}.png"))
        plt.close()

        # Close to 1
        plt.figure(figsize=(10, 6))
        for m in ("TPR", "TNR", "precision", "recall", "f1", "accuracy"):
            plt.plot(close1[m], label=m, marker="o")
        plt.yscale("log")
        plt.xlabel("Index")
        plt.ylabel("Value")
        plt.title(f"{key.capitalize()} Metrics Close to 1")
        plt.legend()
        plt.savefig(os.path.join(exp_dir, f"{key}_metrics_to_1_{exp}.png"))
        plt.close()


def print_and_save_summary(
    metrics: Dict[str, Any],
    counters: Dict[str, int],
    exp: str,
    testing_dir: str,
) -> None:
    exp_dir = os.path.join(testing_dir, exp)
    os.makedirs(exp_dir, exist_ok=True)
    last_bin = metrics["malicious"][-1] if metrics["malicious"] else {}
    last_ovr = metrics["overall"][-1] if metrics["overall"] else {}
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
            f"Final {name.upper() if name!='f1' else 'F1 Score'}: {v:.4f}"
        )

    lines.append("\n=== Overall (BG vs Others) ===")
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
        v = last_ovr.get(name if name != "f1" else "f1", 0)
        lines.append(
            f"Final {name.upper() if name!='f1' else 'F1 Score'}: {v:.4f}"
        )

    lines.append("\n=== Multi-class ===")
    lines.append(f"Accuracy: {last_mul.get('accuracy',0):.4f}")
    lines.append(f"Macro Precision: {last_mul.get('macro_precision',0):.4f}")
    lines.append(f"Macro Recall:    {last_mul.get('macro_recall',0):.4f}")
    lines.append(f"Macro F1:        {last_mul.get('macro_f1',0):.4f}")
    lines.append(f"Micro Precision: {last_mul.get('micro_precision',0):.4f}")
    lines.append(f"Micro Recall:    {last_mul.get('micro_recall',0):.4f}")
    lines.append(f"Micro F1:        {last_mul.get('micro_f1',0):.4f}")

    lines.append(f"\nSummary for Experiment {exp}:")
    lines.append(f"Total lines read:        {counters['total']}")
    lines.append(f"Lines with parse errors: {counters['errors']}")
    lines.append(f"Unusual (NaN/Inf):       {counters['unusual']}")

    summary = "\n".join(lines)
    print(summary)
    with open(os.path.join(exp_dir, "final_metrics.txt"), "w") as f:
        f.write(summary)


def main():
    parser = argparse.ArgumentParser(
        description="Plot testing performance metrics."
    )
    parser.add_argument("-f", "--file", required=True, help="Path to log file")
    parser.add_argument(
        "-e", "--exp", required=True, help="Experiment identifier"
    )
    args = parser.parse_args()

    if not args.file.endswith(".log"):
        args.file = os.path.join(args.file, "testing.log")
    if not os.path.isfile(args.file):
        raise FileNotFoundError(f"Log file not found: {args.file}")

    base_dir = "performance_metrics"
    testing_dir = os.path.join(base_dir, "testing")
    os.makedirs(testing_dir, exist_ok=True)

    data = process_file(args.file)
    plot_metrics(data["metrics"], args.exp, testing_dir)
    print_and_save_summary(
        data["metrics"], data["counters"], args.exp, testing_dir
    )


if __name__ == "__main__":
    main()
