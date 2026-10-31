"""Train a portable C2-pattern classifier on explicit capture-grouped labels."""

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import numpy as np
from sklearn.ensemble import RandomForestClassifier

from modules.beaconing.model import FEATURE_NAMES, PatternModel, vector


def labeled_windows(
    capture: dict[str, Any],
) -> list[tuple[dict[str, Any], int]]:
    """Select benign windows and explicitly curated C2 endpoints only.

    Parameters:
        capture: Replay report with capture-level split and endpoint annotations.

    Returns:
        Feature windows and binary labels; unreviewed malware traffic is excluded.
    """
    selected = []
    for window in capture["windows"]:
        channel = json.loads(window["channel"])
        endpoint = f"{channel[2]}:{channel[3]}/{channel[4]}"
        if capture["label"] == "benign":
            selected.append((window, 0))
        elif endpoint in capture.get("c2_endpoints", []):
            selected.append((window, 1))
    return selected


def train(report: dict[str, Any], output: Path) -> dict[str, Any]:
    """Fit on training captures and set a conservative threshold on validation only.

    Parameters:
        report: Runtime replay features; captures assigned to disjoint splits.
        output: Reviewed portable model JSON destination.

    Returns:
        Validation measurements, without opening or using test-window features.
    """
    groups: dict[str, str] = {}
    capture_groups: dict[str, str] = {}
    samples = []
    validation = []
    for capture in report["captures"]:
        fingerprint = capture["sha256"]
        split = capture["split"]
        if fingerprint in groups and groups[fingerprint] != split:
            raise ValueError("A capture appears in more than one split")
        groups[fingerprint] = split
        group = capture.get("group", capture["name"])
        if group in capture_groups and capture_groups[group] != split:
            raise ValueError(
                "Related capture group appears in more than one split"
            )
        capture_groups[group] = split
        if split not in {"train", "validation"}:
            continue
        labeled = labeled_windows(capture)
        for window, label in labeled:
            if window["features"]["answered"] < 0.8:
                continue
            record = (window, label, capture["name"])
            (samples if split == "train" else validation).append(record)
    if (
        not samples
        or not validation
        or {s[1] for s in samples} != {0, 1}
        or {s[1] for s in validation} != {0, 1}
    ):
        raise ValueError(
            "Both classes are required in training and validation captures"
        )
    # One long channel must not outweigh many independent channels.
    counts = Counter(
        (group, window["channel"]) for window, _, group in samples
    )
    weights = np.asarray(
        [1 / counts[group, window["channel"]] for window, _, group in samples]
    )
    labels = np.asarray([label for _, label, _ in samples])
    for label in (0, 1):
        mask = labels == label
        weights[mask] /= weights[mask].sum()
    weights *= len(weights) / 2
    x = np.asarray([vector(window["features"]) for window, _, _ in samples])
    classifier = RandomForestClassifier(
        n_estimators=32,
        max_depth=3,
        min_samples_leaf=3,
        max_features=1.0,
        random_state=17,
        n_jobs=1,
    ).fit(x, labels, sample_weight=weights)
    trees = []
    for estimator in classifier.estimators_:
        tree = estimator.tree_
        trees.append(
            [
                [
                    int(tree.feature[i]),
                    float(tree.threshold[i]),
                    int(tree.children_left[i]),
                    int(tree.children_right[i]),
                    float(tree.value[i][0][1] / tree.value[i][0].sum()),
                ]
                for i in range(tree.node_count)
            ]
        )
    data = {
        "schema": 1,
        "algorithm": "random_forest",
        "version": "numeric-c2-2026-10-25",
        "features": list(FEATURE_NAMES),
        "trees": trees,
        "protocols": sorted(
            {
                json.loads(w["channel"])[4]
                for w, label, _ in samples
                if label == 1
            }
        ),
        "minimum_threshold": 0.5,
        "training": [
            {
                "name": c["name"],
                "sha256": c["sha256"],
                "split": c["split"],
                "label": c["label"],
                "c2_endpoints": c.get("c2_endpoints", []),
            }
            for c in report["captures"]
            if c["split"] in {"train", "validation"}
        ],
        "note": "Experimental pattern score, not malware probability. Labels are curated capture endpoints, not all flows in malicious captures. No IP/port/name features. Selected depth 3 with 32 trees and minimum 3 windows per leaf on validation captures; no test-set model selection.",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with TemporaryDirectory(
        dir=output.parent, prefix=".beaconing-"
    ) as temporary:
        candidate = Path(temporary) / "model.json"
        candidate.write_text(json.dumps(data, allow_nan=False))
        model = PatternModel(str(candidate))
    negatives = [
        model.score(w["features"])
        for w, label, _ in validation
        if label == 0 and w["features"]["answered"] >= 0.8
    ]
    threshold = max(0.5, max(negatives, default=0) + 0.02)
    if threshold >= 1:
        raise ValueError(
            "No usable conservative threshold; more labeled data is required"
        )
    data["minimum_threshold"] = threshold
    positives = [
        model.score(w["features"])
        for w, label, _ in validation
        if label == 1 and w["features"]["answered"] >= 0.8
    ]
    data["validation"] = {
        "benign_windows": len(negatives),
        "c2_windows": len(positives),
        "c2_windows_over_threshold": sum(
            score >= threshold for score in positives
        ),
        "benign_windows_over_threshold": sum(
            score >= threshold for score in negatives
        ),
        "threshold": threshold,
    }
    data["id"] = hashlib.sha256(
        json.dumps(data, sort_keys=True).encode()
    ).hexdigest()
    with TemporaryDirectory(
        dir=output.parent, prefix=".beaconing-"
    ) as temporary:
        candidate = Path(temporary) / "model.json"
        candidate.write_text(
            json.dumps(data, indent=2, allow_nan=False) + "\n"
        )
        candidate.replace(output)
    return data["validation"]


def main() -> None:
    """Train only from an explicit grouped replay report."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    print(
        json.dumps(
            train(json.loads(args.report.read_text()), args.output), indent=2
        )
    )


if __name__ == "__main__":
    main()
