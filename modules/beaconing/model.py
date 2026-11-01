"""Small portable numeric forest; runtime needs no ML framework."""

import json
import math
import struct
from pathlib import Path
from typing import Any

FEATURE_NAMES = (
    "jitter",
    "missed",
    "sent_variation",
    "received_variation",
    "duration_variation",
    "packets_sent_variation",
    "packets_received_variation",
    "log_period",
    "log_sent",
    "log_received",
    "log_duration",
    "answered",
    "overlap",
)


def vector(stats: dict[str, Any]) -> list[float]:
    """Select ordered, finite numeric features without IP, port or capture labels.

    Parameters:
        stats: Rhythm and bidirectional size/duration statistics.

    Returns:
        Fixed-schema feature vector used in training and runtime.
    """
    return [
        (
            math.log1p(float(stats[name[4:]]))
            if name.startswith("log_")
            else float(stats[name])
        )
        for name in FEATURE_NAMES
    ]


class PatternModel:
    """Score resemblance to labeled C2, rather than claim a malware probability."""

    def __init__(self, path: str) -> None:
        """Load and validate a bounded JSON decision forest.

        Parameters:
            path: Local reviewed model file, with no executable pickle content.
        """
        if Path(path).stat().st_size > 1048576:
            raise ValueError("Beaconing model is too large")
        data = json.loads(Path(path).read_text())
        if data.get("schema") != 1 or data.get("features") != list(
            FEATURE_NAMES
        ):
            raise ValueError("Unsupported beaconing model schema")
        self.version = str(data["version"])
        self.protocols = data["protocols"]
        if not self.protocols or not set(self.protocols) <= {"tcp", "udp"}:
            raise ValueError("Invalid trained protocols")
        if data.get("algorithm") != "random_forest":
            raise ValueError("Unsupported beaconing model algorithm")
        self.trees = data["trees"]
        if not 1 <= len(self.trees) <= 64:
            raise ValueError("Invalid beaconing tree count")
        for tree in self.trees:
            if not 1 <= len(tree) <= 127:
                raise ValueError("Invalid beaconing tree size")
            for index, node in enumerate(tree):
                if len(node) != 5:
                    raise ValueError("Invalid beaconing tree node")
                feature, threshold, left, right, score = node
                if (
                    not isinstance(score, (float, int))
                    or not math.isfinite(score)
                    or not 0 <= score <= 1
                ):
                    raise ValueError("Invalid leaf score")
                if feature == -2:
                    continue
                if (
                    not isinstance(feature, int)
                    or not 0 <= feature < len(FEATURE_NAMES)
                    or not math.isfinite(threshold)
                ):
                    raise ValueError("Invalid split feature")
                if not all(
                    isinstance(child, int) and index < child < len(tree)
                    for child in (left, right)
                ):
                    raise ValueError("Invalid tree child")
        self.minimum_threshold = float(data["minimum_threshold"])
        if not 0.5 <= self.minimum_threshold <= 1:
            raise ValueError("Invalid calibrated threshold")

    def score(self, stats: dict[str, Any]) -> float:
        """Compute a similarity score for an answered recurring channel.

        Parameters:
            stats: Same feature schema used by the training tool.

        Returns:
            Forest decision score in [0,1], not a calibrated probability.
        """
        values = vector(stats)
        if not all(math.isfinite(v) for v in values):
            return 0.0
        # sklearn's trees compare float32 features with float64 thresholds.
        values = [struct.unpack("f", struct.pack("f", v))[0] for v in values]
        scores = []
        for tree in self.trees:
            index = 0
            while tree[index][0] != -2:
                feature, threshold, left, right, _ = tree[index]
                index = left if values[feature] <= threshold else right
            scores.append(tree[index][4])
        return sum(scores) / len(scores)
