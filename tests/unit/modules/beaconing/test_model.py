"""Portable model schema validation and shared feature extraction."""

import json
from pathlib import Path

import pytest

from modules.beaconing.detector import features
from modules.beaconing.model import FEATURE_NAMES, PatternModel, vector
from tests.module_factory import ModuleFactory
from tests.unit.modules.beaconing.test_detector import event


def test_shipped_forest_and_feature_schema() -> None:
    """Shipped forest and feature schema.
    """
    module = ModuleFactory().create_beaconing_obj()
    model = PatternModel(module.settings.model_file)
    stats = features([event(i) for i in range(32)], module.settings)
    assert len(vector(stats)) == len(FEATURE_NAMES)
    score = model.score(stats)
    assert 0 <= score <= 1
    stats["duration"] = float("nan")
    assert model.score(stats) == 0


@pytest.mark.parametrize("corruption", ["schema", "cycle", "score", "feature", "threshold"])
def test_reject_invalid_model(tmp_path: Path, corruption: str) -> None:
    """Reject invalid model.

    Parameters:
        tmp_path: Isolated test directory.
        corruption: Model field to corrupt.
    """
    module = ModuleFactory().create_beaconing_obj()
    data = json.loads(Path(module.settings.model_file).read_text())
    if corruption == "schema":
        data["features"] = []
    elif corruption == "cycle":
        data["trees"][0][0][2] = 0
    elif corruption == "score":
        data["trees"][0][-1][4] = float("nan")
    elif corruption == "feature":
        data["trees"][0][0][0] = 999
    else:
        data["minimum_threshold"] = 0
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        PatternModel(str(path))
