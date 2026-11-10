"""Replay adapters must retain the numeric runtime semantics."""

import json
import sqlite3
from pathlib import Path

import pytest

from tools.beaconing.evaluate import read_flows, replay
from tools.beaconing.train import labeled_windows, train
from modules.beaconing.model import PatternModel
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize("format_", ["json", "tsv", "sqlite"])
def test_read_and_replay(tmp_path: Path, format_: str) -> None:
    """Read and replay.

    Parameters:
        tmp_path: Isolated test directory.
        format_: Input format under test.
    """
    module = ModuleFactory().create_beaconing_obj()
    rows = [{"ts": 1700000000 + i * 60, "uid": str(i), "id.orig_h": "192.168.1.2", "id.orig_p": 50000, "id.resp_h": "8.8.8.8", "id.resp_p": 443, "proto": "tcp", "duration": 0.2, "orig_bytes": 386, "resp_bytes": 115, "orig_pkts": 5, "resp_pkts": 5, "conn_state": "SF"} for i in range(32)]
    path = tmp_path / "conn.log"
    if format_ == "tsv":
        keys = list(rows[0])
        path.write_text("#fields\t" + "\t".join(keys) + "\n" + "\n".join("\t".join(str(r[k]) for k in keys) for r in rows))
    else:
        path.write_text("\n".join(json.dumps(r) for r in rows))
        if format_ == "sqlite":
            flows = list(read_flows(path))
            path = tmp_path / "flows.sqlite"
            connection = sqlite3.connect(path)
            connection.execute("CREATE TABLE flows (flow TEXT)")
            connection.executemany("INSERT INTO flows VALUES (?)", [(json.dumps(f),) for f in flows])
            connection.commit()
            connection.close()
    report = replay(path, module.settings, PatternModel(module.settings.model_file))
    assert report["flows"] == 32
    assert report["recurring_channels"] == 1
    assert report["windows"][0]["features"]["period"] == pytest.approx(60)


def test_training_ignores_unreviewed_malware_and_duplicate_capture() -> None:
    """Training ignores unreviewed malware and duplicate capture.
    """
    module = ModuleFactory().create_beaconing_obj()
    window = {"channel": '["scope","192.168.1.2","8.8.8.8",443,"tcp"]', "features": {}}
    cap = {"windows": [window], "label": "malicious-capture"}
    assert labeled_windows(cap) == []
    cap["c2_endpoints"] = ["8.8.8.8:443/tcp"]
    assert labeled_windows(cap) == [(window, 1)]
    report = {"captures": [{"name": "a", "sha256": "same", "split": "train", "windows": [], "label": "benign"}, {"name": "b", "sha256": "same", "split": "test", "windows": [], "label": "benign"}]}
    with pytest.raises(ValueError, match="more than one split"):
        train(report, Path("unused-model.json"))
    assert module is not None


def test_exported_model_matches_training_forest(tmp_path: Path) -> None:
    """Check real training, portable inference and exclusion of held-out data.

    Parameters:
        tmp_path: Isolated model output directory.
    """
    module = ModuleFactory().create_beaconing_obj()
    from sklearn.ensemble import RandomForestClassifier
    from unittest.mock import patch
    from modules.beaconing.detector import features
    from modules.beaconing.model import vector
    from tests.unit.modules.beaconing.test_detector import event

    base = features([event(i) for i in range(32)], module.settings)
    captures = []
    for split in ("train", "validation"):
        for label in ("benign", "malicious-capture"):
            windows = []
            for i in range(24):
                stats = {**base, "sent": float(30 + i if label == "benign" else 350 + i), "received": float(5000 + i if label == "benign" else 115 + i)}
                windows.append({"channel": '["scope","192.168.1.2","8.8.8.8",443,"tcp"]', "features": stats})
            captures.append({"name": split + label, "sha256": split + label, "split": split, "label": label, "c2_endpoints": ["8.8.8.8:443/tcp"] if label != "benign" else [], "windows": windows})
    captures.append({"name": "untouched", "sha256": "heldout", "split": "test"})
    forest = RandomForestClassifier(n_estimators=32, max_depth=3, min_samples_leaf=3, max_features=1.0, random_state=17, n_jobs=1)
    output = tmp_path / "model.json"
    with patch("tools.beaconing.train.RandomForestClassifier", return_value=forest):
        metrics = train({"captures": captures}, output)
    model = PatternModel(str(output))
    assert metrics["c2_windows_over_threshold"] == 24
    assert metrics["benign_windows_over_threshold"] == 0
    for window in captures[2]["windows"] + captures[3]["windows"]:
        actual = model.score(window["features"])
        expected = forest.predict_proba([vector(window["features"])])[0, 1]
        assert actual == pytest.approx(expected, abs=1e-12)
