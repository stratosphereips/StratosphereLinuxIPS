"""Regression tests for the legacy RNN's padding, state and current window."""

import json
from pathlib import Path
from unittest.mock import Mock, patch

import numpy as np
import pytest

from modules.rnn_cc_detection.preprocessing import connection_count, encode_letters, is_established
from modules.rnn_cc_detection.training_code.train_optimization_optuna import load_splits
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize("state,accepted", [("SF", True), ("Established", True), ("Not Established", False), ("NotEstablished", False), ("REJ", False), ("S0", False)])
def test_exact_established_gate(state: str, accepted: bool) -> None:
    """Exact established gate.

    Parameters:
        state: Connection state under test.
        accepted: Whether that state should be accepted.
    """
    module = ModuleFactory().create_rnn_detection_object()
    assert is_established(state) == accepted
    module.tcpmodel = Mock()
    module.tcpmodel.predict.return_value = np.array([[0.1]])
    module.print = Mock()
    msg = {"new_symbol": "a." * 20, "profileid": "profile_192.168.1.2", "twid": "timewindow1", "tupleid": "8.8.8.8-443-tcp", "flow": {"state": state}}
    module.handle_new_letters({"data": json.dumps(msg)})
    assert module.tcpmodel.predict.called == accepted


def test_padding_current_suffix_and_flow_count() -> None:
    """Padding current suffix and flow count.
    """
    module = ModuleFactory().create_rnn_detection_object()
    assert np.all(module.convert_input_for_module("") == 0)
    assert module.convert_input_for_module("0")[0, 0, 0] == 45
    assert not np.array_equal(encode_letters("a" * 500 + "b" * 500), encode_letters("a" * 1000))
    assert connection_count("a.0+8*H,") == 3
    assert encode_letters("a", schema=2)[0, 0, 0] == 1
    assert encode_letters("a", schema=2)[0, 1, 0] == 0


def test_prediction_cadence_cooldown_and_long_window() -> None:
    """Prediction cadence cooldown and long window.
    """
    module = ModuleFactory().create_rnn_detection_object()
    module.tcpmodel = Mock()
    module.tcpmodel.predict.return_value = np.array([[0.999]])
    module.set_evidence_cc_channel = Mock()
    module.print = Mock()
    msg = {"new_symbol": "a." * 300, "profileid": "profile_192.168.1.2", "twid": "timewindow1", "tupleid": "8.8.8.8-443-tcp", "uid": "x", "flow": {"state": "SF", "starttime": 1700000000, "daddr": "8.8.8.8"}}
    with patch("modules.rnn_cc_detection.rnn_cc_detection.time.monotonic", side_effect=[0, 1, 6, 4000]):
        module.handle_new_letters({"data": json.dumps(msg)})
        msg["new_symbol"] += "b." * 4
        module.handle_new_letters({"data": json.dumps(msg)})
        module.handle_new_letters({"data": json.dumps(msg)})
        msg["new_symbol"] += "b." * 4
        module.handle_new_letters({"data": json.dumps(msg)})
    assert module.tcpmodel.predict.call_count == 3
    assert module.set_evidence_cc_channel.call_count == 2


@pytest.mark.parametrize("problem", ["capture", "duplicate", "broad-label"])
def test_training_rejects_leakage_and_ambiguous_labels(tmp_path: Path, problem: str) -> None:
    """Training rejects leakage and ambiguous labels.

    Parameters:
        tmp_path: Isolated test directory.
        problem: Dataset labeling or split error to introduce.
    """
    module = ModuleFactory().create_rnn_detection_object()
    path = tmp_path / "labels.tsv"
    rows = [("a", "train", "benign", "a" * 20), ("b", "train", "c2", "b" * 20), ("c", "validation", "benign", "c" * 20), ("d", "validation", "c2", "d" * 20), ("e", "test", "benign", "e" * 20), ("f", "test", "c2", "f" * 20)]
    if problem == "capture":
        rows[-1] = ("b", "test", "c2", "f" * 20)
    elif problem == "duplicate":
        rows[-1] = ("f", "test", "c2", "b" * 20)
    else:
        rows[-1] = ("f", "test", "Botnet", "f" * 20)
    path.write_text("group\tsplit\tlabel\tstate\n" + "\n".join("\t".join(row) for row in rows))
    with pytest.raises(ValueError):
        load_splits(path)
    assert module is not None


def test_offline_predictions_follow_packet_time() -> None:
    """Reevaluate accelerated recorded input instead of waiting five wall seconds."""
    module = ModuleFactory().create_rnn_detection_object()
    module.offline = True
    module.tcpmodel = Mock()
    module.tcpmodel.predict.return_value = np.array([[0.1]])
    module.print = Mock()
    msg = {"new_symbol": "a." * 20, "profileid": "profile_192.168.1.2", "twid": "timewindow1", "tupleid": "8.8.8.8-443-tcp", "flow": {"state": "SF", "starttime": 1700000000}}
    with patch("modules.rnn_cc_detection.rnn_cc_detection.time.monotonic", return_value=0):
        module.handle_new_letters({"data": json.dumps(msg)})
        msg["new_symbol"] += "a." * 4
        msg["flow"]["starttime"] += 60
        module.handle_new_letters({"data": json.dumps(msg)})
    assert module.tcpmodel.predict.call_count == 2
