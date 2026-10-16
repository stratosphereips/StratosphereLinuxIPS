"""Live scoring, the one classification path, and the error ledger.

Live: SLIPS publishes every stored conn flow on new_flow and every ARP record
on new_arp, as a wrapper {"flow": asdict(flow), ...} around the same dict it
stores in sqlite. The module predicts each arriving flow with the serving
MERGED model (merged only; nothing before the first merge), keeps the
prediction tagged with the model generation, and at the window's close checks
it against the end-of-window prediction of the same flow: within one
generation they must be equal - a mismatch is a bug and is recorded as an
error. The window boundary drains the channels before the close.

One path: every prediction (end-of-window cell, live flow, single flow) goes
through _scaled_features -> _scale; the scaler only transforms, it is fit in
training alone.

Errors: every caught exception is printed at the always-shown level, counted
and appended to module_errors.log (empty file = clean run). A main-loop
exception no longer stops the module at once (the module base shuts a module
down when main() returns True) - only an error repeating on every pass does.
"""

import json
from unittest.mock import MagicMock

import numpy as np
import pytest

from modules.federated_network_module import (
    federated_network_module as fnm,
)

MAL, BEN = fnm.MALICIOUS, fnm.BENIGN
Module = fnm.FederatedNetworkModule


def _module(tmp_path):
    """A module serving a merged model (generation 3) at window 5."""
    m = object.__new__(Module)
    m.printed = []
    m.print = lambda text, *a, **kw: m.printed.append(str(text))
    m.logger = fnm.ModuleLogger(str(tmp_path), True)
    m.training_count_window = 5
    m.label_finalize_delay_windows = 1
    m._is_fitted = True
    m._using_merged_model = True
    m._model_gen = 3
    m._live_pred = {}
    m._live_counts = m._blank_live_counts()
    m._error_count = 0
    m._main_errors = 0
    m.channels = {}
    m._extract_flow_features = lambda flow: [float(flow.get("x", 0.0))]
    m.scaler = MagicMock(transform=lambda x: x)
    m.predict_batch = lambda x: np.array([MAL if v[0] > 0 else BEN for v in x])
    return m


def _msg(flow):
    """A message as SLIPS publishes it on new_flow / new_arp."""
    return {"data": json.dumps({"flow": flow, "profileid": "p", "twid": "t"})}


def _lines(tmp_path, name):
    return (tmp_path / f"{name}.log").read_text().splitlines()


# --------------------------------------------------------------------------
# live channels
# --------------------------------------------------------------------------
def test_a_live_message_is_unwrapped_to_the_flow_slips_stores(tmp_path):
    m = _module(tmp_path)
    flow = {"uid": "c1", "x": 1.0, "type_": "conn"}
    assert m._unwrap_flow_msg(_msg(flow)) == flow
    assert m._unwrap_flow_msg({"data": "not json"}) is None
    assert m._unwrap_flow_msg({"data": json.dumps({"no_flow": 1})}) is None
    assert m._live_counters()["bad_msg"] == 2


def test_live_scoring_predicts_only_with_a_serving_merged_model(tmp_path):
    m = _module(tmp_path)
    m._using_merged_model = False
    m._on_live_flows([{"uid": "c1", "x": 1.0}])
    assert m._live_pred == {} and m._live_counters()["no_model"] == 1
    m._using_merged_model = True
    m._on_live_flows([{"uid": "c1", "x": 1.0}, {"uid": "c2", "x": -1.0}])
    assert m._live_pred == {"c1": (MAL, 3, 5), "c2": (BEN, 3, 5)}
    assert m._live_counters()["predicted"] == 2


def test_live_and_window_predictions_are_compared_within_one_generation(
    tmp_path,
):
    """Same generation: compared (equal = matched, different = mismatched,
    logged with the flow). Other generation: straddled a training, counted
    gen_race. Never seen live: counted no_live. Entries are consumed."""
    m = _module(tmp_path)
    m._live_pred = {
        "same": (MAL, 3, 5),
        "diff": (BEN, 3, 5),
        "race": (BEN, 2, 4),
    }
    kept = [(u, {"uid": u}) for u in ("same", "diff", "race", "none")]
    m._check_live_consistency(kept, [MAL] * 4)
    c = m._live_counters()
    assert (c["compared"], c["matched"], c["mismatched"]) == (2, 1, 1)
    assert (c["gen_race"], c["no_live"]) == (1, 1)
    assert m._live_pred == {}
    mism = [
        ln
        for ln in _lines(tmp_path, "live_consistency")
        if ln.startswith("MISMATCH")
    ]
    assert len(mism) == 1
    assert "uid=diff" in mism[0] and f"live={BEN} batch={MAL}" in mism[0]


def test_a_live_mismatch_is_an_error_never_silent(tmp_path):
    m = _module(tmp_path)
    m._live_pred = {"diff": (BEN, 3, 5)}
    m._check_live_consistency([("diff", {"uid": "diff"})], [MAL])
    m._write_live_summary()
    summary = [
        ln
        for ln in _lines(tmp_path, "live_consistency")
        if ln.startswith("window_")
    ]
    assert "MISMATCH 1" in summary[-1]
    errors = _lines(tmp_path, "module_errors")
    assert errors and "live_consistency" in errors[0]
    assert any("[FL ERROR]" in t for t in m.printed)
    assert m._live_counters()["mismatched"] == 0  # reset for the next close


def test_stale_live_predictions_are_pruned_after_k_plus_two_windows(tmp_path):
    m = _module(tmp_path)  # window 5, K=1: keep windows >= 5 - 3 = 2
    m._live_pred = {
        "old": (MAL, 3, 1),
        "kept": (MAL, 3, 2),
        "new": (MAL, 3, 5),
    }
    m._write_live_summary()
    assert set(m._live_pred) == {"kept", "new"}
    assert "pruned 1" in _lines(tmp_path, "live_consistency")[-1]


def test_the_window_boundary_drains_every_queued_flow(tmp_path):
    """A normal pass reads at most `limit` messages per channel; the window
    boundary (limit=None) drains both channels completely, so every flow of
    the window is predicted by that window's model before the close."""
    m = _module(tmp_path)
    queues = {
        "new_flow": [_msg({"uid": f"c{i}", "x": 1.0}) for i in range(5)],
        "new_arp": [_msg({"uid": "r0", "x": -1.0})],
    }
    m.channels = {"new_flow": object(), "new_arp": object()}
    m.get_msg = lambda ch: queues[ch].pop(0) if queues[ch] else None
    assert m._read_live(2) == 3  # 2 conn + 1 ARP
    assert m._read_live(None) == 3  # the rest
    assert set(m._live_pred) == {"c0", "c1", "c2", "c3", "c4", "r0"}


def test_reading_the_live_channels_never_raises(tmp_path):
    m = _module(tmp_path)
    m.channels = {"new_flow": object()}

    def broken(channel):
        raise RuntimeError("redis down")

    m.get_msg = broken
    assert m._read_live(None) == 0
    assert "_read_live" in _lines(tmp_path, "module_errors")[0]


@pytest.mark.parametrize("mode", ["train", "test"])
def test_both_modes_subscribe_to_the_two_live_channels(tmp_path, mode):
    m = _module(tmp_path)
    m.mode = mode
    m.db = MagicMock()
    m.subscribe_to_channels()
    assert set(m.channels) == {"new_flow", "new_arp"}


def test_test_mode_classifies_the_inner_flow_of_a_message(tmp_path):
    """The message is a wrapper; test mode used to hand the whole wrapper to
    the classifier (features of the wrong dict)."""
    m = _module(tmp_path)
    m.channels = {"new_flow": object(), "new_arp": object()}
    queues = {"new_flow": [_msg({"uid": "c1", "x": 1.0})], "new_arp": []}
    m.get_msg = lambda ch: queues[ch].pop(0) if queues[ch] else None
    seen = []
    m.run_test_on_flow = seen.append
    m._p2p_connected = True
    assert m._main_testing() is False
    assert seen == [{"uid": "c1", "x": 1.0}]


# --------------------------------------------------------------------------
# one classification path; the scaler only transforms
# --------------------------------------------------------------------------
def test_every_prediction_scales_through_one_path_and_never_fits(tmp_path):
    m = _module(tmp_path)
    calls = []
    real_scale = Module._scale.__get__(m)

    def spy(x):
        calls.append(len(x))
        return real_scale(x)

    m._scale = spy
    m.scaler = MagicMock(
        transform=lambda x: x,
        partial_fit=MagicMock(side_effect=AssertionError("fit in predict")),
    )
    assert m._classify_flow({"uid": "c1", "x": 1.0}) == MAL  # single flow
    m._on_live_flows([{"uid": "c2", "x": -1.0}])  # live
    m.model = object()  # the local model (shadow while merged)
    m._predict_batch_with = lambda model, x: np.array([BEN] * len(x))
    m._get_simulated_gt = lambda flow: MAL
    blank = Module._blank_test_statistics
    cell = {
        "window": 5,
        "flows": {"c3": {"uid": "c3", "x": 1.0, "type_": "conn"}},
        "tested": set(),
        "preds": {},
        "test": {
            k: blank()
            for k in ("main", "conn_main", "shadow_local", "conn_shadow")
        },
        "merged_served": False,
        "scorable": True,
        "flushed": False,
    }
    m._test_cell(cell)  # end of window
    assert calls == [1, 1, 1]
    m.scaler.partial_fit.assert_not_called()
    assert cell["preds"] == {"c3": MAL}


# --------------------------------------------------------------------------
# errors: recorded, never silent, never fatal at once
# --------------------------------------------------------------------------
def test_a_caught_error_is_printed_counted_and_logged(tmp_path):
    m = _module(tmp_path)
    try:
        raise ValueError("boom")
    except ValueError:
        m._record_error("_train_batch")
    assert m._error_count == 1
    assert any("[FL ERROR] _train_batch" in t for t in m.printed)
    log = "\n".join(_lines(tmp_path, "module_errors"))
    assert "#1 _train_batch" in log and "ValueError: boom" in log


def test_main_loop_errors_keep_the_module_running_until_they_persist(
    tmp_path,
):
    """main() returning True makes the module base shut the module down:
    a main-loop error is recorded and the loop continues; only an error on
    every one of _MAX_CONSECUTIVE_MAIN_ERRORS passes stops it (recorded)."""
    m = _module(tmp_path)
    results = []
    for _ in range(Module._MAX_CONSECUTIVE_MAIN_ERRORS):
        try:
            raise RuntimeError("persistent")
        except RuntimeError:
            results.append(m._main_loop_error("_main_training"))
    assert results[:-1] == [False] * (len(results) - 1)
    assert results[-1] is True
    heads = [
        ln
        for ln in _lines(tmp_path, "module_errors")
        if ln.startswith("--- #")
    ]
    assert len(heads) == len(results) + 1  # every error + the stop record
    assert "stopping the module" in "\n".join(
        _lines(tmp_path, "module_errors")
    )
