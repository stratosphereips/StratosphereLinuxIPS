"""Honest testing streams: conn-only twins and local-stream span headers.

Every tested flow is counted in the all-flows streams (local_test.log /
merged_test.log). Conn flows are also counted in conn-only twins
(local_test_conn.log / merged_test_conn.log, same line format and spans),
because ARP records dominate the all-flows streams under a scanning attacker.
The local stream writes its span header on first use, so the first merged
span is not headerless (and silently dropped by span parsers).
"""

from unittest.mock import MagicMock

import pytest

from modules.federated_network_module import (
    federated_network_module as fnm,
)

MAL, BEN = fnm.MALICIOUS, fnm.BENIGN


def _module(tmp_path, merged=False, span="window_2", batch=1):
    """A module instance with only the state the testing path touches."""
    m = object.__new__(fnm.FederatedNetworkModule)
    m.print = MagicMock()
    m.logger = fnm.ModuleLogger(str(tmp_path), True)
    m.testing_log_batch_size = batch
    m.testing_flows_since_last_log = 0
    m._is_fitted = True
    m._using_merged_model = merged
    m._local_only_model = object() if merged else None
    m._local_test = m._blank_test_statistics()
    m._local_stream_used = False
    m._span_label = span
    m._local_span_marked = False
    m._conn_active = m._blank_test_statistics()
    m._conn_local = m._blank_test_statistics()
    m.scaler = MagicMock(transform=lambda x: x)
    m._extract_flow_features = lambda flow: [0.0]
    return m


def _cell(flows):
    """flows: (uid, type_, gt, active_pred, local_pred)."""
    return {
        "flows": {uid: {"uid": uid, "type_": t} for uid, t, *_ in flows},
        "tested": set(),
        "preds": {},
    }


def _run(m, flows):
    gt = {uid: g for uid, _, g, _, _ in flows}
    m._get_simulated_gt = lambda flow: gt[flow["uid"]]
    m.predict_batch = lambda x: [p for *_, p, _ in flows]
    m._predict_batch_with = lambda model, x: [lp for *_, lp in flows]
    m._test_cell(_cell(flows))


def _lines(tmp_path, name):
    return (tmp_path / f"{name}.log").read_text().splitlines()


FLOWS = [
    # uid, type_, gt, active (merged) pred, frozen-local pred
    ("c1", "conn", MAL, MAL, BEN),
    ("c2", "conn", BEN, MAL, BEN),
    ("a1", "arp", MAL, MAL, MAL),
    ("a2", "arp", MAL, MAL, MAL),
    ("a3", "arp", MAL, MAL, MAL),
]


def test_conn_twin_counts_only_conn_flows(tmp_path):
    m = _module(tmp_path, merged=False)
    _run(m, FLOWS)
    all_last = _lines(tmp_path, "local_test")[-1]
    conn_last = _lines(tmp_path, "local_test_conn")[-1]
    assert "flows=5 " in all_last and "TP/FP/TN/FN: 4/1/0/0" in all_last
    assert "flows=2 " in conn_last and "TP/FP/TN/FN: 1/1/0/0" in conn_last
    assert "GT(Mal/Ben): 1/1" in conn_last
    assert _lines(tmp_path, "merged_test_conn") == []


@pytest.mark.parametrize("stream", ["local_test", "local_test_conn"])
def test_local_stream_header_is_written_once_on_first_use(tmp_path, stream):
    m = _module(tmp_path, merged=True, span="window_2")
    _run(m, FLOWS)
    _run(m, [("c3", "conn", MAL, MAL, MAL)])
    lines = _lines(tmp_path, stream)
    assert lines[0] == "--- New local model (window_2) ---"
    assert sum(line.startswith("---") for line in lines) == 1


def test_merged_conn_twin_tracks_the_frozen_local_model(tmp_path):
    m = _module(tmp_path, merged=True)
    _run(m, FLOWS)
    merged_conn = _lines(tmp_path, "merged_test_conn")[-1]
    local_conn = _lines(tmp_path, "local_test_conn")[-1]
    assert "Pred(Mal/Ben): 2/0" in merged_conn  # active = merged model
    assert "Pred(Mal/Ben): 0/2" in local_conn  # frozen local model


def test_conn_residual_flushes_to_the_log_it_was_counted_for(tmp_path):
    """Training flips _using_merged_model before the span's residual is
    flushed; the residual must still land in the stream it belongs to."""
    m = _module(tmp_path, merged=True, batch=1000)
    _run(m, FLOWS)
    assert _lines(tmp_path, "merged_test_conn") == []  # below batch size
    m._using_merged_model = False
    m._flush_conn_stream("active")
    assert "flows=2 " in _lines(tmp_path, "merged_test_conn")[-1]
    assert _lines(tmp_path, "local_test_conn")[0].startswith("--- New local")
    assert len(_lines(tmp_path, "local_test_conn")) == 1  # header only
