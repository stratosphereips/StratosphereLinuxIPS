"""Honest testing streams: conn-only twins and local-stream span headers.

Every tested flow is counted in the all-flows streams (local_test.log /
merged_test.log). Conn flows are also counted in conn-only twins
(local_test_conn.log / merged_test_conn.log, same line format and spans),
because ARP records dominate the all-flows streams under a scanning attacker.
The local stream writes its span header on first use, so the first merged
span is not headerless (and silently dropped by span parsers).

The all-traffic-so-far evaluation (sofar_test.jsonl) stores every flow read
once (raw features, GT, conn flag) and, at each training close, scores the
models of that close on all of them: one JSON row per (model, scope).
"""

import json
from unittest.mock import MagicMock

import numpy as np
import pytest
import torch

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


# --------------------------------------------------------------------------
# all traffic so far (sofar_test.jsonl)
# --------------------------------------------------------------------------
SOFAR_KEYS = ["window", "model", "scope", "flows", "gt_mal", "gt_ben"]
SOFAR_KEYS += ["tp", "fp", "tn", "fn"]

SOFAR_FLOWS = [
    # uid, type_, gt, first raw feature (its sign is _Sign's verdict)
    ("c1", "conn", MAL, 1.0),  # TP
    ("c2", "conn", BEN, 1.0),  # FP
    ("c3", "conn", BEN, -1.0),  # TN
    ("a1", "arp", MAL, -1.0),  # FN
    ("a2", "arp", MAL, 1.0),  # TP
    ("a3", "arp", BEN, -1.0),  # TN
]


class _Sign(torch.nn.Module):
    """Malicious iff the first scaled feature is positive."""

    def forward(self, x):
        return torch.stack([torch.zeros(len(x)), x[:, 0]], dim=1)


class _AllMal(torch.nn.Module):
    """Malicious for every flow."""

    def forward(self, x):
        return torch.stack([torch.zeros(len(x)), torch.ones(len(x))], dim=1)


def _sofar_module(tmp_path, scale=1.0):
    m = _module(tmp_path)
    m.device = torch.device("cpu")
    m.is_preprocessor_fitted = True
    m._sofar_chunks = []
    m.label_source = "alerts"
    m.scaler = MagicMock(transform=lambda x: scale * x)
    m._extract_flow_features = lambda flow: [flow["x"]] + [0.0] * 17
    m._get_simulated_gt = lambda flow: flow["gt"]
    return m


def _sofar_flows(spec):
    return [{"uid": u, "type_": t, "gt": g, "x": x} for u, t, g, x in spec]


def _sofar_rows(tmp_path):
    lines = (tmp_path / "sofar_test.jsonl").read_text().splitlines()
    rows = [json.loads(line) for line in lines]
    assert all(list(row) == SOFAR_KEYS for row in rows)
    return rows


def _row(window, model, scope, flows, gt_mal, tp, fp, tn, fn):
    return dict(
        zip(
            SOFAR_KEYS,
            (window, model, scope, flows, gt_mal, flows - gt_mal)
            + (tp, fp, tn, fn),
        )
    )


@pytest.mark.parametrize(
    "scale, local_all, local_conn",
    [
        (1.0, (2, 1, 2, 1), (1, 1, 1, 0)),
        # the current scaler decides: flipping it flips every verdict
        (-1.0, (1, 2, 1, 2), (0, 1, 1, 1)),
    ],
)
def test_sofar_rows_count_every_flow_per_model_and_scope(
    tmp_path, scale, local_all, local_conn
):
    """Six flows read over two closes (3 conn, 3 ARP) scored by a local and
    a merged model: one row per (model, scope) with exact counts; the conn
    scope counts only the conn flows."""
    m = _sofar_module(tmp_path, scale)
    m._sofar_ingest(_sofar_flows(SOFAR_FLOWS[:2]))
    m._sofar_ingest(_sofar_flows(SOFAR_FLOWS[2:]))
    m._sofar_evaluate(7, [("local", _Sign()), ("merged", _AllMal())])
    assert _sofar_rows(tmp_path) == [
        _row(7, "local", "all", 6, 3, *local_all),
        _row(7, "local", "conn", 3, 1, *local_conn),
        _row(7, "merged", "all", 6, 3, 3, 3, 0, 0),
        _row(7, "merged", "conn", 3, 1, 1, 2, 0, 0),
    ]


def test_sofar_rows_per_close_include_flows_read_before_the_first_fit(
    tmp_path,
):
    """Nothing is scored before the first fit, yet the flows read then are
    in every later close's rows; a close adds rows only for its models."""
    m = _sofar_module(tmp_path)
    m._is_fitted = False
    m._sofar_ingest(_sofar_flows(SOFAR_FLOWS[:3]))
    m._sofar_evaluate(1, [("local", _Sign())])
    assert _sofar_rows(tmp_path) == []
    m._is_fitted = True
    m._sofar_ingest(_sofar_flows(SOFAR_FLOWS[3:]))
    m._sofar_evaluate(2, [("local", _Sign())])
    m._sofar_ingest([])
    m._sofar_evaluate(3, [("local", _Sign()), ("merged", _AllMal())])
    m._sofar_evaluate(4, [])
    assert [
        (r["window"], r["model"], r["scope"], r["flows"])
        for r in _sofar_rows(tmp_path)
    ] == [
        (2, "local", "all", 6),
        (2, "local", "conn", 3),
        (3, "local", "all", 6),
        (3, "local", "conn", 3),
        (3, "merged", "all", 6),
        (3, "merged", "conn", 3),
    ]


@pytest.mark.parametrize(
    "local, merged, names",
    [
        (True, True, ["local", "merged"]),
        (True, False, ["local"]),
        (False, False, []),
    ],
)
def test_sofar_models_are_the_models_of_this_close(
    tmp_path, local, merged, names
):
    """local = this close's local-only snapshot, merged = self.model only
    when this close merged."""
    m = _sofar_module(tmp_path)
    m.model = _AllMal()
    snapshot = _Sign() if local else None
    models = m._sofar_models(snapshot, merged)
    assert [name for name, _ in models] == names
    assert dict(models).get("local") is snapshot or not local
    assert dict(models).get("merged") is m.model or not merged


def test_sofar_store_is_float32_once_and_scored_in_slices(tmp_path):
    """Chunks are merged into one float32 array on evaluation; slicing the
    forward pass does not change the counts; the model's mode survives."""
    m = _sofar_module(tmp_path)
    m._SOFAR_BATCH = 4  # 6 flows -> two forward slices
    for flow in SOFAR_FLOWS:
        m._sofar_ingest(_sofar_flows([flow]))
    model = _Sign().train()
    m._sofar_evaluate(1, [("local", model)])
    assert model.training
    assert len(m._sofar_chunks) == 1
    x, gt, conn = m._sofar_chunks[0]
    assert x.dtype == np.float32 and x.shape == (6, 18)
    assert gt.tolist() == [True, False, False, True, True, False]
    assert conn.tolist() == [True, True, True, False, False, False]
    assert _sofar_rows(tmp_path)[0] == _row(
        1, "local", "all", 6, 3, 2, 1, 2, 1
    )


def test_sofar_errors_are_logged_never_raised(tmp_path):
    """A failing model writes no partial rows for the close; a flow that
    breaks ingest is logged; neither raises into the close path."""

    class Boom(torch.nn.Module):
        def forward(self, x):
            raise RuntimeError("boom")

    m = _sofar_module(tmp_path)
    m._sofar_ingest(_sofar_flows(SOFAR_FLOWS))
    m._sofar_evaluate(1, [("local", _Sign()), ("merged", Boom())])
    assert _sofar_rows(tmp_path) == []
    assert "boom" in str(m.print.call_args)
    m._sofar_ingest([{"uid": "no-features"}])
    assert "KeyError" in str(m.print.call_args)
    assert len(m._sofar_chunks) == 1
