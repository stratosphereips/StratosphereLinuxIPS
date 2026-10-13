"""Merge rules (incl. mean-with-closest and proximity) and class-balance policy.

Merge functions are pure and tested on bare tensors. Undersampling is tested
on a bare module instance (only the state the helper touches)."""

from unittest.mock import MagicMock

import numpy as np
import pytest
import torch

from modules.federated_network_module import (
    federated_network_module as fnm,
)


def _t(*vals):
    return torch.tensor(list(vals), dtype=torch.float32)


# --------------------------------------------------------------------------
# merge rules
# --------------------------------------------------------------------------
def test_registry_has_all_rules():
    assert set(fnm.MERGE_REGISTRY) == {
        "average",
        "trust_weighted",
        "blending",
        "mean_with_closest",
        "proximity",
    }


def test_average_is_mean_of_own_and_peers():
    own = {"w": _t(0.0, 0.0)}
    peers = {"a": {"w": _t(2.0, 2.0)}, "b": {"w": _t(4.0, 4.0)}}
    out = fnm.merge_average(own, peers, ["w"])
    assert torch.allclose(out["w"], _t(2.0, 2.0))  # mean(0,2,4)


# --- mean_with_closest (self-referenced; renamed from "byzantine") -----------
def test_mean_with_closest_averages_own_with_closest_peer_per_key():
    """Block by block, referenced to OWN: average own with the single peer whose
    layer is closest (L2) to own; different keys can pick different peers."""
    own = {"w1": _t(0.0, 0.0), "w2": _t(0.0, 0.0)}
    peers = {
        "a": {"w1": _t(1.0, 1.0), "w2": _t(10.0, 10.0)},
        "b": {"w1": _t(9.0, 9.0), "w2": _t(2.0, 2.0)},
    }
    out = fnm.merge_mean_with_closest(own, peers, ["w1", "w2"])
    # w1: closest to own is a[1,1] -> mean(own,a)=[0.5,0.5]
    assert torch.allclose(out["w1"], _t(0.5, 0.5))
    # w2: closest to own is b[2,2] -> mean(own,b)=[1,1]
    assert torch.allclose(out["w2"], _t(1.0, 1.0))


def test_mean_with_closest_one_peer_is_plain_average():
    own = {"w": _t(0.0, 0.0)}
    peers = {"a": {"w": _t(4.0, 4.0)}}
    out = fnm.merge_mean_with_closest(own, peers, ["w"])
    assert torch.allclose(out["w"], _t(2.0, 2.0))  # 50/50 of own + only peer


def test_mean_with_closest_with_no_peers_returns_own():
    own = {"w": _t(3.0, 3.0)}
    out = fnm.merge_mean_with_closest(own, {}, ["w"])
    assert torch.allclose(out["w"], _t(3.0, 3.0))


# --- proximity (Gaussian kernel on distance-to-own, median-heuristic sigma) --
def test_proximity_two_candidate_weighted_blend():
    """2 candidates: pairwise dist=2 -> sigma(median)=2; w_own=exp(0)=1,
    w_a=exp(-4/8)=0.6065; blend=(1*0 + 0.6065*2)/1.6065 = 0.7551."""
    own = {"w": _t(0.0)}
    peers = {"a": {"w": _t(2.0)}}
    out = fnm.merge_proximity(own, peers, ["w"])
    assert torch.allclose(out["w"], _t(0.7551), atol=1e-3)


def test_proximity_nearer_peer_weighs_more():
    """sigma=median{1,3,2}=2; w_own=1, w_a=exp(-1/8)=.8825, w_b=exp(-9/8)=.3247;
    blend=(.8825*1 + .3247*3)/(1+.8825+.3247)=0.841 -> nearer peer dominates.
    """
    own = {"w": _t(0.0)}
    peers = {"a": {"w": _t(1.0)}, "b": {"w": _t(3.0)}}
    out = fnm.merge_proximity(own, peers, ["w"])
    assert torch.allclose(out["w"], _t(0.8412), atol=1e-3)


def test_proximity_identical_candidates_is_plain_average():
    own = {"w": _t(2.0, 2.0)}
    peers = {"a": {"w": _t(2.0, 2.0)}}
    out = fnm.merge_proximity(own, peers, ["w"])
    assert torch.allclose(out["w"], _t(2.0, 2.0))  # sigma~0 -> average


def test_proximity_with_no_peers_returns_own():
    own = {"w": _t(5.0, 5.0)}
    out = fnm.merge_proximity(own, {}, ["w"])
    assert torch.allclose(out["w"], _t(5.0, 5.0))


def test_trust_weighted_falls_back_to_average_without_trust():
    own = {"w": _t(0.0)}
    peers = {"a": {"w": _t(4.0)}}
    out = fnm.merge_trust_weighted(own, peers, ["w"], trust={})
    assert torch.allclose(out["w"], _t(2.0))


# --------------------------------------------------------------------------
# class balance: undersampling
# --------------------------------------------------------------------------
def _bare_module(seed=7, window=3):
    m = object.__new__(fnm.FederatedNetworkModule)
    m.print = MagicMock()
    m.seed = seed
    m.training_count_window = window
    return m


def test_undersample_balances_majority_to_5050():
    m = _bare_module()
    X = np.arange(20, dtype=float).reshape(10, 2)
    y = np.array([fnm.MALICIOUS] * 8 + [fnm.BENIGN] * 2)
    Xb, yb = m._undersample_majority(X, y)
    assert int((yb == fnm.MALICIOUS).sum()) == 2
    assert int((yb == fnm.BENIGN).sum()) == 2
    # kept rows are a subset of the originals, X/y stay aligned
    assert Xb.shape == (4, 2)
    for row in Xb:
        assert any(np.array_equal(row, orig) for orig in X)


def test_undersample_is_reproducible_per_window():
    X = np.arange(20, dtype=float).reshape(10, 2)
    y = np.array([fnm.MALICIOUS] * 7 + [fnm.BENIGN] * 3)
    a = _bare_module(seed=5, window=2)._undersample_majority(X, y)
    b = _bare_module(seed=5, window=2)._undersample_majority(X, y)
    assert np.array_equal(a[0], b[0]) and np.array_equal(a[1], b[1])


def test_undersample_noop_on_single_class_or_balanced():
    m = _bare_module()
    X = np.zeros((4, 2))
    y_single = np.array([fnm.MALICIOUS] * 4)
    Xb, yb = m._undersample_majority(X, y_single)
    assert len(yb) == 4  # one class absent -> unchanged
    y_bal = np.array([fnm.MALICIOUS, fnm.BENIGN, fnm.MALICIOUS, fnm.BENIGN])
    Xb2, yb2 = m._undersample_majority(X, y_bal)
    assert len(yb2) == 4  # already 50/50 -> unchanged


# --------------------------------------------------------------------------
# feature extraction: one definitive extractor (process_features delegates)
# --------------------------------------------------------------------------
def test_process_features_delegates_to_single_extractor():
    """process_features is a thin wrapper over _extract_flow_features: same 18
    features, same _get_feature_order order, same values."""
    import pandas as pd

    m = object.__new__(fnm.FederatedNetworkModule)
    m.print = lambda *a, **k: None
    flow = {
        "dur": 1.5,
        "sport": 1234,
        "dport": 80,
        "spkts": 5,
        "dpkts": 3,
        "sbytes": 100,
        "dbytes": 200,
        "proto": "tcp",
        "appproto": "http",
        "state": "SF",
        "saddr": "10.0.0.1",
        "daddr": "10.0.0.2",
        "dir_": "->",
        "history": "ShADad",
    }
    order = m._get_feature_order()
    assert len(order) == 18
    direct = m._extract_flow_features(flow)
    via_pf = m.process_features(pd.DataFrame([flow]))
    assert list(via_pf.columns) == order
    assert via_pf.iloc[0].tolist() == [float(v) for v in direct]
    # empty frame -> empty, correctly-columned
    assert list(m.process_features(pd.DataFrame()).columns) == order


# --------------------------------------------------------------------------
# fine-tuning on/off gate (finetune_head)
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "epochs,finetune_head,expected",
    [(5, True, 5), (5, False, 0), (0, True, 0), (12, False, 0)],
)
def test_finetune_epochs_gate(epochs, finetune_head, expected):
    """finetune_head False collapses head fine-tune epochs to 0; True keeps them."""
    assert fnm.finetune_epochs_gate(epochs, finetune_head) == expected
