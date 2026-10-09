"""Merge rules (incl. byzantine block-by-block) and class-balance policy.

Merge functions are pure and tested on bare tensors. Undersampling is tested
on a bare module instance (only the state the helper touches)."""

from unittest.mock import MagicMock

import numpy as np
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
        "byzantine",
    }


def test_average_is_mean_of_own_and_peers():
    own = {"w": _t(0.0, 0.0)}
    peers = {"a": {"w": _t(2.0, 2.0)}, "b": {"w": _t(4.0, 4.0)}}
    out = fnm.merge_average(own, peers, ["w"])
    assert torch.allclose(out["w"], _t(2.0, 2.0))  # mean(0,2,4)


def test_byzantine_picks_closest_layer_to_mean_per_key():
    """Block-by-block: each key independently keeps the single candidate layer
    closest (L2) to that key's mean, so different keys can come from different
    peers (and a far outlier is rejected)."""
    own = {"w1": _t(0.0, 0.0), "w2": _t(0.0, 0.0)}
    peers = {
        "a": {"w1": _t(10.0, 10.0), "w2": _t(10.0, 10.0)},
        "b": {"w1": _t(11.0, 11.0), "w2": _t(0.5, 0.5)},
    }
    out = fnm.merge_byzantine(own, peers, ["w1", "w2"])
    # w1 mean=[7,7] -> closest is a's [10,10] (own=9.9, a=4.24, b=5.66)
    assert torch.allclose(out["w1"], _t(10.0, 10.0))
    # w2 mean=[3.5,3.5] -> closest is b's [0.5,0.5] (own=4.95, a=9.19, b=4.24)
    assert torch.allclose(out["w2"], _t(0.5, 0.5))


def test_byzantine_rejects_a_far_outlier_layer():
    own = {"w": _t(1.0, 1.0)}
    peers = {"a": {"w": _t(1.2, 0.8)}, "b": {"w": _t(500.0, 500.0)}}
    out = fnm.merge_byzantine(own, peers, ["w"])
    # the huge outlier is never selected (own or a, both near [1,1])
    assert not torch.allclose(out["w"], _t(500.0, 500.0))


def test_byzantine_with_no_peers_returns_own():
    own = {"w": _t(3.0, 3.0)}
    out = fnm.merge_byzantine(own, {}, ["w"])
    assert torch.allclose(out["w"], _t(3.0, 3.0))


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
