"""Pretrained start (opt-in `pretrained: true`) and model 0.

Every peer loads the same offline-built model + fitted scaler of its
model_class from <pretrained_dir>/<model_class>/ (model_state.bin,
scaler.bin, meta.json) instead of its per-peer empty init; any missing file
or mismatch raises. Frozen copies of the loaded model and scaler are kept
as model 0. Without the key (or with anything but true) nothing changes:
the per-peer empty start stays the default and no loading is attempted.
"""

import hashlib
import json
import os
import pickle
import shutil
from types import SimpleNamespace
from unittest.mock import MagicMock

import numpy as np
import pytest
import torch
import yaml
from sklearn.preprocessing import StandardScaler

from modules.federated_network_module import (
    federated_network_module as fnm,
)
from slips_files.common.abstracts import ml_module_base as ml_base

SEED = 1111  # as in conftest.py
MODULE_DIR = os.path.dirname(os.path.abspath(fnm.__file__))
SHIPPED_RP = os.path.join(MODULE_DIR, "artifacts", "random_projection.bin")
CLASSES = sorted(fnm.MODEL_REGISTRY)


def sha256_of(path) -> str:
    """Hex sha256 of a file's bytes."""
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _peer(tmp_path, name, pretrained_dir, model_class, rp="shipped"):
    """A bare module with the state init() sets before the start model is
    picked; its projection file is a copy of the shipped one (or absent)."""
    m = object.__new__(fnm.FederatedNetworkModule)
    m.print = MagicMock()
    peer_dir = tmp_path / name
    peer_dir.mkdir(parents=True, exist_ok=True)
    m.output_dir = str(peer_dir / "logs")
    m.logger = fnm.ModuleLogger(m.output_dir, True)
    m.my_peer_id = name
    m.seed = SEED
    m.init_seed = fnm.peer_init_seed(SEED, name)
    m.model_class_name = model_class
    m.balancing = "weighting"
    m._read_module_config_bool = lambda key, default: default  # yaml
    m.device = torch.device("cpu")
    m.input_dim = None
    m.model = None
    m.scaler = StandardScaler()
    m.is_preprocessor_fitted = False
    m._is_fitted = False
    m.rp_path = str(peer_dir / "random_projection.bin")
    if rp == "shipped":
        shutil.copy(SHIPPED_RP, m.rp_path)
    m.pretrained = True
    m.pretrained_dir = pretrained_dir
    return m


def _states_equal(a: dict, b: dict) -> bool:
    return a.keys() == b.keys() and all(torch.equal(a[k], b[k]) for k in a)


# --------------------------------------------------------------------------
# loading
# --------------------------------------------------------------------------
@pytest.mark.parametrize("model_class", CLASSES)
@pytest.mark.parametrize(
    "meta_sha, peer_rp",
    [
        # the sha of the projection file as the pretrainer's build re-saved it
        ("rewritten", "shipped"),
        ("rewritten", "absent"),  # peer regenerates it from the seed
        # the sha of the distributed file, as the peer finds it at startup
        ("shipped", "shipped"),
    ],
)
def test_pretrained_start_gives_every_peer_the_same_model_and_scaler(
    tmp_path, pretrained, model_class, meta_sha, peer_rp
):
    meta = (
        {"random_projection_sha256": sha256_of(SHIPPED_RP)}
        if meta_sha == "shipped"
        else None
    )
    art = pretrained(model_class, meta=meta)
    peers = [
        _peer(tmp_path, name, art.dir, model_class, rp=peer_rp)
        for name in ("slips-1", "slips-2")
    ]
    for p in peers:
        p._load_pretrained()
        assert _states_equal(p.model.state_dict(), art.state)
        assert p.is_preprocessor_fitted and p._is_fitted
        for attr in ("mean_", "var_", "scale_", "n_samples_seen_"):
            np.testing.assert_array_equal(
                getattr(p.scaler, attr), getattr(art.scaler, attr)
            )
        # model 0: frozen copies of the loaded model and scaler
        assert p._model0 is not p.model
        assert _states_equal(p._model0.state_dict(), art.state)
        assert not p._model0.training
        assert not any(t.requires_grad for t in p._model0.parameters())
        assert any(t.requires_grad for t in p.model.parameters())
        assert p._model0_scaler is not p.scaler
        np.testing.assert_array_equal(p._model0_scaler.mean_, art.scaler.mean_)
        assert os.path.isfile(os.path.join(p.output_dir, "model0_test.log"))
    assert _states_equal(
        peers[0].model.state_dict(), peers[1].model.state_dict()
    )
    # what they replaced: per-peer empty inits that differ from each other
    empty = [p.create_empty_model().state_dict() for p in peers]
    assert not _states_equal(empty[0], empty[1])


def _write_state_of(art, model_class):
    """Overwrite model_state.bin with another class's state_dict."""
    stub = SimpleNamespace(rp_path=None, seed=SEED, input_dim=None)
    other = fnm.MODEL_REGISTRY[model_class](stub)
    torch.save(other.state_dict(), art.path / "model_state.bin")


def _foreign_projection(art, m):
    """The peer's projection file holds another projection, and meta.json
    names exactly that file: the sha matches, the tensors do not."""
    torch.save(fnm.shared_random_projection(18, 256, SEED + 1), m.rp_path)
    meta = dict(art.meta, random_projection_sha256=sha256_of(m.rp_path))
    (art.path / "meta.json").write_text(json.dumps(meta))


def _pickle_to(path, obj):
    with open(path, "wb") as f:
        pickle.dump(obj, f)


FAILURES = {
    "missing model_state.bin": (
        lambda art, m: os.remove(art.path / "model_state.bin"),
        r"missing \['model_state.bin'\]",
    ),
    "missing scaler.bin": (
        lambda art, m: os.remove(art.path / "scaler.bin"),
        r"missing \['scaler.bin'\]",
    ),
    "missing meta.json": (
        lambda art, m: os.remove(art.path / "meta.json"),
        r"missing \['meta.json'\]",
    ),
    "missing class dir": (
        lambda art, m: setattr(m, "model_class_name", "simple_mlp"),
        r"missing \['model_state.bin', 'scaler.bin', 'meta.json'\]",
    ),
    "corrupt meta.json": (
        lambda art, m: (art.path / "meta.json").write_text("not json"),
        "unreadable meta.json",
    ),
    "meta.json not an object": (
        lambda art, m: (art.path / "meta.json").write_text("[]"),
        "meta.json is not an object",
    ),
    "meta model_class mismatch": (
        lambda art, m: (art.path / "meta.json").write_text(
            '{"model_class": "simple_mlp", "random_projection_sha256": "'
            + art.meta["random_projection_sha256"]
            + '"}'
        ),
        "model_class 'simple_mlp' does not match 'random_projection_mlp'",
    ),
    "wrong projection sha": (
        lambda art, m: (art.path / "meta.json").write_text(
            '{"model_class": "random_projection_mlp", '
            '"random_projection_sha256": "' + "0" * 64 + '"}'
        ),
        "random_projection_sha256 '0000",
    ),
    "no projection sha": (
        lambda art, m: (art.path / "meta.json").write_text(
            '{"model_class": "random_projection_mlp"}'
        ),
        "random_projection_sha256 None does not match",
    ),
    "foreign projection behind a matching sha": (
        _foreign_projection,
        "frozen random projection in model_state.bin differs",
    ),
    "state of another model class": (
        lambda art, m: _write_state_of(art, "simple_mlp"),
        "model_state.bin does not load",
    ),
    "unfitted scaler": (
        lambda art, m: _pickle_to(art.path / "scaler.bin", StandardScaler()),
        "scaler.bin is not a StandardScaler fitted on 18 features",
    ),
    "scaler over other features": (
        lambda art, m: _pickle_to(
            art.path / "scaler.bin", StandardScaler().fit(np.eye(4))
        ),
        "scaler.bin is not a StandardScaler fitted on 18 features",
    ),
    "unsafe scaler pickle": (
        lambda art, m: _pickle_to(art.path / "scaler.bin", SimpleNamespace()),
        "unreadable scaler.bin: Blocked",
    ),
}


@pytest.mark.parametrize("case", list(FAILURES))
def test_pretrained_start_fails_loudly(tmp_path, pretrained, case):
    """Any missing file or mismatch raises a clear PretrainedLoadError (and
    prints it); nothing is installed, so no model is silently empty."""
    art = pretrained("random_projection_mlp")
    m = _peer(tmp_path, "slips-1", art.dir, "random_projection_mlp")
    mutate, match = FAILURES[case]
    mutate(art, m)
    with pytest.raises(fnm.PretrainedLoadError, match=match):
        m._load_pretrained()
    assert m.model is None and m._model0 is None
    assert not (m._is_fitted or m.is_preprocessor_fitted)
    assert not os.path.exists(os.path.join(m.output_dir, "model0_test.log"))
    assert "pretrained start failed" in str(m.print.call_args)


# --------------------------------------------------------------------------
# config: opt-in only, the empty start stays the default
# --------------------------------------------------------------------------
class _Conf:
    """ConfigParser stand-in serving one federated_network_module section."""

    section: dict = {}

    def read_configuration(self, section, name, default):
        assert section == "federated_network_module"
        return self.section.get(name, default)


def _dispatch(monkeypatch, section):
    """Run _init_start_model on a bare module under `section`; returns
    (module, calls) with the loaders replaced by recorders."""
    conf = _Conf()
    conf.section = section
    monkeypatch.setattr(fnm, "ConfigParser", lambda: conf)
    m = object.__new__(fnm.FederatedNetworkModule)
    calls = []
    m._load_pretrained = lambda: calls.append("pretrained")
    m._load_local_model = lambda: calls.append("latest_local")
    m._init_start_model()
    return m, calls


@pytest.mark.parametrize(
    "section, calls",
    [
        ({}, ["latest_local"]),  # no key at all: exactly as before
        ({"train_from_scratch": True}, []),
        ({"pretrained": False}, ["latest_local"]),
        ({"pretrained": "false", "train_from_scratch": True}, []),
        ({"pretrained": None}, ["latest_local"]),
        ({"pretrained": "maybe"}, ["latest_local"]),  # unparseable -> false
        ({"pretrained": [1]}, ["latest_local"]),
        # opt-in overrides both the warm start and train_from_scratch
        ({"pretrained": True}, ["pretrained"]),
        ({"pretrained": "true", "train_from_scratch": True}, ["pretrained"]),
    ],
)
def test_pretrained_is_opt_in_and_overrides_the_start_model(
    monkeypatch, section, calls
):
    m, made = _dispatch(monkeypatch, section)
    assert made == calls
    assert m.pretrained is (calls == ["pretrained"])


@pytest.mark.parametrize(
    "configured, expected",
    [
        (None, os.path.join(MODULE_DIR, "artifacts", "pretrained")),
        ("", os.path.join(MODULE_DIR, "artifacts", "pretrained")),
        (
            "artifacts/pretrained",
            os.path.join(MODULE_DIR, "artifacts/pretrained"),
        ),
        ("elsewhere/base", os.path.join(MODULE_DIR, "elsewhere/base")),
        ("/abs/base", "/abs/base"),
    ],
)
def test_pretrained_dir_is_relative_to_the_module(
    monkeypatch, configured, expected
):
    section = {} if configured is None else {"pretrained_dir": configured}
    m, _ = _dispatch(monkeypatch, section)
    assert m.pretrained_dir == expected


def test_yaml_declares_the_opt_in_defaults():
    path = os.path.join(MODULE_DIR, "..", "..", "config", "slips.yaml")
    with open(path) as f:
        section = yaml.safe_load(f)["federated_network_module"]
    assert section["pretrained"] is False
    assert fnm.FederatedNetworkModule._resolve_pretrained_dir(
        section["pretrained_dir"]
    ) == fnm.FederatedNetworkModule._resolve_pretrained_dir("")


# --------------------------------------------------------------------------
# the base class's pre_main artifact load
# --------------------------------------------------------------------------
def test_base_read_model_keeps_the_pretrained_scaler(
    tmp_path, pretrained, monkeypatch
):
    """pre_main's base read_model would replace self.scaler (empty or
    preprocess_load_path); a pretrained start keeps the loaded one, every
    other start still goes through the base class unchanged."""
    base = MagicMock()
    monkeypatch.setattr(ml_base.MLBaseDetection, "read_model", base)
    art = pretrained("simple_mlp")
    m = _peer(tmp_path, "slips-1", art.dir, "simple_mlp")
    m._load_pretrained()
    scaler, model = m.scaler, m.model
    m.read_model()
    assert m.scaler is scaler and m.model is model
    assert (m.clf, m.preprocessor) == (model, scaler)
    base.assert_not_called()
    m.pretrained = False
    m.read_model()
    base.assert_called_once()


def test_base_read_model_keeps_a_warm_started_scaler(
    tmp_path, pretrained, monkeypatch
):
    """Warm start (train_from_scratch: false) reloads latest_local_* in
    init(); the base read_model must not swap that scaler for an empty one,
    or every chained offline run re-fits the scaler on its own capture."""
    base = MagicMock()
    monkeypatch.setattr(ml_base.MLBaseDetection, "read_model", base)
    art = pretrained("simple_mlp")
    src = _peer(tmp_path, "slips-0", art.dir, "simple_mlp")
    src._load_pretrained()
    state, scaler_path = tmp_path / "state.bin", tmp_path / "scaler.bin"
    torch.save(src.model.state_dict(), state)
    with open(scaler_path, "wb") as fh:
        pickle.dump(src.scaler, fh)
    m = _peer(tmp_path, "slips-1", art.dir, "simple_mlp")
    m.pretrained, m._warm_started = False, False
    m.local_state_path, m.local_scaler_path = str(state), str(scaler_path)
    m._load_local_model()
    assert m._warm_started
    seen = m.scaler.n_samples_seen_
    m.read_model()
    base.assert_not_called()
    assert m.scaler.n_samples_seen_ == seen and m.preprocessor is m.scaler
    m._warm_started = False  # nothing reloaded: the base class runs
    m.read_model()
    base.assert_called_once()
