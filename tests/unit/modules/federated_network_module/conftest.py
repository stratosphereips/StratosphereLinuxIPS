"""Shared fixtures of the federated network module tests."""

import hashlib
import json
import os
import pickle
import shutil
from types import SimpleNamespace

import numpy as np
import pytest
import torch
from sklearn.preprocessing import StandardScaler

from modules.federated_network_module import (
    federated_network_module as fnm,
)

SEED = 1111
SHIPPED_RP = os.path.join(
    os.path.dirname(fnm.__file__), "artifacts", "random_projection.bin"
)


def sha256_of(path) -> str:
    """Hex sha256 of a file's bytes."""
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


@pytest.fixture
def pretrained(tmp_path):
    """Factory writing <tmp>/pretrained/<model_class>/ as the offline
    pretraining would: model_state.bin (full state_dict of a model built
    with its own seed and its own copy of the shipped projection, which the
    build re-saves), scaler.bin (a fitted StandardScaler) and meta.json
    (model_class + sha256 of the pretrainer's projection file). `meta`
    entries override meta.json fields. Returns dir (the pretrained_dir),
    path, state, scaler and meta."""
    root = tmp_path / "pretrained"

    def make(model_class="random_projection_mlp", meta=None):
        rp_dir = tmp_path / "pretrainer" / model_class
        rp_dir.mkdir(parents=True, exist_ok=True)
        rp_path = rp_dir / "random_projection.bin"
        shutil.copy(SHIPPED_RP, rp_path)
        stub = SimpleNamespace(rp_path=str(rp_path), seed=SEED, input_dim=None)
        model = fnm.build_with_init_seed(
            fnm.peer_init_seed(SEED, "pretrainer"),
            lambda: fnm.MODEL_REGISTRY[model_class](stub),
        )
        rng = np.random.default_rng(7)
        scaler = StandardScaler().fit(rng.normal(5.0, 3.0, size=(200, 18)))
        out = root / model_class
        out.mkdir(parents=True, exist_ok=True)
        torch.save(model.state_dict(), out / "model_state.bin")
        with open(out / "scaler.bin", "wb") as f:
            pickle.dump(scaler, f)
        info = {
            "model_class": model_class,
            "random_projection_sha256": sha256_of(rp_path),
        }
        info.update(meta or {})
        (out / "meta.json").write_text(json.dumps(info))
        return SimpleNamespace(
            dir=str(root),
            path=out,
            state={k: v.clone() for k, v in model.state_dict().items()},
            scaler=scaler,
            meta=info,
        )

    return make
