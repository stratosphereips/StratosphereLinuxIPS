"""Model initialisation of the federated network module.

The frozen random projection is shared by every peer (and equals the
distributed artifacts/random_projection.bin); the trainable layers use the
same init scheme on every peer but a per-peer, run-to-run reproducible seed.
"""

import os
from types import SimpleNamespace

import pytest
import torch

from modules.federated_network_module import (
    federated_network_module as fnm,
)

SEED = 1111
SHIPPED_RP = os.path.join(
    os.path.dirname(fnm.__file__), "artifacts", "random_projection.bin"
)
BUILDERS = [
    fnm._build_random_projection_mlp,
    fnm._build_random_projection_two_layer,
    fnm._build_simple_mlp,
]
RP_BUILDERS = BUILDERS[:2]


def _build(builder, init_seed, rp_path):
    stub = SimpleNamespace(rp_path=rp_path, seed=SEED, input_dim=None)
    return fnm.build_with_init_seed(init_seed, lambda: builder(stub))


def _trainable(model):
    return {
        name: p.detach().clone()
        for name, p in model.named_parameters()
        if p.requires_grad
    }


def test_shared_projection_equals_the_distributed_artifact():
    shipped = torch.load(SHIPPED_RP, weights_only=True)
    regenerated = fnm.shared_random_projection(18, 256, SEED)
    assert torch.equal(regenerated, shipped)


@pytest.mark.parametrize("builder", RP_BUILDERS)
@pytest.mark.parametrize("rp_file", ["missing", "corrupt", "shipped"])
def test_projection_is_identical_across_peers_however_obtained(
    builder, rp_file, tmp_path
):
    rp_path = str(tmp_path / "random_projection.bin")
    if rp_file == "corrupt":
        with open(rp_path, "wb") as f:
            f.write(b"not a tensor")
    elif rp_file == "shipped":
        with open(SHIPPED_RP, "rb") as src, open(rp_path, "wb") as dst:
            dst.write(src.read())
    peer_a = _build(builder, fnm.peer_init_seed(SEED, "slips-1"), rp_path)
    peer_b = _build(builder, fnm.peer_init_seed(SEED, "slips-2"), rp_path)
    shipped = torch.load(SHIPPED_RP, weights_only=True)
    for model in (peer_a, peer_b):
        assert torch.equal(model.random_projection.weight.data, shipped.T)
        assert not model.random_projection.weight.requires_grad


@pytest.mark.parametrize("builder", BUILDERS)
def test_trainable_layers_differ_between_peers(builder, tmp_path):
    rp_path = str(tmp_path / "rp.bin")
    a = _trainable(
        _build(builder, fnm.peer_init_seed(SEED, "slips-1"), rp_path)
    )
    b = _trainable(
        _build(builder, fnm.peer_init_seed(SEED, "slips-2"), rp_path)
    )
    assert a.keys() == b.keys() and a
    assert all(not torch.equal(a[k], b[k]) for k in a)


@pytest.mark.parametrize("builder", BUILDERS)
def test_trainable_layers_are_reproducible_per_peer(builder, tmp_path):
    seed = fnm.peer_init_seed(SEED, "slips-3")
    first = _trainable(_build(builder, seed, str(tmp_path / "a.bin")))
    # the shipped/regenerated projection file must not change the result
    second = _trainable(_build(builder, seed, str(tmp_path / "a.bin")))
    assert all(torch.equal(first[k], second[k]) for k in first)


def test_building_a_model_leaves_the_global_rng_untouched(tmp_path):
    state = torch.get_rng_state()
    _build(fnm._build_random_projection_mlp, 42, str(tmp_path / "rp.bin"))
    assert torch.equal(torch.get_rng_state(), state)


def test_peer_init_seed_is_stable_and_peer_specific():
    assert fnm.peer_init_seed(SEED, "slips-1") == fnm.peer_init_seed(
        SEED, "slips-1"
    )
    assert fnm.peer_init_seed(SEED, "slips-1") != fnm.peer_init_seed(
        SEED, "slips-2"
    )
    assert 0 <= fnm.peer_init_seed(SEED, "slips-1") < 2**31
