"""Model initialisation of the federated network module.

The frozen random projection is shared by every peer (and equals the
distributed artifacts/random_projection.bin); the trainable layers are also
SHARED across peers - every peer starts fc1/head from the same seed so FedAvg's
averaging of the shared layers is meaningful.
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
    peer_a = _build(builder, fnm.shared_init_seed(SEED), rp_path)
    peer_b = _build(builder, fnm.shared_init_seed(SEED), rp_path)
    shipped = torch.load(SHIPPED_RP, weights_only=True)
    for model in (peer_a, peer_b):
        assert torch.equal(model.random_projection.weight.data, shipped.T)
        assert not model.random_projection.weight.requires_grad


@pytest.mark.parametrize("builder", BUILDERS)
def test_trainable_layers_are_identical_across_peers(builder, tmp_path):
    # shared init: every peer starts fc1/head from the same weights, so FedAvg
    # averages compatible layers (per-peer init broke merging)
    rp_path = str(tmp_path / "rp.bin")
    a = _trainable(_build(builder, fnm.shared_init_seed(SEED), rp_path))
    b = _trainable(_build(builder, fnm.shared_init_seed(SEED), rp_path))
    assert a.keys() == b.keys() and a
    assert all(torch.equal(a[k], b[k]) for k in a)


@pytest.mark.parametrize("builder", BUILDERS)
def test_trainable_layers_are_reproducible(builder, tmp_path):
    seed = fnm.shared_init_seed(SEED)
    first = _trainable(_build(builder, seed, str(tmp_path / "a.bin")))
    # the shipped/regenerated projection file must not change the result
    second = _trainable(_build(builder, seed, str(tmp_path / "a.bin")))
    assert all(torch.equal(first[k], second[k]) for k in first)


def test_building_a_model_leaves_the_global_rng_untouched(tmp_path):
    state = torch.get_rng_state()
    _build(fnm._build_random_projection_mlp, 42, str(tmp_path / "rp.bin"))
    assert torch.equal(torch.get_rng_state(), state)


def test_shared_init_seed_is_stable_and_shared():
    # no peer_id: identical for every peer, stable run-to-run, in range
    assert fnm.shared_init_seed(SEED) == fnm.shared_init_seed(SEED)
    assert fnm.shared_init_seed(SEED) != fnm.shared_init_seed(SEED + 1)
    assert 0 <= fnm.shared_init_seed(SEED) < 2**31


def test_two_layer_second_projection_frozen_shared_and_forward(tmp_path):
    """RP-L-RP-L-H: a second frozen projection that is identical across peers,
    while only the two trainable linears are shared and the net runs forward.
    """
    a = _build(
        fnm._build_random_projection_two_layer,
        fnm.shared_init_seed(SEED),
        str(tmp_path / "a.bin"),
    )
    b = _build(
        fnm._build_random_projection_two_layer,
        fnm.shared_init_seed(SEED),
        str(tmp_path / "b.bin"),
    )
    # RP2 exists, is frozen, and is identical on both peers (shared by seed)
    assert hasattr(a, "random_projection2")
    assert a.random_projection2.weight.requires_grad is False
    assert torch.equal(
        a.random_projection2.weight.data, b.random_projection2.weight.data
    )
    # RP1 also still shared; the two RPs are different matrices
    assert torch.equal(
        a.random_projection.weight.data, b.random_projection.weight.data
    )
    assert not torch.equal(
        a.random_projection.weight.data, a.random_projection2.weight.data
    )
    # shared/federated weights are exactly the two trainable linears
    assert set(a.weights_for_sharing()) == {
        "fc1_weight",
        "fc1_bias",
        "fc2_weight",
        "fc2_bias",
    }
    # the frozen projections must NOT be shared
    assert not any("projection" in k for k in a.weights_for_sharing())
    # end-to-end forward produces 2-class logits
    out = a(torch.randn(4, fnm.SimpleFederatedNet.FIXED_INPUT_DIM))
    assert out.shape == (4, 2)


def test_simple_mlp_is_the_trainable_twin_of_rlh(tmp_path):
    """simple_mlp: 18->256->16->2 — same neurons as R-L-H (256 from the RP
    layer as a LEARNABLE linear, 16, head 2), no random projection, nothing
    frozen, both linears federated."""
    stub = SimpleNamespace(
        rp_path=str(tmp_path / "rp.bin"), seed=SEED, input_dim=None
    )
    model = fnm.build_with_init_seed(
        fnm.shared_init_seed(SEED),
        lambda: fnm._build_simple_mlp(stub),
    )
    assert not hasattr(model, "random_projection")
    assert model.fc1.in_features == 18 and model.fc1.out_features == 256
    assert model.fc2.in_features == 256 and model.fc2.out_features == 16
    assert model.head.in_features == 16 and model.head.out_features == 2
    # nothing frozen
    assert all(p.requires_grad for p in model.parameters())
    # federated tensors: the two linears (head stays local)
    assert set(model.weights_for_sharing()) == {
        "fc1_weight",
        "fc1_bias",
        "fc2_weight",
        "fc2_bias",
    }
    out = model(torch.randn(4, fnm.SimpleFederatedNet.FIXED_INPUT_DIM))
    assert out.shape == (4, 2)


@pytest.mark.parametrize(
    "value, expected",
    [
        (None, None),
        ("", None),
        ("None", None),
        ("x", None),
        ("3", 3),
        (4, 4),
        (0, 0),
    ],
)
def test_run_seed_from_config(value, expected):
    assert fnm.run_seed_from_config(value) == expected


@pytest.mark.parametrize(
    "value, expected",
    [
        (None, 0.01),
        ("", 0.01),
        ("x", 0.01),
        ("0", 0.01),
        (-0.1, 0.01),
        ("nan", 0.01),
        ("inf", 0.01),
        ("0.03", 0.03),
        (0.1, 0.1),
        (1, 1.0),
    ],
)
def test_learning_rate_from_config(value, expected):
    assert fnm.learning_rate_from_config(value) == expected


def test_window_offset_seed_without_run_seed_is_the_peer_id_hash():
    import hashlib

    peer = "slips-weak"
    expected = int(hashlib.md5(peer.encode()).hexdigest(), 16) % (2**31)
    assert fnm.window_offset_seed(peer, None) == expected


def test_window_offset_seed_varies_per_run_and_per_peer():
    a = fnm.window_offset_seed("slips-weak", 2)
    assert a == fnm.window_offset_seed("slips-weak", 2)
    assert a != fnm.window_offset_seed("slips-weak", 3)
    assert a != fnm.window_offset_seed("slips-strong", 2)
    assert a != fnm.window_offset_seed("slips-weak", None)
    assert 0 <= a < 2**31


def test_run_seed_does_not_touch_the_model_init_seed():
    # the trainable init and the random projection derive from `seed` only
    import inspect

    assert list(inspect.signature(fnm.shared_init_seed).parameters) == ["seed"]
