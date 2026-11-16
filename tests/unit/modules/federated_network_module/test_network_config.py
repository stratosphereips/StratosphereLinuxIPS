"""Every model_class runs the network its docs describe, and every network
config key reaches the module.

Each registry model is checked layer by layer: which layers run, in which
order, where the ReLUs are, and the 1/16 projection scaling, against a forward
pass written out by hand from the model's own weights. The config keys go
through the real init() with a stubbed yaml section (the base class init,
redis and the yaml file are not used; the repo artifacts are only read).
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import numpy as np
import pytest
import torch
import torch.nn.functional as F

from modules.federated_network_module import (
    federated_network_module as fnm,
)
from slips_files.common.abstracts import ml_module_base as ml_base

SEED = 1111
SECTION = fnm.FederatedNetworkModule.module_config_section
RLH, RLHR = "random_projection_mlp", "random_projection_relu_mlp"

# The layers each model runs, in order (leaf modules; the 1/16 scaling is not
# a module, the hand-written forward checks it).
LAYERS = {
    RLH: ["random_projection", "fc1", "relu", "head"],
    RLHR: ["random_projection", "relu", "fc1", "relu", "head"],
    "simple_mlp": ["fc1", "relu", "fc2", "relu", "head"],
    "random_projection_two_layer": [
        "random_projection",
        "fc1",
        "relu",
        "random_projection2",
        "lin2",
        "relu",
        "head",
    ],
}


def _by_hand(name: str, m: torch.nn.Module, x: torch.Tensor) -> torch.Tensor:
    """The forward pass of model `name`, written out from m's weights."""
    relu = torch.relu
    if name == "simple_mlp":
        h = relu(F.linear(x, m.fc1.weight, m.fc1.bias))
        h = relu(F.linear(h, m.fc2.weight, m.fc2.bias))
        return F.linear(h, m.head.weight, m.head.bias)
    p = F.linear(x, m.random_projection.weight) / 16.0
    if name == RLHR:
        p = relu(p)
    h = relu(F.linear(p, m.fc1.weight, m.fc1.bias))
    if name == "random_projection_two_layer":
        h = F.linear(h, m.random_projection2.weight) / 16.0
        h = relu(F.linear(h, m.lin2.weight, m.lin2.bias))
    return F.linear(h, m.head.weight, m.head.bias)


def _build(name: str, tmp_path, seed: int = SEED) -> torch.nn.Module:
    """Model `name` as a peer builds it (shared init from `seed`)."""
    stub = SimpleNamespace(
        rp_path=str(tmp_path / f"rp-{seed}.bin"), seed=seed, input_dim=None
    )
    return fnm.build_with_init_seed(
        fnm.shared_init_seed(seed), lambda: fnm.MODEL_REGISTRY[name](stub)
    )


def _x(n: int = 256, seed: int = 0) -> torch.Tensor:
    """Standard-normal features, as the global scaler's z-scores are."""
    g = torch.Generator().manual_seed(seed)
    return torch.randn(n, fnm.SimpleFederatedNet.FIXED_INPUT_DIM, generator=g)


def _layers_run(model: torch.nn.Module, x: torch.Tensor) -> list:
    """Names of the leaf modules model(x) calls, in call order."""
    names = {
        mod: name
        for name, mod in model.named_modules()
        if name and not list(mod.children())
    }
    order = []
    hooks = [
        mod.register_forward_hook(
            lambda mod, inp, out: order.append(names[mod])
        )
        for mod in names
    ]
    try:
        model(x)
    finally:
        for h in hooks:
            h.remove()
    return order


def _fc1_input(model: torch.nn.Module, x: torch.Tensor) -> torch.Tensor:
    """What fc1 receives during model(x)."""
    seen = []
    hook = model.fc1.register_forward_pre_hook(
        lambda mod, inp: seen.append(inp[0].detach().clone())
    )
    try:
        model(x)
    finally:
        hook.remove()
    return seen[0]


# --------------------------------------------------------------------------
# the networks
# --------------------------------------------------------------------------
def test_every_registry_model_has_a_layer_spec():
    assert set(fnm.MODEL_REGISTRY) == set(LAYERS)


@pytest.mark.parametrize("name", sorted(LAYERS))
def test_each_model_runs_its_layers_in_the_documented_order(name, tmp_path):
    assert _layers_run(_build(name, tmp_path), _x()) == LAYERS[name]


@pytest.mark.parametrize("name", sorted(LAYERS))
def test_each_forward_equals_the_hand_written_pass(name, tmp_path):
    m = _build(name, tmp_path)
    with torch.no_grad():  # trained-looking weights, not only the init
        for p in m.parameters():
            if p.requires_grad:
                p.add_(0.1 * torch.randn_like(p))
    x = _x()
    assert torch.allclose(m(x), _by_hand(name, m, x), atol=1e-6)


@pytest.mark.parametrize("name, rectified", [(RLH, False), (RLHR, True)])
def test_fc1_sees_rectified_features_only_with_the_projection_relu(
    name, rectified, tmp_path
):
    """The projection relu zeroes about half the 256 random features of
    every flow; without it fc1 gets them signed."""
    feats = _fc1_input(_build(name, tmp_path), _x())
    assert feats.shape == (256, 256)
    negative = (feats < 0).float().mean().item()
    zero = (feats == 0).float().mean().item()
    if rectified:
        assert negative == 0.0 and 0.3 < zero < 0.7
    else:
        assert 0.3 < negative < 0.7 and zero == 0.0


@pytest.mark.parametrize("name, linear", [(RLH, True), (RLHR, False)])
def test_only_the_projection_relu_makes_fc1_nonlinear_in_the_input(
    name, linear, tmp_path
):
    """Without the relu, projection + scaling + fc1 is one linear map
    (fc1(x) - bias is odd in x); with it, it is not."""
    m = _build(name, tmp_path)
    x = _x()
    with torch.no_grad():
        pre = lambda v: F.linear(_fc1_input(m, v), m.fc1.weight)  # noqa: E731
        odd = torch.allclose(pre(-x), -pre(x), atol=1e-6)
    assert odd == linear


def test_the_relu_model_is_the_default_model_plus_the_relu(tmp_path):
    """Same seed: the same projection, initial weights, frozen and
    federated tensors and class weighting as random_projection_mlp; only
    the forward pass differs."""
    rlh, rlhr = _build(RLH, tmp_path), _build(RLHR, tmp_path)
    assert isinstance(rlhr, fnm.SimpleFederatedNet)
    a, b = rlh.state_dict(), rlhr.state_dict()
    assert a.keys() == b.keys()
    assert all(torch.equal(a[k], b[k]) for k in a)
    assert {n: p.requires_grad for n, p in rlh.named_parameters()} == {
        n: p.requires_grad for n, p in rlhr.named_parameters()
    }
    sa, sb = rlh.weights_for_sharing(), rlhr.weights_for_sharing()
    assert sa.keys() == sb.keys() == {"fc1_weight", "fc1_bias"}
    assert all(sa[k].shape == sb[k].shape for k in sa)
    assert rlh.USE_CLASS_WEIGHTING == rlhr.USE_CLASS_WEIGHTING is True
    x = _x()
    assert not torch.allclose(rlh(x), rlhr(x))


@pytest.mark.parametrize("name", sorted(LAYERS))
def test_seed_sets_the_projection_and_the_initial_weights(name, tmp_path):
    a, b = _build(name, tmp_path), _build(name, tmp_path, seed=SEED + 1)
    for key, tensor in a.state_dict().items():
        assert not torch.equal(tensor, b.state_dict()[key]), key


@pytest.mark.parametrize("name", sorted(LAYERS))
def test_shared_weights_round_trip(name, tmp_path):
    """A peer's federated tensors set into another model of the class
    reproduce the peer's forward pass (head copied too)."""
    src, dst = _build(name, tmp_path), _build(name, tmp_path, seed=7)
    with torch.no_grad():
        for p in src.parameters():
            if p.requires_grad:
                p.add_(0.1 * torch.randn_like(p))
    dst.set_shared_weights(src.weights_for_sharing())
    dst.set_head_weights(*src.get_head_weights())
    if hasattr(src, "random_projection"):  # frozen, shared by seed
        dst.load_state_dict(src.state_dict())
    x = _x()
    assert torch.equal(dst(x), src(x))


# --------------------------------------------------------------------------
# the config keys, through the real init()
# --------------------------------------------------------------------------
def _init(tmp_path, monkeypatch, **cfg) -> fnm.FederatedNetworkModule:
    """The module after its real init() read `cfg` as its yaml section."""
    cfg.setdefault("train_from_scratch", True)  # never load repo artifacts

    def base_init(self):
        self.mode = "train"
        self.seed = SEED
        self.enable_logs = False

    def read(self, section, key, default):
        return cfg.get(key, default) if section == SECTION else default

    monkeypatch.setattr(ml_base.MLBaseDetection, "init", base_init)
    monkeypatch.setattr(fnm.ConfigParser, "read_configuration", read)
    # init() pins torch threads, which torch refuses once it has run
    monkeypatch.setattr(torch, "set_num_threads", lambda n: None)
    monkeypatch.setattr(torch, "set_num_interop_threads", lambda n: None)
    m = object.__new__(fnm.FederatedNetworkModule)
    m.print = MagicMock()
    m.output_dir = str(tmp_path)
    m.db = MagicMock()
    m.init()
    # model builds save the projection: here, not into the repo's artifacts
    m.rp_path = str(tmp_path / "rp.bin")
    return m


def test_network_key_defaults(tmp_path, monkeypatch):
    m = _init(tmp_path, monkeypatch)
    assert m.model_class_name == RLH
    assert m.learning_rate == 0.01
    assert (m.local_training_epochs, m.merge_finetune_epochs) == (10, 5)
    assert m.finetune_head is True and m.finetune_fc_layers is True
    assert m.merge_finetune_adam == "copy"
    assert m.merge_head is False and m.merge_scaler is False
    assert m.global_scaler is True
    assert m.minibatch_size == 0
    assert m.merge_rule == "average" and m.balancing == ""
    assert m.run_seed is None
    assert m.min_training_samples == 30


@pytest.mark.parametrize(
    "key, value, attr, expected",
    [
        ("model_class", RLHR, "model_class_name", RLHR),
        ("model_class", "simple_mlp", "model_class_name", "simple_mlp"),
        ("learning_rate", "0.05", "learning_rate", 0.05),
        ("learning_rate", 0.01, "learning_rate", 0.01),
        ("local_training_epochs", "20", "local_training_epochs", 20),
        ("merge_finetune_epochs", 3, "merge_finetune_epochs", 3),
        ("finetune_head", False, "merge_finetune_epochs", 0),
        ("finetune_fc_layers", "false", "finetune_fc_layers", False),
        ("merge_finetune_adam", "fresh", "merge_finetune_adam", "fresh"),
        ("merge_head", True, "merge_head", True),
        ("merge_scaler", "true", "merge_scaler", True),
        ("global_scaler", False, "global_scaler", False),
        ("minibatch_size", "64", "minibatch_size", 64),
        ("merge_rule", "proximity", "merge_rule", "proximity"),
        ("merge_rule", "trust_weighted", "merge_rule", "trust_weighted"),
        ("merge_rule", "distance_weighted", "merge_rule", "distance_weighted"),
        ("balancing", "Undersample", "balancing", "undersample"),
        ("balancing", "none", "balancing", "none"),
        ("run_seed", "3", "run_seed", 3),
        ("min_training_samples", "50", "min_training_samples", 50),
    ],
)
def test_each_network_key_reaches_the_module(
    key, value, attr, expected, tmp_path, monkeypatch
):
    m = _init(tmp_path, monkeypatch, **{key: value})
    assert getattr(m, attr) == expected


@pytest.mark.parametrize("name", sorted(LAYERS))
def test_model_class_key_builds_that_network(name, tmp_path, monkeypatch):
    m = _init(tmp_path, monkeypatch, model_class=name)
    net = m.create_empty_model()
    x = _x()
    assert _layers_run(net, x) == LAYERS[name]
    assert torch.allclose(net(x), _by_hand(name, net, x), atol=1e-6)
    # the module's shared init: equal to a peer's build of the class
    ref = _build(name, tmp_path)
    assert all(
        torch.equal(t, ref.state_dict()[k])
        for k, t in net.state_dict().items()
    )


def test_unknown_model_class_fails_when_the_model_is_built(
    tmp_path, monkeypatch
):
    m = _init(tmp_path, monkeypatch, model_class="no_such_net")
    with pytest.raises(ValueError, match="unknown model_class"):
        m.create_empty_model()


def test_unknown_merge_rule_stops_the_module(tmp_path, monkeypatch):
    with pytest.raises(ValueError, match="unknown merge_rule"):
        _init(tmp_path, monkeypatch, merge_rule="no_such_rule")


@pytest.mark.parametrize(
    "cfg, weighted",
    [
        ({}, True),
        ({"model_class": RLHR}, True),
        ({"model_class": "simple_mlp"}, False),
        ({"class_weighting": False}, False),
        ({"balancing": "undersample"}, False),
        ({"balancing": "none", "class_weighting": True}, False),
        ({"balancing": "weighting", "model_class": "simple_mlp"}, True),
    ],
)
def test_class_weighting_and_balancing_keys_reach_the_network(
    cfg, weighted, tmp_path, monkeypatch
):
    m = _init(tmp_path, monkeypatch, **cfg)
    assert m.create_empty_model().USE_CLASS_WEIGHTING is weighted


def _one_local_training(m: fnm.FederatedNetworkModule) -> dict:
    """Local training on 10 flows (8 malicious) from the module's fresh
    model; returns the weight change and leaves m._adam_state."""
    m.model = m.create_empty_model()
    before = {k: v.clone() for k, v in m.model.state_dict().items()}
    x = np.random.default_rng(0).normal(size=(10, 18)).astype(np.float32)
    m.fit_incremental_model(x, [fnm.MALICIOUS] * 8 + [fnm.BENIGN] * 2)
    after = m.model.state_dict()
    return {k: after[k] - before[k] for k in before}


@pytest.mark.parametrize("name", sorted(LAYERS))
def test_learning_rate_key_scales_the_first_training_step(
    name, tmp_path, monkeypatch
):
    deltas = [
        _one_local_training(
            _init(
                tmp_path / lr,
                monkeypatch,
                model_class=name,
                learning_rate=lr,
                local_training_epochs=1,
            )
        )
        for lr in ("0.01", "0.02")
    ]
    assert any(d.abs().sum() > 0 for d in deltas[0].values())
    for k in deltas[0]:
        assert torch.allclose(deltas[1][k], 2 * deltas[0][k], atol=1e-6)


@pytest.mark.parametrize(
    "epochs, minibatch, steps", [(1, 0, 1), (3, 0, 3), (2, 3, 8)]
)
def test_epoch_and_minibatch_keys_set_the_number_of_adam_steps(
    epochs, minibatch, steps, tmp_path, monkeypatch
):
    """local_training_epochs full passes, each one step per mini-batch
    (ceil(10 / 3) = 4); 0 = one full-batch step per pass."""
    m = _init(
        tmp_path,
        monkeypatch,
        model_class=RLHR,
        local_training_epochs=epochs,
        minibatch_size=minibatch,
    )
    delta = _one_local_training(m)
    assert m._adam_state["fc1.weight"]["step"] == steps
    assert m._adam_state["head.weight"]["step"] == steps
    # the frozen projection is never stepped and never moves
    assert (
        m._adam_state.get("random_projection.weight", {"step": 0})["step"] == 0
    )
    assert not delta["random_projection.weight"].any()
