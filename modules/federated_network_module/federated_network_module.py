# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""
Federated Network Module - Federated Learning with Model Sharing

Architecture: input(N features, fixed 18) -> RandomProjection(256,frozen,shared) -> Linear(256->16)+ReLU [fc1] -> Linear(16->2) [head]

Training Flow:
1. Local Training (on wall-clock window close every 5 minutes):
   - Buffer flows and alerts during the window
   - Label flows using all evidence from buffered alerts; rest benign
   - Train fc1 + head for local_training_epochs
   - Save the head produced by local training as "head_before"
   - Freeze fc1, fine-tune head for merge_finetune_epochs (local_head_train.log)
   - Save as latest_local model
   - Send to peers via P2P

2. Model Merging (event-based, after own local training):
   - Collect all peer models + own latest local
   - Aggregate fc1 weights (AVERAGE)
   - Restore "head_before" (head from local full training)
   - Fine-tune head for merge_finetune_epochs (merged_train.log) with fc1 frozen
   - Save as merged_N model (merged models NOT used in future merges)

This makes local and merged models directly comparable: both heads start from
identical weights and receive the same head-only fine-tuning; only fc1 differs.

Key Features:
- Fixed 18-feature input
- Single training buffer per wall-clock window
- Model separation: latest_local (own data only) vs merged (aggregated)
- Off-sync windows: random time offset per peer to avoid synchronized pulses
- Graceful shutdown: saves latest_local and latest merged model

Artifact Paths:
- Base (shared): artifacts/random_projection.bin, artifacts/scaler.bin
- Local: artifacts/latest_local_fc1.bin, latest_local_head.bin, latest_local_scaler.bin
- Merged: artifacts/merged_N_fc1.bin, merged_N_head.bin (N = merge count)
"""

import collections
import ipaddress
import json
import os
import pickle
import random
import copy
import shutil
import time
import traceback
from typing import Dict, Optional

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.preprocessing import StandardScaler

import slips_files.common.abstracts.ml_module_base as ml_base
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.core.structures.evidence import EvidenceType

BENIGN = ml_base.BENIGN
MALICIOUS = ml_base.MALICIOUS


class SimpleFederatedNet(nn.Module):
    """
    Federated network model: frozen shared random projection + learnable fc1 + head.

    Architecture: input(18) -> RandomProjection(256,frozen) -> /sqrt(256) -> Linear(256->16)+ReLU -> Linear(16->2)

    FIXED FEATURE COUNT: 18 Zeek-native features (see process_features for full list)
    """

    FIXED_INPUT_DIM = 18  # Must match len(feature_order) in process_features

    # Class weighting per batch is a property of THIS model only; other models
    # in the registry set USE_CLASS_WEIGHTING = False and train on plain CE.
    USE_CLASS_WEIGHTING = True

    def __init__(
        self,
        input_dim: int,
        hidden1: int = 256,
        hidden2: int = 16,
        rp_path: Optional[str] = None,
        seed: int = 1111,
    ):
        super().__init__()
        self.seed = seed
        self.hidden1 = hidden1
        self.hidden2 = hidden2

        # Validate input dimension matches expected fixed size
        if input_dim != self.FIXED_INPUT_DIM:
            raise ValueError(
                f"Input dimension {input_dim} does not match expected "
                f"fixed size {self.FIXED_INPUT_DIM}. "
                f"Check process_features() feature_order list."
            )
        self.input_dim = self.FIXED_INPUT_DIM

        # Load or create frozen random projection with He initialization
        import sys

        sys.stdout.flush()
        if rp_path and os.path.exists(rp_path):
            try:
                random_weights = torch.load(rp_path, weights_only=True)
                if random_weights.shape[0] != self.FIXED_INPUT_DIM:
                    raise ValueError(
                        f"Loaded random_projection has input_dim={random_weights.shape[0]}, "
                        f"expected {self.FIXED_INPUT_DIM}"
                    )
            except (RuntimeError, ValueError) as e:
                print(
                    f"[FederatedNetworkModule] Random projection load failed: {e}. "
                    f"Reconstructing new random projection from seed={seed}."
                )
                random_weights = torch.empty(self.FIXED_INPUT_DIM, hidden1)
                nn.init.kaiming_normal_(
                    random_weights, mode="fan_in", nonlinearity="relu"
                )
        else:
            torch.manual_seed(seed)
            random_weights = torch.empty(self.FIXED_INPUT_DIM, hidden1)
            nn.init.kaiming_normal_(
                random_weights, mode="fan_in", nonlinearity="relu"
            )

        if rp_path:
            os.makedirs(os.path.dirname(rp_path), exist_ok=True)
            torch.save(random_weights, rp_path)

        self.random_projection = nn.Linear(
            self.FIXED_INPUT_DIM, hidden1, bias=False
        )
        self.random_projection.weight.data = random_weights.T
        self.random_projection.weight.requires_grad = False

        self.projection_scale = hidden1**0.5

        # fc1 layer (learnable)
        self.fc1 = nn.Linear(hidden1, hidden2, bias=True)

        # Head layer (learnable)
        self.head = nn.Linear(hidden2, 2)
        self.relu = nn.ReLU()

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.random_projection(x)
        x = x / self.projection_scale
        x = self.fc1(x)
        x = self.relu(x)
        x = self.head(x)
        return x

    def get_fc1_weights(self) -> tuple:
        """Get fc1 weights and bias for model sharing."""
        return self.fc1.weight.data.clone(), self.fc1.bias.data.clone()

    def get_head_weights(self) -> tuple:
        """Get head weights and bias for model sharing."""
        return self.head.weight.data.clone(), self.head.bias.data.clone()

    def set_fc1_weights(self, weight: torch.Tensor, bias: torch.Tensor):
        """Set fc1 weights (used during merge)."""
        with torch.no_grad():
            self.fc1.weight.data.copy_(weight)
            self.fc1.bias.data.copy_(bias)

    def set_head_weights(self, weight: torch.Tensor, bias: torch.Tensor):
        """Set head weights (used during model loading)."""
        with torch.no_grad():
            self.head.weight.data.copy_(weight)
            self.head.bias.data.copy_(bias)

    def freeze_fc1(self):
        """Freeze fc1 layer for head-only training."""
        for param in self.fc1.parameters():
            param.requires_grad = False

    def unfreeze_fc1(self):
        """Unfreeze fc1 layer for normal training."""
        for param in self.fc1.parameters():
            param.requires_grad = True

    def freeze_head(self):
        """Freeze head layer for fc1-only training."""
        for param in self.head.parameters():
            param.requires_grad = False

    def unfreeze_head(self):
        """Unfreeze head layer for normal/head-only training."""
        for param in self.head.parameters():
            param.requires_grad = True

    # ---- federation protocol ------------------------------------------- #
    # Every model usable by this module implements:
    #   forward(X)                      -> logits
    #   weights_for_sharing()           -> {'key': tensor, ...}   (FEDERATED part; any count)
    #   set_shared_weights(dict)        <- {'key': tensor, ...}
    #   get_head_weights()/set_head_weights(w, b)                 (non-shared trainable tail)
    #   set_shared_frozen(bool) / set_head_frozen(bool)           (for stage freezing)
    # Everything below (send/merge/artifacts/telemetry/plots) is driven purely
    # by this protocol, never by a model's internals.
    def weights_for_sharing(self) -> dict:
        """Federated weights for this model: fc1 weight + bias (protocol)."""
        fc1_w, fc1_b = self.get_fc1_weights()
        return {"fc1_weight": fc1_w, "fc1_bias": fc1_b}

    def set_shared_weights(self, weights: dict):
        """Apply averaged federated weights back (protocol)."""
        self.set_fc1_weights(weights["fc1_weight"], weights["fc1_bias"])

    def set_shared_frozen(self, frozen: bool):
        """Freeze/unfreeze the FEDERATED params for head-only stages."""
        self.freeze_fc1() if frozen else self.unfreeze_fc1()

    def set_head_frozen(self, frozen: bool):
        """Freeze/unfreeze the non-shared tail for fc1-only stages."""
        self.freeze_head() if frozen else self.unfreeze_head()


class SimpleMLP3Layer(nn.Module):
    """Model 1: plain 3-layer perceptron, NO random projection.

        input(18) -> Linear(18->64) -> ReLU -> Linear(64->32) -> ReLU -> head(32->2)

    Federated: BOTH hidden linears (fc1 + fc2, 4 tensors); head stays local
    (fine-tuned around merges). No class weighting, no projection magic —
    deliberately simple (USE_CLASS_WEIGHTING = False).
    """

    USE_CLASS_WEIGHTING = False

    def __init__(self, input_dim: int = 18):
        super().__init__()
        self.fc1 = nn.Linear(input_dim, 64)
        self.fc2 = nn.Linear(64, 32)
        self.head = nn.Linear(32, 2)
        self.relu = nn.ReLU()

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.relu(self.fc1(x))
        x = self.relu(self.fc2(x))
        return self.head(x)

    def weights_for_sharing(self) -> dict:
        return {
            "fc1_weight": self.fc1.weight.data.clone(),
            "fc1_bias": self.fc1.bias.data.clone(),
            "fc2_weight": self.fc2.weight.data.clone(),
            "fc2_bias": self.fc2.bias.data.clone(),
        }

    def set_shared_weights(self, weights: dict):
        with torch.no_grad():
            self.fc1.weight.data.copy_(weights["fc1_weight"])
            self.fc1.bias.data.copy_(weights["fc1_bias"])
            self.fc2.weight.data.copy_(weights["fc2_weight"])
            self.fc2.bias.data.copy_(weights["fc2_bias"])

    def get_head_weights(self) -> tuple:
        return self.head.weight.data.clone(), self.head.bias.data.clone()

    def set_head_weights(self, weight: torch.Tensor, bias: torch.Tensor):
        with torch.no_grad():
            self.head.weight.data.copy_(weight)
            self.head.bias.data.copy_(bias)

    def set_shared_frozen(self, frozen: bool):
        for layer in (self.fc1, self.fc2):
            for param in layer.parameters():
                param.requires_grad = not frozen

    def set_head_frozen(self, frozen: bool):
        for param in self.head.parameters():
            param.requires_grad = not frozen


class RandomProjectionTwoLayerNet(SimpleFederatedNet):
    """Model 3: RP + 2 federated linears + head.

        input(18) -> RP(18->256, frozen, He) -> /sqrt(256) -> Linear(256->64) -> ReLU
        -> Linear(64->32) -> ReLU -> head(32->2)

    Federated: BOTH linears (fc1 256->64 and fc2 64->32); head fine-tuned
    around merges exactly like the base model. Shares the same frozen
    projection as the base class (same seed -> same weights, required for
    peers to agree on the projection). No class weighting.
    """

    USE_CLASS_WEIGHTING = False

    def __init__(
        self,
        input_dim: int,
        rp_path: Optional[str] = None,
        seed: int = 1111,
        hidden1: int = 256,
        hidden2: int = 64,
        mid2: int = 32,
    ):
        super().__init__(
            input_dim,
            hidden1=hidden1,
            hidden2=hidden2,
            rp_path=rp_path,
            seed=seed,
        )
        self.lin2 = nn.Linear(hidden2, mid2)
        self.head = nn.Linear(mid2, 2)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.random_projection(x)
        x = x / self.projection_scale
        x = self.relu(self.fc1(x))
        x = self.relu(self.lin2(x))
        return self.head(x)

    def weights_for_sharing(self) -> dict:
        own = super().weights_for_sharing()
        own["fc2_weight"] = self.lin2.weight.data.clone()
        own["fc2_bias"] = self.lin2.bias.data.clone()
        return own

    def set_shared_weights(self, weights: dict):
        super().set_shared_weights(
            {
                "fc1_weight": weights["fc1_weight"],
                "fc1_bias": weights["fc1_bias"],
            }
        )
        with torch.no_grad():
            self.lin2.weight.data.copy_(weights["fc2_weight"])
            self.lin2.bias.data.copy_(weights["fc2_bias"])

    def set_shared_frozen(self, frozen: bool):
        for layer in (self.fc1, self.lin2):
            for param in layer.parameters():
                param.requires_grad = not frozen


def _build_random_projection_mlp(module):
    """Builder for the default model (registry entry)."""
    module.input_dim = SimpleFederatedNet.FIXED_INPUT_DIM
    return SimpleFederatedNet(
        module.input_dim, rp_path=module.rp_path, seed=module.seed
    )


def _build_simple_mlp(module):
    """Builder for the plain 3-layer perceptron (no random projection)."""
    # getattr(..., default) returns None because module.input_dim EXISTS as
    # None before the first preprocess; mirror the other builders instead.
    module.input_dim = module.input_dim or SimpleFederatedNet.FIXED_INPUT_DIM
    return SimpleMLP3Layer(module.input_dim)


def _build_random_projection_two_layer(module):
    """Builder for the RP + 2 federated linears model."""
    module.input_dim = SimpleFederatedNet.FIXED_INPUT_DIM
    return RandomProjectionTwoLayerNet(
        module.input_dim, rp_path=module.rp_path, seed=module.seed
    )


# Model registry: yaml `federated_network_module.model_class` selects the
# network instance this module trains/merges/serializes. To add your own:
#   1. write your class above (see ExampleNewNet scaffold),
#   2. add a _build_<name> fn and a registry line below,
#   3. set `model_class: <name>` in the peer's slips yaml (baked image).
# Everything else — channels, wall-clock windows, merge policy, dual testing,
# artifacts, telemetry, plots — works unchanged for any protocol-conforming model.
MODEL_REGISTRY = {
    "random_projection_mlp": _build_random_projection_mlp,
    "simple_mlp": _build_simple_mlp,
    "random_projection_two_layer": _build_random_projection_two_layer,
    # "my_new_net": _build_my_new_net,
}


# ----------------------------------------------------------------------
# Merge rules (how the merged model is computed from peer models)
# ----------------------------------------------------------------------
# Pure functions: merge_<name>(own_shared, peer_models, shared_keys) -> dict.
#   own_shared:   {key: tensor}            own model's federated weights
#   peer_models:  {peer_id: {key: tensor}} received federated weights
#   shared_keys:  sorted list of shared tensor keys to merge
# Returns: {key: tensor} — the merged federated weights.
# yaml `federated_network_module.merge_rule` selects the rule (default average).
# Add a rule below and a registry line — nothing else to touch.
def merge_average(
    own_shared: dict, peer_models: dict, shared_keys: list, trust: dict = None
) -> dict:
    """Plain average of own + every peer, per shared key (current behavior)."""
    merged = {}
    for key in shared_keys:
        stack = [own_shared[key]] + [m[key] for m in peer_models.values()]
        merged[key] = torch.stack(stack).mean(dim=0)
    return merged


def merge_blending(
    own_shared: dict, peer_models: dict, shared_keys: list, trust: dict = None
) -> dict:
    """Blending selection: compute the plain mean, then adopt the single model
    (own or a peer's) whose flat shared params are closest to it. One real
    model wins; the rest is left unblended."""

    def _flat(ws):
        return torch.cat([ws[k].detach().reshape(-1) for k in shared_keys])

    candidates = {"own": own_shared}
    candidates.update(peer_models)
    mean = merge_average(own_shared, peer_models, shared_keys)
    mean_flat = _flat(mean)
    best = min(
        candidates,
        key=lambda cid: torch.norm(_flat(candidates[cid]) - mean_flat).item(),
    )
    return {k: candidates[best][k].clone() for k in shared_keys}


def merge_trust_weighted(
    own_shared: dict, peer_models: dict, shared_keys: list, trust: dict = None
) -> dict:
    """Trust-weighted average: peer weights scale with their SLIPS trust
    (score * confidence, clipped to [0,1]; unknown trust = weight 0, own = 1).
    `trust` maps peer_id -> {"score": float, "confidence": float} collected by
    the module from the classic p2p trust db. When every weight is 0 (no
    trust data available yet), falls back to plain averaging."""
    trust = trust or {}
    if not trust:
        # no trust data at all (system warm-up) -> treat everyone equally
        return merge_average(own_shared, peer_models, shared_keys)
    weights = {"own": 1.0}
    for pid in peer_models:
        t = trust.get(pid)
        if not t:
            weights[pid] = 0.0
        else:
            weights[pid] = max(0.0, t.get("score", 0.0)) * max(
                0.0, t.get("confidence", 0.0)
            )
    total = sum(weights.values())
    if total <= 0:
        return merge_average(own_shared, peer_models, shared_keys)
    merged = {}
    for key in shared_keys:
        acc = weights["own"] * own_shared[key]
        for pid, m in peer_models.items():
            acc = acc + weights[pid] * m[key]
        merged[key] = acc / total
    return merged


MERGE_REGISTRY = {
    "average": merge_average,
    "trust_weighted": merge_trust_weighted,
    "blending": merge_blending,
    # "my_rule": merge_my_rule,
}


class ModuleLogger:
    """Centralized logging for training, testing, and label comparison."""

    def __init__(self, output_dir: str, enable: bool):
        self.enable = enable
        self._files = {}
        if enable:
            os.makedirs(output_dir, exist_ok=True)
            filenames = {"trained_labels": "trained_labels.jsonl"}
            for name in [
                "local_train",
                "local_head_train",
                "local_test",
                "merged_train",
                "merged_test",
                "comp_inferred_gt",
                "comp_merged_inferred_gt",
                "comp_test_inferred",
                "comp_test_gt",
                "comp_merged_test_gt",
                "merging_data",
                "training_network",
                "label_flips",
                "trained_labels",
            ]:
                path = os.path.join(
                    output_dir, filenames.get(name, f"{name}.log")
                )
                self._files[name] = open(path, "w")

    def _write(self, name: str, msg: str) -> None:
        if self.enable:
            f = self._files.get(name)
            if f:
                f.write(msg + "\n")
                f.flush()

    def log_train_header(self, target: str, label: str) -> None:
        self._write(target, f"--- {label} ---")

    def log_train_epoch(
        self,
        target: str,
        epoch: int,
        total_epochs: int,
        loss: float,
        acc: float,
    ) -> None:
        self._write(
            target,
            f"  epoch {epoch}/{total_epochs} | loss={loss:.4f} | acc={acc:.4f}",
        )

    def log_train_batch(
        self,
        target: str,
        batch_size: int,
        mal: int,
        ben: int,
        loss: float,
        acc: float,
        tp: int,
        fp: int,
        tn: int,
        fn: int,
    ) -> None:
        self._write(
            target,
            f"  batch {batch_size} (Mal:{mal} Ben:{ben}) | "
            f"loss={loss:.4f} | acc={acc:.4f} | "
            f"TP/FP/TN/FN: {tp}/{fp}/{tn}/{fn}",
        )

    def log_test_flow(
        self,
        target: str,
        total: int,
        seen: dict,
        predicted: dict,
        tp: int,
        fp: int,
        tn: int,
        fn: int,
        acc: float,
    ) -> None:
        self._write(
            target,
            f"  flows={total} | "
            f"Seen(Mal/Ben): {seen.get(MALICIOUS,0)}/{seen.get(BENIGN,0)} | "
            f"Pred(Mal/Ben): {predicted.get(MALICIOUS,0)}/{predicted.get(BENIGN,0)} | "
            f"TP/FP/TN/FN: {tp}/{fp}/{tn}/{fn} | Acc={acc:.4f}",
        )

    def log_test_marker(self, target: str, msg: str) -> None:
        self._write(target, f"--- {msg} ---")

    def log_comp_header(self, target: str, header: str) -> None:
        self._write(target, f"--- {header} ---")

    def log_comp_line(self, target: str, line: str) -> None:
        self._write(target, f"  {line}")

    def log_timeline(self, event: str, details: str = "") -> None:
        """Log a timestamped event to training_network.log."""
        import datetime as _dt

        ts = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        self._write("training_network", f"{ts} | {event} | {details}")

    def close(self) -> None:
        for f in self._files.values():
            f.close()


class FederatedNetworkModule(ml_base.MLBaseDetection):
    """
    Federated network ML detector with model sharing and merging.

    Training triggers:
    1. Window close: flows enter a small ring; alerts (evidence-UID + IP
       touches) are matched against ALL ring cells — so *late* alerts still
       label their window's flows. When a cell is older than
       `label_finalize_delay_windows` (default 2) it is finalized and trained
       exactly once (matched→MALICIOUS, rest→BENIGN). 0 = legacy immediate
       labeling.
    2. Merge event: Aggregate peer models -> Retrain head ONCE on alignment buffer
    """

    name = "federated_network_module"
    description = "Federated network ML detector with model sharing"
    authors = ["Jan Svoboda"]
    module_key = "federated_network_module"
    module_config_section = "federated_network_module"
    malicious_flow_evidence_type = (
        EvidenceType.FEDERATED_NETWORK_MALICIOUS_FLOW
    )
    malicious_flow_description_template = (
        "Flow detected as malicious by federated_network_module. "
        "Src IP {src_ip}:{sport} to {dst_ip}:{dport}"
    )

    def init(self):
        """Initialize module, model, preprocessor, and buffers."""
        super().init()

        # Single-thread all torch backends BEFORE any torch operations.
        # Must be called in init() (before multiprocessing fork) to prevent
        # RuntimeError: "cannot set number of interop threads after parallel work has started"
        # when the forked child calls torch operations.
        import torch as _torch

        _torch.set_num_threads(1)
        _torch.set_num_interop_threads(1)

        # Invalidate stale bytecode cache so every run compiles from source.
        _pycache = os.path.join(os.path.dirname(__file__), "__pycache__")
        if os.path.isdir(_pycache):
            shutil.rmtree(_pycache)

        # Artifact paths - use SLIPS root dir, not relative CWD
        _slips_root = os.path.dirname(os.path.dirname(__file__))
        artifacts_dir = os.path.join(
            _slips_root, "modules", "federated_network_module", "artifacts"
        )
        os.makedirs(artifacts_dir, exist_ok=True)
        self.rp_path = os.path.join(artifacts_dir, "random_projection.bin")
        # Model artifacts are stored as FULL state dicts so any model class
        # in the registry round-trips identically (class-driven persistence).
        self.local_state_path = os.path.join(
            artifacts_dir, "latest_local_state.bin"
        )
        self.local_scaler_path = os.path.join(
            artifacts_dir, "latest_local_scaler.bin"
        )
        self.merged_dir = os.path.join(artifacts_dir, "merged")
        os.makedirs(self.merged_dir, exist_ok=True)

        # Input dimension (determined from first flow)
        self.input_dim: Optional[int] = None

        # Initialize model (in memory)
        self.model = None

        # Preprocessor
        self.scaler = StandardScaler()
        self.is_preprocessor_fitted = False

        # Classifier readiness flag (model + scaler both valid)
        self._is_fitted: bool = False

        # Testing metrics dicts (initialized early to survive shutdown with no flows)
        self.malware_metrics = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
        self.seen_labels = {MALICIOUS: 0, BENIGN: 0}
        self.predicted_labels = {MALICIOUS: 0, BENIGN: 0}

        # Training state
        self.optimizer = None  # manual Adam (fork-safe, no torch.optim)
        self._adam_state: Dict[str, dict] = {}
        self.criterion = nn.CrossEntropyLoss()

        # Buffers
        self.training_buffer_x: list = []
        self.training_buffer_y: list = []
        self._last_train_X: Optional[np.ndarray] = None
        self._last_train_Y: Optional[np.ndarray] = None
        self.alignment_buffer_x: list = []
        self.alignment_buffer_y: list = []

        # Flow tracking
        self.window_flows: dict = {}  # flow_id -> flow_dict
        self._buffered_flow_ids: set = (
            set()
        )  # flows already in training buffer

        # Alerts buffered during a training window (evidence IDs + IPs)
        self.pending_alerts: list = []

        # Peer models storage
        self.peer_models: Dict[str, dict] = (
            {}
        )  # peer_id -> {fc1, head, timestamp}

        # Use hostname as our peer identity (deterministic, available in Docker)
        try:
            import socket

            self.my_peer_id = socket.gethostname()
        except Exception:
            self.my_peer_id = "unknown"
        self.print(f"My peer ID: {self.my_peer_id}", 1, 1)

        # Device
        self.device = torch.device(
            "cuda" if torch.cuda.is_available() else "cpu"
        )

        # Metrics
        self.last_batch_loss: float = 0.0
        self.merge_count: int = 0

        # Training counters
        self.training_count_alert: int = 0
        # Label-flip instrumentation: flows that trained with one label whose
        # final (later-alert) label contradicts it. Not label-vs-GT - our own
        # pipeline's self-contradiction. flow_id -> {label,uid,saddr,daddr};
        # flips are counted once per flow and attributed to the train window.
        self._trained_label_flows: dict = {}
        self._trained_window_of: dict = {}
        self._trained_per_window: dict = {}
        self._flip_events: list = []
        self._flipped_ids: set = set()
        # Labeled-but-not-yet-trained flows. Finalization assigns their final
        # label here; the registry/jsonl write at TRAIN time (window truthful).
        # Carried-over (sub-threshold) batches wait here instead of vanishing.
        self._pending_labeled: dict = {}
        self.training_count_twclose: int = 0
        self.training_count_window: int = 0
        self._training_trigger: str = ""

        # Track whether current model is merged (affects testing log target)
        self._using_merged_model: bool = False

        # Dual-stream testing (L1): the last fully-local-trained model is
        # deep-copied after every full local train, so during the merged
        # phase BOTH models evaluate each incoming flow — merged stream goes
        # to merged_test.log via the legacy path, local stream accumulates in
        # _local_test and lands in local_test.log.
        self._local_only_model = None
        self._local_test: dict = self._blank_test_statistics()
        self._local_stream_used: bool = False

        # Store test-time predictions per flow for comparison against alert labels
        self.test_time_predictions: dict = {}  # flow_id -> predicted_label

        # Centralized logger
        self.logger = ModuleLogger(self.output_dir, self.enable_logs)

        # Read module-specific config using ConfigParser
        conf = ConfigParser()
        section = self.module_config_section

        self.local_training_epochs = conf.ml_module_local_training_epochs(
            section, default=10
        )
        self.merge_finetune_epochs = conf.ml_module_merge_finetune_epochs(
            section, default=5
        )
        self.min_training_samples = conf.read_configuration(
            section, "min_training_samples", 30
        )
        self.min_training_samples = int(self.min_training_samples)

        # Sub-window size for our module (shorter than global Slips TW, default 20 minutes)
        self.window_size_seconds: int = self._read_module_config_int(
            "time_window_width", default=1200
        )

        # Alert-labelling FINALIZATION delay in training windows.
        # Flows sit in a small ring for N windows so *late* alerts can still
        # match them; on exit they are labeled MALICIOUS only if some alert
        # (evidence-UID or attacker/victim IP) connected, else BENIGN — and
        # trained exactly once with their final label. 0 = immediate labeling
        # (legacy behavior). Config key: label_finalize_delay_windows
        self.label_finalize_delay_windows = self._read_module_config_int(
            "label_finalize_delay_windows", default=2
        )
        # Label matching is flow-exact (uid) by design and by methodology:
        # a flow labels malicious only when an alert's evidence cites that
        # flow's uid. Any device-level/IP-based expansion was removed
        # entirely (Oct 1): it would let the model learn "device X is
        # malign" independent of alerts - a self-feeding cascade with no
        # bounded policy (and the module may emit evidence in future).
        self._flow_ring = (
            collections.deque()
        )  # ring cells: {"flows": dict, "mal_ids": set}

        # Deterministic per-instance sub-window offset (0–5 minutes).
        # Uses hostname hash to avoid all peers getting the same offset
        # when containers start simultaneously (same system-time random seed).
        import hashlib

        seed = int(hashlib.md5(self.my_peer_id.encode()).hexdigest(), 16) % (
            2**31
        )
        rng = random.Random(seed)
        self._time_offset: float = rng.uniform(0, 300)
        self.print(
            f"Time window offset (seed={seed}, peer={self.my_peer_id}): "
            f"{self._time_offset:.1f}s (max 300s = 5 min)",
            1,
            0,
        )

        # Wall-clock training window tracking (independent of Slips global windows)
        # First trigger is offset by _time_offset so peers train out of phase.
        self.training_window_start: float = time.time() - self._time_offset

        # Which neural network instance this module runs (registry-selected,
        # config is the source of truth).
        self.model_class_name = str(
            conf.read_configuration(
                section, "model_class", "random_projection_mlp"
            )
        )
        self.print(f"model_class: {self.model_class_name}", 0, 2)

        # Which aggregation rule merges own + peer models into the merged
        # model (registry-selected; what computes the merge, not when).
        self.merge_rule = str(
            conf.read_configuration(section, "merge_rule", "average")
        )
        if self.merge_rule not in MERGE_REGISTRY:
            raise ValueError(
                f"unknown merge_rule '{self.merge_rule}' "
                f"(known: {sorted(MERGE_REGISTRY)})"
            )
        self.print(f"merge_rule: {self.merge_rule}", 0, 2)

        # Load existing local model if present and not training from scratch
        train_from_scratch = self._read_module_config_bool(
            "train_from_scratch", default=False
        )
        if not train_from_scratch:
            self._load_local_model()

    def subscribe_to_channels(self):
        """Subscribe to flows, alerts, and P2P channels."""
        self.c_flows = self.db.subscribe("new_flow")
        self.c_alerts = self.db.subscribe("new_alert")
        self.channels = {
            "new_flow": self.c_flows,
            "new_alert": self.c_alerts,
        }
        # Training uses an independent wall-clock window; Slips tw_closed is ignored.
        self._p2p_connected = False

    def _try_p2p_subscribe(self):
        """Attempt to subscribe to the P2P channel (may not exist at startup).

        Uses the real P2P gopy channel (Go -> Python) for receiving peer
        models, and filters messages to extract only model data.
        """
        if self._p2p_connected:
            return
        # The P2P module creates p2p_gopy (Go->Python) for receiving data
        # and p2p_pygo (Python->Go) for sending. Subscribe to gopy.
        c_p2p = self.db.subscribe("p2p_gopy")
        if c_p2p and c_p2p is not True:
            self.channels["p2p_gopy"] = c_p2p
            self.channel_tracker["p2p_gopy"] = {"msg_received": False}
            self._p2p_connected = True
            self.print(
                "P2P model channel (p2p_gopy) connected, model sharing enabled",
                1,
                1,
            )

    def _read_module_config_int(self, config_key: str, default: int) -> int:
        """Read an integer value from this module's config section."""
        conf = ConfigParser()
        section = self.module_config_section
        value = conf.read_configuration(section, config_key, default)
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def _read_module_config_bool(self, config_key: str, default: bool) -> bool:
        """Read a boolean value from this module's config section."""
        conf = ConfigParser()
        section = self.module_config_section
        value = conf.read_configuration(section, config_key, default)
        return self._to_bool(value, default)

    def _load_local_model(self):
        """Load local model (full state dict) and scaler from artifacts."""
        try:
            if not os.path.exists(self.local_state_path):
                return
            if not os.path.exists(self.local_scaler_path):
                return

            if self.model is None:
                self.model = self.create_empty_model().to(self.device)
                self.optimizer = None  # manual Adam, fork-safe

            state = torch.load(
                self.local_state_path,
                map_location=self.device,
                weights_only=True,
            )
            self.model.load_state_dict(state)

            with open(self.local_scaler_path, "rb") as f:
                loaded_scaler = pickle.load(f)
            # Verify loaded scaler is actually fitted
            if not hasattr(loaded_scaler, "n_features_in_"):
                self.print(
                    "Loaded scaler is not fitted, refitting on first training.",
                    0,
                    1,
                )
            else:
                self.scaler = loaded_scaler
                self.is_preprocessor_fitted = True
                self._is_fitted = True

            self.print("Loaded local model and scaler from artifacts.", 0, 1)
        except Exception:
            self.print(
                f"Could not load local model: {traceback.format_exc()}",
                0,
                1,
            )

    def create_empty_model(self):
        """Instantiate the model class selected by yaml `model_class`
        (registry-driven; protocol objects only)."""
        builder = MODEL_REGISTRY.get(self.model_class_name)
        if builder is None:
            raise ValueError(
                f"unknown model_class '{self.model_class_name}' "
                f"(known: {sorted(MODEL_REGISTRY)})"
            )
        model = builder(self)
        # Class weighting default is model-declared (USE_CLASS_WEIGHTING);
        # yaml `class_weighting` overrides it per experiment (A/B runs).
        model.USE_CLASS_WEIGHTING = self._read_module_config_bool(
            "class_weighting", getattr(model, "USE_CLASS_WEIGHTING", True)
        )
        return model

    def create_empty_preprocessor(self) -> StandardScaler:
        """Create untrained scaler."""
        return StandardScaler()

    def update_preprocessor(self, x_train: pd.DataFrame):
        """Incrementally update scaler using partial_fit.

        Always calls partial_fit for ongoing incremental updates.
        Keeps scaler statistics accumulating with each training batch.
        """
        numeric_data = x_train.select_dtypes(include=[np.number]).fillna(0)
        self.scaler.partial_fit(numeric_data)
        self.is_preprocessor_fitted = True

    def transform_features(self, x_data: pd.DataFrame) -> np.ndarray:
        """Transform features to normalized numpy array."""
        if not self.is_preprocessor_fitted:
            raise RuntimeError(
                "Preprocessor not fitted. Train the model before transforming."
            )
        numeric_data = x_data.select_dtypes(include=[np.number]).fillna(0)
        return self.scaler.transform(numeric_data).astype(np.float32)

    def process_features(self, dataset: pd.DataFrame) -> pd.DataFrame:
        """
        Process Zeek flows into exactly 18 features matching ml_online_model patterns.

        Feature list (fixed order):
        1. dur         - Duration in seconds
        2. proto       - Encoded via _encode_proto (tcp=0, udp=1, icmp=2, icmp-ipv6=3, arp=4)
        3. appproto    - Encoded via _encode_appproto (http=0, dns=1, ssl=2, ...)
        4. sport       - Source port
        5. dport       - Destination port
        6. spkts       - Source packets
        7. dpkts       - Destination packets
        8. sbytes      - Source bytes
        9. dbytes      - Destination bytes
        10. state      - Inferred via _infer_state (established=1.0, failed=0.0)
        11. total_bytes - Derived: sbytes + dbytes
        12. total_pkts  - Derived: spkts + dpkts
        13. avg_pkt_size - Derived: sbytes / max(spkts, 1)
        14. throughput  - Derived: total_bytes / max(dur, 0.001)
        15. history_len - len(history or "")
        16. saddr_num   - IP address to numeric via ipaddress
        17. daddr_num   - IP address to numeric via ipaddress
        18. dir_num     - Direction: 1.0 if "->", else 0.0

        Protocol encoding is INCLUSIVE (no filtering of icmp, arp, icmp-ipv6).

        Returns DataFrame with exactly 18 columns in fixed order.
        """
        if dataset.empty:
            return pd.DataFrame(columns=self._get_feature_order())

        df = dataset.copy()

        # Coerce base numeric fields (matching other ML modules)
        for col in [
            "dur",
            "sport",
            "dport",
            "spkts",
            "dpkts",
            "sbytes",
            "dbytes",
        ]:
            if col not in df.columns:
                df[col] = 0.0
            df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0.0)

        # Encode proto using base class method (inclusive: tcp, udp, icmp, arp all kept)
        if "proto" in df.columns:
            df["proto"] = df["proto"].apply(
                lambda x: self._encode_proto(str(x))
            )

        # Encode appproto using module-specific mapping
        if "appproto" in df.columns:
            df["appproto"] = df["appproto"].apply(
                lambda x: (
                    self._encode_appproto(str(x)) if pd.notna(x) else 10.0
                )
            )

        # Inline appproto if missing
        if "appproto" not in df.columns:
            df["appproto"] = 10.0

        # Infer state using base class method (state, spkts, dpkts -> float)
        if "state" in df.columns:
            df["state"] = df.apply(
                lambda row: self._infer_state(
                    str(row.get("state", "")),
                    row.get("spkts", 0.0),
                    row.get("dpkts", 0.0),
                ),
                axis=1,
            )

        # Convert IPs to numeric using ipaddress
        if "saddr" in df.columns:
            df["saddr_num"] = df["saddr"].apply(
                lambda x: (
                    int(ipaddress.ip_address(str(x))) % 1000000
                    if pd.notna(x)
                    else 0.0
                )
            )
        if "daddr" in df.columns:
            df["daddr_num"] = df["daddr"].apply(
                lambda x: (
                    int(ipaddress.ip_address(str(x))) % 1000000
                    if pd.notna(x)
                    else 0.0
                )
            )

        # Convert direction to numeric
        if "dir_" in df.columns:
            df["dir_num"] = (df["dir_"].astype(str) == "->").astype(float)
        else:
            df["dir_num"] = 0.0

        # Derived features
        df["total_bytes"] = df["sbytes"] + df["dbytes"]
        df["total_pkts"] = df["spkts"] + df["dpkts"]
        df["avg_pkt_size"] = df.apply(
            lambda row: (row["sbytes"] / max(float(row["spkts"]), 1.0)),
            axis=1,
        )
        df["throughput"] = df.apply(
            lambda row: (row["total_bytes"] / max(row["dur"], 0.001)),
            axis=1,
        )
        df["history_len"] = (
            df.get("history", "").astype(str).str.len().fillna(0.0)
        )

        # Select and order features to match FIXED_INPUT_DIM = 18
        feature_order = self._get_feature_order()
        for col in feature_order:
            if col not in df.columns:
                df[col] = 0.0

        result = df[feature_order].fillna(0.0).astype("float64")

        # Validate final dimension
        expected_dim = SimpleFederatedNet.FIXED_INPUT_DIM
        if len(result.columns) != expected_dim:
            self.print(
                f"Warning: process_features produced {len(result.columns)} "
                f"features instead of {expected_dim}. "
                f"Missing: {set(feature_order) - set(result.columns)}",
                0,
                1,
            )

        return result

    def _get_feature_order(self) -> list:
        """
        Return the fixed order of 18 features.

        All Zeek-native: dur, proto, appproto, sport, dport, spkts, dpkts,
        sbytes, dbytes, state, total_bytes, total_pkts, avg_pkt_size,
        throughput, history_len, saddr_num, daddr_num, dir_num
        """
        return [
            "dur",
            "proto",
            "appproto",
            "sport",
            "dport",
            "spkts",
            "dpkts",
            "sbytes",
            "dbytes",
            "state",
            "total_bytes",
            "total_pkts",
            "avg_pkt_size",
            "throughput",
            "history_len",
            "saddr_num",
            "daddr_num",
            "dir_num",
        ]

    def _encode_appproto(self, appproto) -> float:
        """Encode application protocol to numeric value."""
        if not isinstance(appproto, str):
            return 0.0
        appproto = appproto.strip().lower()
        proto_map = {
            "http": 0.0,
            "dns": 1.0,
            "ssl": 2.0,
            "ssh": 3.0,
            "smtp": 4.0,
            "ftp": 5.0,
            "pop3": 6.0,
            "imap": 7.0,
            "telnet": 8.0,
            "https": 9.0,
        }
        return proto_map.get(appproto, 10.0)

    def fit_incremental_model(
        self,
        x_train: np.ndarray,
        y_train: np.ndarray,
        classes: Optional[list] = None,
        train_target: str = "local",
    ):
        """
        Train model on provided batch.

        Note: This implementation uses internal config values for epochs.
        For head-only training, set _freeze_fc1_for_training=True before calling.
        For fc1-only training, set _freeze_head_for_training=True before calling.

        Args:
            x_train: Normalized features
            y_train: Labels (BENIGN/MALICIOUS)
            classes: List of class labels (unused, kept for compatibility)
            train_target: Logger target ("local" for "local_train",
                          "local_head" for "local_head_train",
                          "merged" for "merged_train")
        """
        self.print("fit_incremental_model: entering", 1, 1)

        freeze_fc1 = getattr(self, "_freeze_fc1_for_training", False)
        freeze_head = getattr(self, "_freeze_head_for_training", False)
        epochs = (
            self.merge_finetune_epochs
            if freeze_fc1
            else self.local_training_epochs
        )

        model_state = "new" if self.model is None else "loaded"
        self.print(
            f"fit_incremental_model: model={model_state} device={self.device}",
            1,
            1,
        )

        log_target = f"{train_target}_train"

        if self.model is None:
            self.print("fit_incremental_model: creating model...", 1, 1)
            self.model = self.create_empty_model().to(self.device)
            self.print(
                "fit_incremental_model: model created, creating optimizer...",
                1,
                1,
            )
            self.optimizer = None  # manual Adam, fork-safe
            self.print(
                "fit_incremental_model: using manual Adam (fork-safe)", 1, 1
            )

        if freeze_fc1:
            self.model.set_shared_frozen(True)
            self.model.set_head_frozen(False)
        elif freeze_head:
            self.model.set_shared_frozen(False)
            self.model.set_head_frozen(True)
        else:
            self.model.set_shared_frozen(False)
            self.model.set_head_frozen(False)
        self.optimizer = None  # manual Adam, fork-safe

        self.print(
            f"fit_incremental_model: creating tensors, x_shape={x_train.shape}",
            1,
            1,
        )
        X_tensor = torch.FloatTensor(x_train).to(self.device)
        self.print("fit_incremental_model: X_tensor created", 1, 1)
        y_tensor = torch.LongTensor(
            [0 if y == BENIGN else 1 for y in y_train]
        ).to(self.device)

        # Class weighting is a MODEL-declared training detail (USE_CLASS_WEIGHTING
        # on the net class): the original model weights batches per class; the
        # deliberately-simple models use a plain CrossEntropyLoss.
        mal_count = int((y_tensor == 1).sum().item())
        ben_count = int((y_tensor == 0).sum().item())
        total_count = mal_count + ben_count
        if getattr(self.model, "USE_CLASS_WEIGHTING", True):
            class_weight = torch.tensor(
                [
                    total_count / (2.0 * max(ben_count, 1)),
                    total_count / (2.0 * max(mal_count, 1)),
                ],
                device=self.device,
            )
            criterion = nn.CrossEntropyLoss(weight=class_weight)
        else:
            criterion = nn.CrossEntropyLoss()

        self.model.train()

        # Manual Adam (fork-safe, no torch.optim)
        lr = 0.01
        wd = 1e-4
        beta1 = 0.9
        beta2 = 0.999
        eps = 1e-8

        # Initialize or reuse Adam state
        if not hasattr(self, "_adam_state"):
            self._adam_state = {}
        for name, param in self.model.named_parameters():
            if name not in self._adam_state:
                self._adam_state[name] = {
                    "m": torch.zeros_like(param),
                    "v": torch.zeros_like(param),
                    "step": 0,
                }

        self.print(
            f"fit_incremental_model: starting {epochs} epochs with {len(y_train)} samples",
            1,
            1,
        )

        for epoch in range(epochs):
            outputs = self.model(X_tensor)
            loss = criterion(outputs, y_tensor)
            loss.backward()

            with torch.no_grad():
                for name, param in self.model.named_parameters():
                    if param.grad is None:
                        continue
                    state = self._adam_state[name]
                    state["step"] += 1
                    g = param.grad.clone()

                    # Weight decay (decoupled, as in PyTorch's Adam)
                    param.mul_(1.0 - lr * wd)

                    m = state["m"]
                    v = state["v"]
                    m.mul_(beta1).add_(g, alpha=1.0 - beta1)
                    v.mul_(beta2).addcmul_(g, g, value=1.0 - beta2)

                    m_hat = m / (1.0 - beta1 ** state["step"])
                    v_hat = v / (1.0 - beta2 ** state["step"])

                    param.addcdiv_(m_hat, v_hat.sqrt().add_(eps), value=-lr)

                    param.grad.zero_()

            self.last_batch_loss = loss.item()

            self.print(
                f"fit_incremental_model: epoch {epoch+1}/{epochs} done loss={loss.item():.6f}",
                1,
                1,
            )

            with torch.no_grad():
                epoch_outputs = self.model(X_tensor)
                epoch_preds = torch.argmax(epoch_outputs, dim=1)
                epoch_correct = (epoch_preds == y_tensor).sum().item()
                epoch_acc = epoch_correct / len(y_tensor)
                self.logger.log_train_epoch(
                    log_target, epoch + 1, epochs, loss.item(), epoch_acc
                )

        self.print(
            "fit_incremental_model: training complete, computing final loss",
            1,
            1,
        )

        with torch.no_grad():
            final_outputs = self.model(X_tensor)
            final_preds = torch.argmax(final_outputs, dim=1)
            final_loss = criterion(final_outputs, y_tensor).item()

            tp = int(((final_preds == 1) & (y_tensor == 1)).sum().item())
            fp = int(((final_preds == 1) & (y_tensor == 0)).sum().item())
            tn = int(((final_preds == 0) & (y_tensor == 0)).sum().item())
            fn = int(((final_preds == 0) & (y_tensor == 1)).sum().item())

        mal_count = int((y_tensor == 1).sum().item())
        ben_count = int((y_tensor == 0).sum().item())
        self.logger.log_train_batch(
            log_target,
            len(y_train),
            mal_count,
            ben_count,
            final_loss,
            (tp + tn) / len(y_train) if len(y_train) > 0 else 0.0,
            tp,
            fp,
            tn,
            fn,
        )

        self.print("fit_incremental_model: exiting", 1, 1)

    def predict_batch(self, x_data: np.ndarray) -> np.ndarray:
        """Predict labels for a batch."""
        if self.model is None or not self.is_preprocessor_fitted:
            return np.array([BENIGN] * len(x_data))

        self.model.eval()
        X_tensor = torch.FloatTensor(x_data).to(self.device)

        with torch.no_grad():
            outputs = self.model(X_tensor)
            probs = torch.softmax(outputs, dim=1)
            predictions = torch.argmax(probs, dim=1)

        return np.array(
            [
                MALICIOUS if p == 1 else BENIGN
                for p in predictions.cpu().numpy()
            ]
        )

    def is_preprocessor_initialized(self) -> bool:
        """Check if preprocessor is fitted."""
        return self.is_preprocessor_fitted

    def main(self):
        """Main function - handle flows, alerts, time window, and P2P messages."""
        if self.mode == "train":
            return self._main_training()
        else:
            return self._main_testing()

    def is_msg_version_compatible(self, message: dict) -> bool:
        """Bypass version check - this module handles all messages directly."""
        return True

    def _main_training(self) -> bool:
        """Training main loop: buffer flows, close wall-clock windows, test if model ready."""
        try:
            if msg := self.get_msg("new_flow"):
                data = json.loads(msg["data"])
                flow = data["flow"]
                flow_ts = float(data.get("stime", 0))

                # Buffer flow for the next training window
                self.handle_new_flow(flow, flow_ts)

                # Test with local model (if fitted)
                if self._is_fitted:
                    predicted = self._classify_flow(flow)
                    if predicted is not None:
                        gt_label = self._get_simulated_gt(flow) or BENIGN
                        self.store_testing_results(gt_label, predicted)
                        self.test_time_predictions[self._get_flow_id(flow)] = (
                            predicted
                        )
                        # Second testing stream (L1): while merged, also
                        # evaluate with the frozen last-locally-trained model.
                        if (
                            self._using_merged_model
                            and self._local_only_model is not None
                        ):
                            local_pred = self._predict_with(
                                self._local_only_model, flow
                            )
                            if local_pred is not None:
                                self._store_local_stream(gt_label, local_pred)

            if msg := self.get_msg("new_alert"):
                self.handle_new_alert(json.loads(msg["data"]))

            # Only check P2P channel if it exists (uses p2p_gopy)
            if "p2p_gopy" in self.channels:
                if msg := self.get_msg("p2p_gopy"):
                    try:
                        import base64

                        # Parse outer Go wrapper: {"message_type":"go_data", "message_contents":{"message":"<base64>","reporter":"...","report_time":...}}
                        outer = json.loads(msg["data"])
                        outer_type = outer.get("message_type", "")
                        outer_contents = outer.get("message_contents", {})

                        if outer_type == "go_data":
                            # Model messages: base64 payload inside message_contents.message
                            b64_payload = outer_contents.get("message", "")
                            if b64_payload:
                                decoded = base64.b64decode(
                                    b64_payload
                                ).decode()
                                model_data = json.loads(decoded)
                                inner_type = model_data.get(
                                    "message_type", "?"
                                )
                                self.print(
                                    f"p2p_gopy: received {inner_type} message from {outer_contents.get('reporter','?')}",
                                    1,
                                    1,
                                )
                                if inner_type == "model":
                                    self.handle_p2p_model(model_data)
                        elif outer_type == "peer_update":
                            # Peer updates: ignore (handled by p2p_trust module)
                            pass
                    except Exception:
                        # Ignore non-model/parse-error messages
                        pass
            elif not self._p2p_connected:
                self._try_p2p_subscribe()

            # Wall-clock training window trigger (independent of Slips windows)
            if (
                time.time() - self.training_window_start
                >= self.window_size_seconds
            ):
                self._close_training_window()

            time.sleep(0.1)
            return False
        except Exception:
            self.print(f"Error in main: {traceback.format_exc()}", 0, 1)
            return True

    def _main_testing(self) -> bool:
        """Testing main loop - returns True on error."""
        try:
            if msg := self.get_msg("new_flow"):
                flow = json.loads(msg["data"])
                self.run_test_on_flow(flow)

            if not self._p2p_connected:
                self._try_p2p_subscribe()

            time.sleep(0.1)
            return False
        except Exception:
            self.print(f"Error in main: {traceback.format_exc()}", 0, 1)
            return True

    def _classify_flow(self, flow: dict) -> Optional[str]:
        """Extract features, scale, classify. Returns BENIGN/MALICIOUS or None."""
        if not self._is_fitted:
            return None
        try:
            features = self._extract_flow_features(flow)
            if features is None:
                return None
            X = np.array([features], dtype=np.float32)
            X_scaled = self.scaler.transform(X)
            return self.predict_batch(X_scaled)[0]
        except Exception:
            return None

    def handle_new_flow(self, flow: dict, flow_ts: float = 0.0):
        """Store flow in the current training window.

        Training windows are closed on a wall-clock timer (see _main_training),
        not on flow timestamps, to keep time independent of Slips global windows.
        """
        flow_id = self._get_flow_id(flow)
        self.window_flows[flow_id] = flow

    def handle_new_alert(self, alert: dict):
        """
        Buffer alert evidence for the next wall-clock training window.

        Flows are not labeled or trained immediately. All alerts received
        during a window are aggregated and used to label flows when the
        window closes (see _close_training_window).

        Alert structure:
        - profile: {"ip": "..."}
        - timewindow: {"number": N, ...}
        - last_evidence: {"attacker": {"direction": ..., "ioc_type": ...,
                          "value": "<ip/domain/url>", ...},
                          "victim": {"value": "...", ...} | None, "ID": "..."}
        - correl_id: [list of evidence IDs]
        - id: alert ID

        Note: SLIPS serializes the Evidence dataclasses with the address in
        the field "value" (utils.to_dict = asdict passthrough). "ip" is kept
        as a fallback for hypothetical older payloads; "value" is what this
        SLIPS lineage (>=2023-12) actually emits.
        """
        try:
            self.print("Alert received, buffering evidence", 1, 1)
            self.logger.log_timeline(
                "ALERT", f"alert_{self.training_count_alert}"
            )

            profile_ip = alert.get("profile", {}).get("ip")
            tw_number = alert.get("timewindow", {}).get("number")
            if not profile_ip or not tw_number:
                self.print(
                    "Invalid alert structure: missing profile/twid",
                    0,
                    1,
                )
                return

            correl_id = alert.get("correl_id", [])
            last_evidence = alert.get("last_evidence", {})

            evidence_ids = set()
            if correl_id:
                evidence_ids.update(correl_id)
            if last_evidence.get("ID"):
                evidence_ids.add(last_evidence["ID"])

            if not evidence_ids:
                self.print("No evidence IDs in alert, skipping", 1, 1)
                return

            def _party_ip(party: str) -> Optional[str]:
                """Address of the attacker/victim from last_evidence.

                :param party: "attacker" or "victim"
                :return: the ip/domain string, or None when absent
                """
                node = last_evidence.get(party)
                if isinstance(node, dict):
                    # SLIPS serializes Attacker/Victim with the address in
                    # "value"; "ip" lived only in this module's old docstring
                    return node.get("value") or node.get("ip")
                return node if isinstance(node, str) else None

            attacker_ip = _party_ip("attacker")
            victim_ip = _party_ip("victim")

            # p2p bootstrap self-reports (attacker == own IP) are handled at
            # the SLIPS/admin layer, not by module-side filtering; thread the
            # identity question upward (see p2p-self-alerts.md).
            self.pending_alerts.append(
                {
                    "evidence_ids": list(evidence_ids),
                    "attacker_ip": attacker_ip,
                    "victim_ip": victim_ip,
                }
            )
            self.training_count_alert += 1
            self.print(
                f"Buffered alert {self.training_count_alert} with "
                f"{len(evidence_ids)} evidence IDs",
                1,
                1,
            )

        except Exception:
            self.print(f"Error handling alert: {traceback.format_exc()}", 1, 1)

    def _label_window_flows(self):
        """
        Label flows in the current window using all buffered alerts.

        Returns:
            tuple: (malicious_flows, benign_flows, malicious_flow_ids,
                    alert_count, evidence_count)
        """
        matched_uids: set = set()
        all_evidence_ids: set = set()

        for alert in self.pending_alerts:
            for evid_id in alert.get("evidence_ids", []):
                all_evidence_ids.add(evid_id)
                uids = self.db.get_flows_causing_evidence(evid_id)
                if uids:
                    matched_uids.update(uids)

        malicious_flows = []
        malicious_flow_ids = set()
        # UID-only semantics, same matcher as the ring path (the legacy
        # inline attacker/victim IP branch was removed Oct 2 with the rest
        # of IP-based labeling).
        for flow_id, flow in self.window_flows.items():
            if self._flow_matches(flow, matched_uids, set(), set()):
                malicious_flows.append(flow)
                malicious_flow_ids.add(flow_id)

        benign_flows = [
            flow
            for flow_id, flow in self.window_flows.items()
            if flow_id not in malicious_flow_ids
        ]

        return (
            malicious_flows,
            benign_flows,
            malicious_flow_ids,
            len(self.pending_alerts),
            len(all_evidence_ids),
        )

    def _collect_alert_signatures(self):
        """Aggregate matching material from pending alerts: evidence-connected
        flow UIDs (via SLIPS db) plus attacker/victim IP sets. Same semantics
        as the legacy inline matcher in _label_window_flows."""
        matched_uids: set = set()
        attacker_ips: set = set()
        victim_ips: set = set()
        evidence_ids: set = set()
        for alert in list(self.pending_alerts):
            for evid_id in alert.get("evidence_ids", []):
                evidence_ids.add(evid_id)
                try:
                    uids = self.db.get_flows_causing_evidence(evid_id)
                except Exception:  # noqa: BLE001
                    uids = None
                if uids:
                    matched_uids.update(uids)
            attacker_ip = alert.get("attacker_ip")
            victim_ip = alert.get("victim_ip")
            if attacker_ip:
                attacker_ips.add(attacker_ip)
            if victim_ip:
                victim_ips.add(victim_ip)
        return matched_uids, attacker_ips, victim_ips, len(evidence_ids)

    def _flow_matches(self, flow, matched_uids, attacker_ips, victim_ips):
        """Flow-exact alert matching: the flow's uid must be cited by an
        alert's evidence. attacker_ips/victim_ips are accepted for caller
        compatibility but intentionally unused - device-level labeling was
        deleted Oct 1 as methodologically unsound (self-feeding cascade,
        unbounded IP-keep policy, and IP-total labels only ever agreed
        with GT because GT shared the same attacker identity). The flip
        detector uses this exact rule so labels and contradictions share
        one semantics.
        """
        uid = (flow.get("uid") or "").strip()
        return bool(uid and uid in matched_uids)

    def _label_ring_then_finalize(self):
        """Delay-then-finalize labelling.

        Push this window's flows onto the ring, match alerts against ALL ring
        cells (late arrivals still land), then finalize the oldest cell when
        the ring is longer than the configured delay. Returns the finalized
        lists (may be None when still warming up) plus bookkeeping stats.
        """
        cell = {"flows": dict(self.window_flows), "mal_ids": set()}
        self._flow_ring.append(cell)

        matched_uids, attacker_ips, victim_ips, evidence_count = (
            self._collect_alert_signatures()
        )
        new_hits = 0
        for ring_cell in self._flow_ring:
            for fid, flow in ring_cell["flows"].items():
                if fid in ring_cell["mal_ids"]:
                    continue
                if self._flow_matches(
                    flow, matched_uids, attacker_ips, victim_ips
                ):
                    ring_cell["mal_ids"].add(fid)
                    new_hits += 1

        # flip detection: alerts arriving now may contradict earlier TRAINED
        # labels (flows long gone from the ring). Counted once per flow and
        # attributed to the window the flow was trained in.
        flips_now = self._detect_label_flips(
            matched_uids, attacker_ips, victim_ips
        )

        alert_count = len(self.pending_alerts)
        finalized = None
        if len(self._flow_ring) > self.label_finalize_delay_windows:
            finalized = self._flow_ring.popleft()

        stats = {
            "ring_cells": len(self._flow_ring),
            "new_hits": new_hits,
            "alert_count": alert_count,
            "evidence_count": evidence_count,
            "flips_total": len(self._flip_events),
            "flips_now": flips_now,
        }
        if finalized is None:
            return None, None, None, stats
        malicious_flows = [
            f
            for fid, f in finalized["flows"].items()
            if fid in finalized["mal_ids"]
        ]
        benign_flows = [
            f
            for fid, f in finalized["flows"].items()
            if fid not in finalized["mal_ids"]
        ]
        stats["finalized_mal"] = len(malicious_flows)
        stats["finalized_ben"] = len(benign_flows)
        return malicious_flows, benign_flows, finalized["mal_ids"], stats

    def _record_pending_labels(
        self, malicious_flows: list, benign_flows: list
    ) -> None:
        """Snapshot finalize-time labels into the pending pool.

        Pendings wait until a training batch actually fires; sub-threshold
        batches therefore stay visible to flips instead of vanishing.
        """
        for lbl, group in ((1, malicious_flows), (0, benign_flows)):
            for flow in group:
                fid = self._get_flow_id(flow)
                if (
                    fid in self._pending_labeled
                    or fid in self._trained_label_flows
                ):
                    continue
                self._pending_labeled[fid] = {
                    "label": lbl,
                    "uid": (flow.get("uid") or "").strip(),
                    "saddr": str(flow.get("saddr", "")),
                    "daddr": str(flow.get("daddr", "")),
                    "starttime": str(flow.get("starttime", "")),
                }

    def _commit_training_labels(self, window_n: int) -> None:
        """Commit pending labels into the trained registry + JSONL audit.

        Called exactly when a training batch fires, so every flow gets its
        TRUE train window (carried batches may have waited several windows).
        One JSONL line per flow goes to trained_labels.jsonl for offline
        cross-checks against the saved alert stream.

        :param window_n: training window index of the firing batch
        """
        import json as _json

        for fid, rec in self._pending_labeled.items():
            if fid in self._trained_label_flows:
                continue
            self._trained_label_flows[fid] = rec
            self._trained_window_of[fid] = window_n
        self._trained_per_window[window_n] = self._trained_per_window.get(
            window_n, 0
        ) + len(self._pending_labeled)
        for fid, rec in self._pending_labeled.items():
            self.logger._write(
                "trained_labels",
                _json.dumps(
                    {
                        "flow_id": fid,
                        "uid": rec["uid"],
                        "saddr": rec["saddr"],
                        "daddr": rec["daddr"],
                        "starttime": rec["starttime"],
                        "label": rec["label"],
                        "train_window": window_n,
                    }
                ),
            )
        self._pending_labeled.clear()

    def _detect_label_flips(
        self, matched_uids: set, attacker_ips: set, victim_ips: set
    ) -> int:
        """Count earlier-trained benign flows this alert wave would flip.

        A flip = a flow trained BENIGN whose stored addresses/uid match the
        current alert signatures (evidence-uids or attacker/victim IP sets).
        Each flow flips at most once.

        :param matched_uids: flow uids resolvable from buffered alerts
        :param attacker_ips: attacker party IPs of buffered alerts
        :param victim_ips: victim party IPs of buffered alerts
        :return: number of new flips recorded this call
        """
        if not (matched_uids or attacker_ips or victim_ips):
            return 0
        new_flips = 0
        for fid, rec in self._trained_label_flows.items():
            if rec["label"] != 0 or fid in self._flipped_ids:
                continue
            if self._flow_matches(rec, matched_uids, attacker_ips, victim_ips):
                self._flipped_ids.add(fid)
                self._flip_events.append(
                    {
                        "flow_id": fid,
                        "trained_window": self._trained_window_of.get(fid),
                        "flip_window": self.training_count_window,
                    }
                )
                new_flips += 1
        return new_flips

    def _write_label_flips(self, trigger: str) -> None:
        """Append a cumulative flip snapshot to label_flips.log.

        :param trigger: emitter context ("finalize" / "shutdown")
        """
        trained_total = len(self._trained_label_flows)
        flips_total = len(self._flip_events)
        pct = 100.0 * flips_total / trained_total if trained_total else 0.0
        self.logger.log_comp_header(
            "label_flips",
            f"{trigger} @window_{self.training_count_window} | "
            f"flips: {flips_total} / {trained_total} ({pct:.2f}%)",
        )
        per_window_flip = {}
        for ev in self._flip_events:
            w = ev["trained_window"]
            per_window_flip[w] = per_window_flip.get(w, 0) + 1
        for w in sorted(self._trained_per_window):
            t = self._trained_per_window[w]
            f = per_window_flip.get(w, 0)
            self.logger.log_comp_header(
                "label_flips",
                f"window_{w} | trained {t} | flipped {f} | "
                f"pct {100.0 * f / t if t else 0.0:.2f}",
            )

    def _add_flows_to_buffers(self, flows: list, label: str):
        """
        Add flows to training and alignment buffers if not already present.

        Args:
            flows: List of flow dictionaries to add.
            label: BENIGN or MALICIOUS label to assign.
        """
        for flow in flows:
            fid = self._get_flow_id(flow)
            if fid in self._buffered_flow_ids:
                continue
            x, _ = self._process_flow(flow, label)
            if x is not None:
                self.training_buffer_x.append(x)
                self.training_buffer_y.append(label)
                self.alignment_buffer_x.append(x)
                self.alignment_buffer_y.append(label)
                self._buffered_flow_ids.add(fid)

    def _log_window_comparisons(
        self,
        malicious_flows: list,
        benign_flows: list,
        malicious_flow_ids: set,
        window_header: str,
    ):
        """
        Log inferred-vs-GT and prediction-vs-label comparisons for the window.

        Args:
            malicious_flows: Flows labeled MALICIOUS.
            benign_flows: Flows labeled BENIGN.
            malicious_flow_ids: Set of flow IDs labeled MALICIOUS.
            window_header: Header string for comparison logs.
        """
        self.logger.log_comp_header("comp_inferred_gt", window_header)
        self.logger.log_comp_header("comp_test_inferred", window_header)
        self.logger.log_comp_header("comp_test_gt", window_header)

        # Inferred labels must be keyed BY FLOW, not by training_buffer
        # position: training_buffer_y may start with leftovers from
        # sub-threshold windows (min_training_samples carry-over), which
        # shifts every comparison by that many entries and fabricates
        # FN/TN artifacts. The finalized lists already carry the label.
        all_flows = malicious_flows + benign_flows
        inferred_of = [MALICIOUS] * len(malicious_flows) + [BENIGN] * len(
            benign_flows
        )

        # inferred vs GT
        gt_labels = []
        inferred_labels = []
        for flow, inferred in zip(all_flows, inferred_of):
            gt_norm = self._get_simulated_gt(flow)
            if gt_norm is None:
                continue
            inferred_labels.append(inferred)
            gt_labels.append(gt_norm)

        if len(gt_labels) > 0:
            inf_arr = np.array(inferred_labels)
            gt_arr = np.array(gt_labels)
            mal_inf = int(np.sum(inf_arr == MALICIOUS))
            ben_inf = int(np.sum(inf_arr == BENIGN))
            mal_gt = int(np.sum(gt_arr == MALICIOUS))
            ben_gt = int(np.sum(gt_arr == BENIGN))
            tp = int(np.sum((inf_arr == MALICIOUS) & (gt_arr == MALICIOUS)))
            fp = int(np.sum((inf_arr == MALICIOUS) & (gt_arr == BENIGN)))
            tn = int(np.sum((inf_arr == BENIGN) & (gt_arr == BENIGN)))
            fn = int(np.sum((inf_arr == BENIGN) & (gt_arr == MALICIOUS)))
            acc = (tp + tn) / len(gt_labels) if len(gt_labels) > 0 else 0.0
            self.logger.log_comp_line(
                "comp_inferred_gt",
                f"inferred vs GT: {len(gt_labels)} samples | "
                f"Mal/Ben: {mal_inf}/{ben_inf} vs {mal_gt}/{ben_gt} | "
                f"TP/FP/TN/FN: {tp}/{fp}/{tn}/{fn} | Acc: {acc:.4f}",
            )
            if self._using_merged_model:
                self.logger.log_comp_line(
                    "comp_merged_inferred_gt",
                    f"inferred vs GT: {len(gt_labels)} samples | "
                    f"Mal/Ben: {mal_inf}/{ben_inf} vs {mal_gt}/{ben_gt} | "
                    f"TP/FP/TN/FN: {tp}/{fp}/{tn}/{fn} | Acc: {acc:.4f}",
                )

        # pred vs inferred and pred vs GT
        pred_data = []
        for flow in all_flows:
            fid = self._get_flow_id(flow)
            pred = self.test_time_predictions.pop(fid, None)
            if pred is not None:
                inferred = MALICIOUS if fid in malicious_flow_ids else BENIGN
                gt_norm = self._get_simulated_gt(flow)
                pred_data.append((pred, inferred, gt_norm))

        if len(pred_data) > 0:
            pred_labels = [p for p, _, _ in pred_data]
            pred_inferred_labels = [i for _, i, _ in pred_data]

            pred_arr = np.array(pred_labels)
            pinf_arr = np.array(pred_inferred_labels)
            mal_pred = int(np.sum(pred_arr == MALICIOUS))
            ben_pred = int(np.sum(pred_arr == BENIGN))
            mal_pinf = int(np.sum(pinf_arr == MALICIOUS))
            ben_pinf = int(np.sum(pinf_arr == BENIGN))
            tp = int(np.sum((pred_arr == MALICIOUS) & (pinf_arr == MALICIOUS)))
            fp = int(np.sum((pred_arr == MALICIOUS) & (pinf_arr == BENIGN)))
            tn = int(np.sum((pred_arr == BENIGN) & (pinf_arr == BENIGN)))
            fn = int(np.sum((pred_arr == BENIGN) & (pinf_arr == MALICIOUS)))
            acc = (tp + tn) / len(pred_labels) if len(pred_labels) > 0 else 0.0
            self.logger.log_comp_line(
                "comp_test_inferred",
                f"pred vs inferred: {len(pred_labels)} samples | "
                f"Mal/Ben: {mal_pred}/{ben_pred} vs {mal_pinf}/{ben_pinf} | "
                f"TP/FP/TN/FN: {tp}/{fp}/{tn}/{fn} | Acc: {acc:.4f}",
            )

            pvg_pairs = [(p, g) for p, _, g in pred_data if g is not None]
            if len(pvg_pairs) > 0:
                pvg_preds = [p for p, _ in pvg_pairs]
                pvg_gts = [g for _, g in pvg_pairs]
                pvg_arr = np.array(pvg_preds)
                gt_arr2 = np.array(pvg_gts)
                mal_pvg = int(np.sum(pvg_arr == MALICIOUS))
                ben_pvg = int(np.sum(pvg_arr == BENIGN))
                mal_gt2 = int(np.sum(gt_arr2 == MALICIOUS))
                ben_gt2 = int(np.sum(gt_arr2 == BENIGN))
                tp = int(
                    np.sum((pvg_arr == MALICIOUS) & (gt_arr2 == MALICIOUS))
                )
                fp = int(np.sum((pvg_arr == MALICIOUS) & (gt_arr2 == BENIGN)))
                tn = int(np.sum((pvg_arr == BENIGN) & (gt_arr2 == BENIGN)))
                fn = int(np.sum((pvg_arr == BENIGN) & (gt_arr2 == MALICIOUS)))
                acc = (tp + tn) / len(pvg_preds) if len(pvg_preds) > 0 else 0.0
                self.logger.log_comp_line(
                    "comp_test_gt",
                    f"pred vs GT: {len(pvg_preds)} samples | "
                    f"Mal/Ben: {mal_pvg}/{ben_pvg} vs {mal_gt2}/{ben_gt2} | "
                    f"TP/FP/TN/FN: {tp}/{fp}/{tn}/{fn} | Acc: {acc:.4f}",
                )
                if self._using_merged_model:
                    self.logger.log_comp_line(
                        "comp_merged_test_gt",
                        f"pred vs GT: {len(pvg_preds)} samples | "
                        f"Mal/Ben: {mal_pvg}/{ben_pvg} vs {mal_gt2}/{ben_gt2} | "
                        f"TP/FP/TN/FN: {tp}/{fp}/{tn}/{fn} | Acc: {acc:.4f}",
                    )

    def _close_training_window(self):
        """
        Close the current wall-clock training window.

        Labels flows using all buffered alerts, adds them to the training
        buffer, logs comparisons, and trains if min_training_samples is met.
        """
        try:
            self.training_count_window += 1
            window_n = self.training_count_window
            self.print(
                f"Training window {window_n} closed, preparing batch", 1, 1
            )

            ring_stats = None
            if self.label_finalize_delay_windows > 0:
                (
                    malicious_flows,
                    benign_flows,
                    malicious_flow_ids,
                    ring_stats,
                ) = self._label_ring_then_finalize()
                alert_count = ring_stats["alert_count"]
                evidence_count = ring_stats["evidence_count"]
                if malicious_flows is None:
                    # ring warming up; finalize nothing this window
                    self.print(
                        f"Window {window_n}: ring warm-up "
                        f"({ring_stats['ring_cells']}/{self.label_finalize_delay_windows} cells), "
                        f"no finalized batch; {alert_count} alerts"
                        f" -> {ring_stats['new_hits']} ring matches",
                        1,
                        1,
                    )
                    self.window_flows.clear()
                    self.pending_alerts.clear()
                    self.test_time_predictions.clear()
                    self.training_window_start += self.window_size_seconds
                    return
            else:
                (
                    malicious_flows,
                    benign_flows,
                    malicious_flow_ids,
                    alert_count,
                    evidence_count,
                ) = self._label_window_flows()

            self.print(
                f"Window {window_n}: {len(malicious_flows)} malicious, "
                f"{len(benign_flows)} benign flows from {alert_count} alerts",
                0,
                1,
            )

            total_labeled = len(malicious_flows) + len(benign_flows)
            if total_labeled == 0:
                self.print(f"No flows in window {window_n}, skipping", 0, 1)
                self.window_flows.clear()
                self.pending_alerts.clear()
                self.test_time_predictions.clear()
                self.training_window_start += self.window_size_seconds
                return

            self._add_flows_to_buffers(malicious_flows, MALICIOUS)
            self._add_flows_to_buffers(benign_flows, BENIGN)

            connected_count = len(malicious_flows)
            total_batch = total_labeled
            header = (
                f"window_{window_n} | "
                f"{alert_count} alerts, {evidence_count} evidence. "
                f"{connected_count} malicious connected to evidence, "
                f"{len(benign_flows)} benign, "
                f"{total_batch} total"
            )
            self._log_window_comparisons(
                malicious_flows, benign_flows, malicious_flow_ids, header
            )
            if ring_stats:
                # approved audit marker: finalization lag is visible directly
                # in local_train.log next to the batch lines
                self.logger.log_comp_header(
                    "local_train",
                    f"ring | pending {ring_stats['ring_cells']} cells | "
                    f"finalized mal {ring_stats['finalized_mal']} ben "
                    f"{ring_stats['finalized_ben']} | "
                    f"ring matches {ring_stats['new_hits']} | alerts "
                    f"{ring_stats['alert_count']} | "
                    f"flips {ring_stats['flips_total']}",
                )

            self._record_pending_labels(malicious_flows, benign_flows)
            # Central flip detection (immediate K=0 path too): this close's
            # alerts are matched against earlier-TRAINED flows. The ring
            # path also detects inside _label_ring_then_finalize; set-dedup
            # (_flipped_ids) keeps re-execution idempotent.
            _sign = self._collect_alert_signatures()
            self._detect_label_flips(_sign[0], _sign[1], _sign[2])
            self._training_trigger = "window"
            if len(self.training_buffer_x) >= self.min_training_samples:
                # flips/jsonl audit only for flows that actually trained
                self._commit_training_labels(window_n)
                self._write_label_flips("finalize")
                self._train_batch()

                self.malware_metrics = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
                self.seen_labels = {MALICIOUS: 0, BENIGN: 0}
                self.predicted_labels = {MALICIOUS: 0, BENIGN: 0}

                target = (
                    "merged_test" if self._using_merged_model else "local_test"
                )
                self.logger.log_test_marker(
                    target,
                    f"New local model ({self._training_trigger}_{window_n})",
                )

                # Dual testing stream closeout: flush the local-only stream's
                # window tail, mark its new model version, reset its counters
                # (mirrors the legacy active-stream bookkeeping above).
                if self._local_stream_used:
                    self._flush_local_stream()
                    self.logger.log_test_marker(
                        "local_test",
                        f"New local model ({self._training_trigger}_{window_n})",
                    )
                    self._local_test = self._blank_test_statistics()
                    self._local_stream_used = False

            self.window_flows.clear()
            self.pending_alerts.clear()
            self.test_time_predictions.clear()
            self.training_window_start += self.window_size_seconds

            if (
                self.testing_flows_since_last_log > 0
                and self._using_merged_model
            ):
                self.flush_testing_results()

        except Exception:
            self.print(
                f"Error closing training window: {traceback.format_exc()}",
                0,
                1,
            )

    def handle_p2p_model(self, model_data: dict):
        """
        Store received model from peer.

        Args:
            model_data: Dict with peer_id and model weights
        """
        try:
            peer_id = model_data.get("peer_id")
            self.print(f"handle_p2p_model: entering, peer={peer_id}", 1, 1)
            if not peer_id:
                return

            if (
                model_data.get("model_class")
                and model_data["model_class"] != self.model_class_name
            ):
                self.print(
                    f"WARNING: peer {peer_id} runs model_class "
                    f"'{model_data['model_class']}', we run '{self.model_class_name}'",
                    0,
                    1,
                )

            shared_in = model_data.get("shared") or {}
            self.peer_models[peer_id] = {
                k: torch.tensor(v) for k, v in shared_in.items()
            }
            self.peer_models[peer_id]["timestamp"] = model_data.get(
                "timestamp", time.time()
            )

            self.print(
                f"Received model from peer {peer_id}, stashed ({len(self.peer_models)} total)",
                1,
                1,
            )
            # Merge ONLY after own local training (triggered in _train_batch)
            self.print("handle_p2p_model: exiting", 1, 1)

        except Exception:
            self.print(
                f"Error handling P2P model: {traceback.format_exc()}", 0, 1
            )

    def _reset_head_adam_state(self):
        """Reset Adam state for head parameters before head-only fine-tuning."""
        for name, state in self._adam_state.items():
            if "head" in name:
                state["m"].zero_()
                state["v"].zero_()
                state["step"] = 0

    def _train_batch(self):
        """Train on accumulated training buffer: local fc1+head, local head, merge head."""
        try:
            self.print("_train_batch: entering", 1, 1)
            if len(self.training_buffer_x) == 0:
                return

            self.print(
                f"_train_batch: buffer has {len(self.training_buffer_x)} samples",
                1,
                1,
            )

            X = np.array(self.training_buffer_x)
            y = np.array(self.training_buffer_y)
            epochs = self.local_training_epochs

            mal_count = int(np.sum(y == MALICIOUS))
            ben_count = int(np.sum(y == BENIGN))

            counter = self.training_count_window

            self.logger.log_timeline(
                "TRAIN_START",
                f"{self._training_trigger}_{counter} buffer={len(X)} mal={mal_count} ben={ben_count} epochs={epochs}",
            )

            self.logger.log_train_header(
                "local_train",
                f"{self._training_trigger}_{counter} | {mal_count} mal, {ben_count} ben",
            )

            self.update_preprocessor(pd.DataFrame(X))
            X_scaled = self.scaler.transform(X)

            # Save scaled batch for both local and merge head fine-tuning
            self._last_train_X = X_scaled.copy()
            self._last_train_Y = y.copy()

            self.print(
                f"[TIMELINE] TRAIN {self._training_trigger}_{counter}: "
                f"{epochs} epochs, {len(y)} samples ({mal_count} mal, {ben_count} ben)",
                1,
                1,
            )

            # Phase 1: local full training (fc1 + head together)
            self.fit_incremental_model(X_scaled, y, train_target="local")
            self.logger.log_timeline(
                "TRAIN_DONE",
                f"{self._training_trigger}_{counter} samples={len(y)}",
            )

            # Capture the head produced by local training; merge will start from here too
            head_before_w, head_before_b = self.model.get_head_weights()

            # Phase 2: local head fine-tuning (fc1 frozen)
            self.logger.log_train_header(
                "local_head_train",
                f"{self._training_trigger}_{counter} | {mal_count} mal, {ben_count} ben",
            )
            self._reset_head_adam_state()
            self._freeze_fc1_for_training = True
            self.fit_incremental_model(
                self._last_train_X,
                self._last_train_Y,
                train_target="local_head",
            )
            self._freeze_fc1_for_training = False

            self._save_local_model()

            # Snapshot the fresh local-only model for the dual testing stream
            # (small model; deep copy keeps it frozen while self.model merges).
            try:
                self._local_only_model = copy.deepcopy(self.model)
            except Exception:
                self.print(
                    "local-only model snapshot failed: "
                    + traceback.format_exc(),
                    0,
                    1,
                )

            self._using_merged_model = False
            self._is_fitted = True
            self.print("[DEBUG] _train_batch done, about to send model", 1, 1)

            self.print("_train_batch: calling send_model_to_peers", 1, 1)
            self.send_model_to_peers()
            self.print("_train_batch: send_model_to_peers returned", 1, 1)

            # After own training, try merge if we have pending peer models.
            # Merge averages fc1, then fine-tunes the SAME pre-local head
            # (before the 5-epoch local head tuning) under identical conditions.
            if len(self.peer_models) >= 1:
                self.print(
                    "_train_batch: pending peer models, triggering merge", 1, 1
                )
                self.trigger_merge(head_before_w, head_before_b)

            self.training_buffer_x.clear()
            self.training_buffer_y.clear()
            self._buffered_flow_ids.clear()

            self.print("_train_batch: exiting", 1, 1)

        except Exception:
            self.print(
                f"Error in _train_batch: {traceback.format_exc()}", 1, 1
            )

    _TRUST_CACHE_TTL_S = 60

    def _resolve_peer_ip(self, peer_id: str) -> Optional[str]:
        """Best-effort hostname -> topology IP via docker DNS (cached)."""
        cache = getattr(self, "_peer_ip_cache", None) or {}
        if peer_id in cache:
            return cache[peer_id]
        ip = None
        try:
            import socket

            ip = socket.gethostbyname(peer_id)
        except Exception:
            pass
        cache[peer_id] = ip
        self._peer_ip_cache = cache
        return ip

    def _collect_peer_trust(self, peer_ids) -> dict:
        """SLIPS classic p2p trust for merge functions, read-only, cached 60s.

        Returns {peer_id: {"score", "confidence", "network_score", "ip"}} with
        peers missing a trust entry omitted. The trust sqlite lives inside the
        p2p trust module's permanent dir (visible to this module's container);
        we open it read-only (mode=ro) so we never disturb the writer.
        """
        if (
            time.time() - getattr(self, "_trust_cache_ts", 0)
            < self._TRUST_CACHE_TTL_S
        ):
            cached = getattr(self, "_trust_cache_map", None) or {}
            return {p: cached.get(p) for p in peer_ids if cached.get(p)}
        out = {}
        try:
            path = self.db.get_p2p_trust_db_path()
        except Exception:
            path = getattr(self.db, "trust_db_path", None)
        if path and os.path.exists(path):
            try:
                import sqlite3

                conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
                cur = conn.cursor()
                for pid in set(peer_ids):
                    ip = self._resolve_peer_ip(pid)
                    for key in (("ip", ip), ("ip", pid)):
                        if not key[1]:
                            continue
                        cur.execute(
                            "SELECT score, confidence, network_score, update_time "
                            "FROM opinion_cache WHERE key_type=? AND reported_key=? "
                            "ORDER BY update_time DESC LIMIT 1",
                            key,
                        )
                        row = cur.fetchone()
                        if row:
                            out[pid] = {
                                "score": row[0],
                                "confidence": row[1],
                                "network_score": row[2],
                                "ts": row[3],
                                "ip": ip,
                            }
                            break
                conn.close()
            except Exception as exc:  # noqa: BLE001
                self.print(
                    f"trust db read failed (keeping empty map): {exc}", 0, 1
                )
        self._trust_cache_ts = time.time()
        self._trust_cache_map = out
        return out

    def trigger_merge(
        self,
        head_before_w: Optional[torch.Tensor] = None,
        head_before_b: Optional[torch.Tensor] = None,
    ):
        """
        Merge all peer models + own latest, retrain head, save merged model.

        Averages fc1 across peers + own model, then fine-tunes the head
        starting from the head produced by local full training (before any
        head-only fine-tuning). This makes local and merged models differ
        only in the origin of fc1.

        Args:
            head_before_w: Head weight tensor from after local full training.
            head_before_b: Head bias tensor from after local full training.
        """
        try:
            self.print("trigger_merge: entering", 1, 1)
            self.logger.log_timeline(
                "MERGE_START",
                f"merge_{self.merge_count + 1} peers={len(self.peer_models)} ("
                + ",".join(self.peer_models.keys())
                + ")",
            )
            if len(self.peer_models) < 1:
                self.print(
                    f"trigger_merge: {len(self.peer_models)} peer models available",
                    1,
                    1,
                )
                return

            self.print(
                f"Merging {len(self.peer_models)} peer models + own model",
                1,
                1,
            )

            self.logger.log_train_header(
                "merged_train",
                f"merge_{self.merge_count + 1} | {len(self.peer_models)} peers: {','.join(self.peer_models.keys())} + own",
            )

            # Protocol-driven merge: average every shared tensor across own +
            # peers; distances/dumps use the flat concatenation of the shared
            # parameters (key order fixed) — works for ANY model class.
            own_shared = self.model.weights_for_sharing() if self.model else {}
            shared_keys = sorted(own_shared)
            usable = {
                pid: m
                for pid, m in self.peer_models.items()
                if all(isinstance(m.get(k), torch.Tensor) for k in shared_keys)
            }
            skipped = [pid for pid in self.peer_models if pid not in usable]
            if skipped:
                self.print(
                    f"trigger_merge: skipping incompatible peer payload(s): {skipped}",
                    0,
                    1,
                )

            def _flat_all(ws):
                return torch.cat(
                    [ws[k].detach().reshape(-1) for k in shared_keys]
                )

            # Trust visibility: merge functions receive the SLIPS trust map
            # (collected only when the selected rule consumes it).
            trust_map = {}
            if self.merge_rule == "trust_weighted":
                trust_map = self._collect_peer_trust(list(usable))
                if not trust_map:
                    self.print(
                        "merge_rule=trust_weighted: no trust data available; "
                        "falling back to equal weights",
                        0,
                        1,
                    )

            merged_shared = MERGE_REGISTRY[self.merge_rule](
                own_shared, usable, shared_keys, trust_map
            )
            self.print(
                f"trigger_merge: applied merge_rule={self.merge_rule} "
                f"over {len(usable)} peers + own",
                1,
                1,
            )

            numel = sum(t.numel() for t in merged_shared.values())

            # Log peer weight distances for analysis
            if self.model and shared_keys:
                own_flat = _flat_all(own_shared)
                merged_flat = _flat_all(merged_shared)
                merge_label = f"merge_{self.merge_count + 1}"
                self.logger._write(
                    "merging_data",
                    f"--- {merge_label} | {len(usable)} peers ---",
                )
                self.logger._write(
                    "merging_data", f"  merge_rule={self.merge_rule}"
                )
                for peer_id, m in usable.items():
                    l2_norm = torch.norm(_flat_all(m) - own_flat).item()
                    l2_normalized = l2_norm / (numel**0.5)
                    trust_note = ""
                    t = trust_map.get(peer_id)
                    if t:
                        trust_note = f" | trust={t.get('score', 0.0) * t.get('confidence', 0.0):.4f}"
                    self.logger._write(
                        "merging_data",
                        f"  peer={peer_id} | L2_dist={l2_norm:.6f} | L2_norm={l2_normalized:.6f} | n_params={numel}{trust_note}",
                    )
                merged_l2 = torch.norm(merged_flat - own_flat).item()
                merged_l2_norm = merged_l2 / (numel**0.5)
                merged_differs = merged_l2 > 1e-8
                self.logger._write(
                    "merging_data",
                    f"  merged_vs_own | L2_dist={merged_l2:.6f} | L2_norm={merged_l2_norm:.6f} | differs={merged_differs}",
                )
                # Persist flat shared-param vectors per merge for offline analysis.
                # Norms/cosine/PCA are computed downstream (UI); the module
                # only serializes what it already holds in memory here.
                try:
                    vec_dir = os.path.join(self.output_dir, "weights")
                    os.makedirs(vec_dir, exist_ok=True)

                    def _flat_np(ws) -> np.ndarray:
                        return _flat_all(ws).cpu().numpy().astype(np.float32)

                    vecs = {
                        "own": _flat_np(own_shared),
                        "merged": _flat_np(merged_shared),
                    }
                    for peer_id, m in usable.items():
                        tag = "".join(
                            ch if ch.isalnum() or ch in "-_" else "_"
                            for ch in str(peer_id)
                        )
                        vecs[f"peer_{tag}"] = _flat_np(m)
                    np.savez_compressed(
                        os.path.join(
                            vec_dir, f"merge_{self.merge_count + 1:04d}.npz"
                        ),
                        **vecs,
                    )
                except Exception:
                    self.print(
                        "trigger_merge: weight snapshot failed: "
                        + traceback.format_exc(),
                        0,
                        1,
                    )
            self.print(
                f"trigger_merge: merging {len(usable)} peers over {numel} shared params",
                1,
                1,
            )

            if self.model:
                self.model.set_shared_weights(merged_shared)

            # Start merge head fine-tuning from the same head used for local
            # head fine-tuning, so local and merged differ only in fc1 origin.
            if head_before_w is not None and head_before_b is not None:
                self.model.set_head_weights(head_before_w, head_before_b)
                self._reset_head_adam_state()

            self.print("trigger_merge: calling _align_head_on_buffer", 1, 1)
            self._align_head_on_buffer(self._last_train_X, self._last_train_Y)

            self._using_merged_model = True

            self.merge_count += 1
            self._save_merged_model(self.merge_count)
            self._save_final_merged_model()

            self.print(
                f"trigger_merge: exiting, merged_{self.merge_count} saved",
                1,
                1,
            )

        except Exception:
            self.print(
                f"Error in trigger_merge: {traceback.format_exc()}", 0, 1
            )

    def _align_head_on_buffer(self, X: np.ndarray, y: np.ndarray):
        """
        Freeze fc1, train head ONLY on the provided batch with configured epochs.
        """
        try:
            if len(X) == 0:
                self.print(
                    "Alignment buffer empty, skipping head alignment", 1, 1
                )
                return

            self.update_preprocessor(pd.DataFrame(X))
            X_scaled = self.scaler.transform(X)

            # Get epochs from instance variable (set in init)
            epochs = self.merge_finetune_epochs

            # Train head ONLY (fc1 frozen) for specified epochs
            self.print(
                f"Fine-tuning head for {epochs} epochs on {len(y)} samples",
                1,
                1,
            )
            # For head alignment, we need to train with frozen fc1
            # Override by temporarily setting a flag
            self._freeze_fc1_for_training = True
            self.fit_incremental_model(X_scaled, y, train_target="merged")
            self._freeze_fc1_for_training = False

            self.print(
                f"Head aligned ({self.merge_finetune_epochs} epochs) on {len(y)} samples "
                f"from alignment buffer",
                1,
                1,
            )

        except Exception:
            self.print(
                f"Error in _align_head_on_buffer: {traceback.format_exc()}",
                0,
                1,
            )

    def send_model_to_peers(self):
        """
        Send latest local model weights to all connected peers via P2P module.

        Called after each local training event.
        """
        try:
            self.print("send_model_to_peers: entering", 1, 1)
            if self.model is None:
                return

            shared = self.model.weights_for_sharing()
            n_params = sum(t.numel() for t in shared.values())

            self.print(
                f"send_model_to_peers: {len(shared)} shared tensors, {n_params} params",
                1,
                1,
            )

            model_data = {
                "message_type": "model",
                "model_class": self.model_class_name,
                "shared": {
                    k: t.cpu().numpy().tolist() for k, t in shared.items()
                },
                "n_params": n_params,
                "timestamp": time.time(),
                "peer_id": getattr(self, "my_peer_id", "unknown"),
            }

            # Publish to P2P module via p2p_pygo (Python -> Go) channel
            # The Go binary requires {"message": "<base64>", "recipient": "<peer_id|*>"}
            try:
                import base64

                message_json = json.dumps(model_data)
                message_b64 = base64.b64encode(message_json.encode()).decode()
                go_message = {
                    "message": message_b64,
                    "recipient": "*",
                }
                self.print(
                    f"send_model_to_peers: message_b64_len={len(message_b64)}",
                    1,
                    1,
                )
                self.db.publish("p2p_pygo", json.dumps(go_message))
                self.print(
                    "send_model_to_peers: published to p2p_pygo, result=True",
                    self.logger.log_timeline(
                        "MODEL_SENT",
                        f"peer={getattr(self, 'my_peer_id', '?' )} n_params={n_params}",
                    ),
                    1,
                    1,
                )
            except Exception:
                self.print(
                    "P2P publish channel not available, model not sent",
                    1,
                    1,
                )
            except Exception:
                self.print(
                    "P2P publish channel not available, model not sent",
                    1,
                    1,
                )

            self.print("send_model_to_peers: exiting", 1, 1)

        except Exception:
            self.print(
                f"Error sending model to peers: {traceback.format_exc()}",
                0,
                1,
            )

    def _process_flow(self, flow: dict, label: str) -> tuple:
        """Process flow into features and label."""
        try:
            features = self._extract_flow_features(flow)
            if features is None or len(features) == 0:
                return None, None
            return np.array(features, dtype=np.float32), label
        except Exception:
            return None, None

    def _get_feature_order(self) -> list:
        """Return fixed 18-feature order matching FIXED_INPUT_DIM."""
        return [
            "dur",
            "sport",
            "dport",
            "spkts",
            "dpkts",
            "sbytes",
            "dbytes",
            "proto",
            "appproto",
            "state",
            "saddr_num",
            "daddr_num",
            "dir_num",
            "total_bytes",
            "total_pkts",
            "avg_pkt_size",
            "throughput",
            "history_len",
        ]

    def _extract_flow_features(self, flow: dict) -> Optional[list]:
        """
        Extract exactly 18 features from a Slips flow dictionary.

        Uses same logic as process_features() to ensure consistent feature
        extraction matching the FIXED_INPUT_DIM constant.

        Returns list of 18 numeric values or None if extraction fails.
        """
        try:
            df = pd.DataFrame([flow])

            # Coerce base numerics (matching other ML modules)
            for col in [
                "dur",
                "sport",
                "dport",
                "spkts",
                "dpkts",
                "sbytes",
                "dbytes",
            ]:
                if col in df.columns:
                    df[col] = pd.to_numeric(df[col], errors="coerce").fillna(
                        0.0
                    )
                else:
                    df[col] = 0.0

            # Encode proto using base class method (inclusive)
            proto_val = str(df.iloc[0].get("proto", ""))
            df["proto"] = self._encode_proto(proto_val)

            # Encode appproto
            appproto_val = df.iloc[0].get("appproto")
            if pd.notna(appproto_val):
                df["appproto"] = self._encode_appproto(str(appproto_val))
            else:
                df["appproto"] = 10.0

            # Infer state using base class method
            state_str = str(df.iloc[0].get("state", ""))
            spkts = df.iloc[0]["spkts"]
            dpkts = df.iloc[0]["dpkts"]
            df["state"] = self._infer_state(state_str, spkts, dpkts)

            # IP to numeric via ipaddress
            saddr = df.iloc[0].get("saddr")
            daddr = df.iloc[0].get("daddr")
            df["saddr_num"] = (
                int(ipaddress.ip_address(str(saddr))) % 1000000
                if saddr and pd.notna(saddr)
                else 0.0
            )
            df["daddr_num"] = (
                int(ipaddress.ip_address(str(daddr))) % 1000000
                if daddr and pd.notna(daddr)
                else 0.0
            )

            # Direction numeric
            dir_val = str(df.iloc[0].get("dir_", "->"))
            df["dir_num"] = 1.0 if dir_val == "->" else 0.0

            # Derived features
            sbytes = df.iloc[0]["sbytes"]
            dbytes = df.iloc[0]["dbytes"]
            dur_val = df.iloc[0]["dur"]
            df["total_bytes"] = sbytes + dbytes
            df["total_pkts"] = df.iloc[0]["spkts"] + df.iloc[0]["dpkts"]
            df["avg_pkt_size"] = sbytes / max(float(spkts), 1.0)
            df["throughput"] = df["total_bytes"] / max(dur_val, 0.001)
            history = df.iloc[0].get("history")
            df["history_len"] = float(len(str(history))) if history else 0.0

            # Extract features in fixed order
            feature_order = self._get_feature_order()
            features = []
            for feat in feature_order:
                val = df.iloc[0].get(feat, 0.0)
                if val is None:
                    val = 0.0
                features.append(
                    float(val) if not isinstance(val, str) else 0.0
                )

            if len(features) != SimpleFederatedNet.FIXED_INPUT_DIM:
                self.print(
                    f"Feature extraction produced {len(features)} features "
                    f"instead of {SimpleFederatedNet.FIXED_INPUT_DIM}",
                    0,
                    1,
                )
                return None

            return features
        except Exception:
            return None

    def _get_flows_for_ip_in_window(self, ip: str) -> list:
        """Get flows for an IP in current window."""
        return [
            flow
            for flow_id, flow in self.window_flows.items()
            if flow.get("saddr") == ip or flow.get("daddr") == ip
        ]

    def _get_simulated_gt(self, flow: dict) -> Optional[str]:
        """
        Derive ground-truth label for simulation/testing.

        Resolution order (first hit wins):
          1. Netflow-labeler standard: a zeek-flow ``ground_truth_label`` (or the
             detailed variant) present in the flow dict — the canonical way to
             feed labeled flows / runtime-labeled flows into Slips.
          2. Runtime attack-IP allow-list injected by the experiment runtime at
             ``/opt/network-setup/simulated_attackers.txt`` (one IPv4 per line;
             re-read on file mtime change so the experiment runner can plug the
             static attacker + aracne pivot address in live, no restart).
          3. Otherwise BENIGN.
        """
        gt = flow.get("ground_truth_label") or flow.get(
            "detailed_ground_truth_label"
        )
        if gt:
            low = str(gt).strip().lower()
            if low.startswith(("mal", "attack")):
                return MALICIOUS
            if low.startswith(("ben", "norm")):
                return BENIGN

        saddr = str(flow.get("saddr", ""))
        daddr = str(flow.get("daddr", ""))
        for ip in self._simulated_attackers():
            if saddr == ip or daddr == ip:
                return MALICIOUS
        return BENIGN

    _SIM_ATTACKERS_PATH = "/opt/network-setup/simulated_attackers.txt"

    def _simulated_attackers(self):
        """Read the runtime attack-IP allow-list, cached on file mtime.

        Path can be overridden via env FL_SIM_ATTACKERS. Missing file -> no
        extra rules (matches pre-runtime behavior, benign by default).
        """
        import os

        path = os.environ.get("FL_SIM_ATTACKERS", self._SIM_ATTACKERS_PATH)
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            return ()
        cache = getattr(self, "_sim_attackers_cache", None)
        if cache and cache[0] == mtime and cache[1] == path:
            return cache[2]
        ips = []
        try:
            with open(path, "r") as fh:
                for line in fh:
                    token = line.strip()
                    if not token or token.startswith("#"):
                        continue
                    ips.append(token.split()[0])
        except OSError:
            return ()
        frozen = tuple(ips)
        self._sim_attackers_cache = (mtime, path, frozen)
        return frozen

    def _get_flow_id(self, flow: dict) -> str:
        """Generate unique flow ID. Prefer Zeek uid, fallback to 5-tuple + time."""
        uid = flow.get("uid")
        if uid:
            return str(uid)
        return f"{flow.get('saddr', '')}:{flow.get('sport', '')}-{flow.get('daddr', '')}:{flow.get('dport', '')}-{flow.get('starttime', '')}"

    def _compute_accuracy(self, X: np.ndarray, y: np.ndarray) -> float:
        """Compute accuracy."""
        preds = self.predict_batch(X)
        correct = sum(1 for p, t in zip(preds, y) if p == t)
        return correct / len(y) if len(y) > 0 else 0.0

    def _save_local_model(self):
        """Save latest local model (full state dict + scaler)."""
        try:
            if self.model is None:
                return

            torch.save(self.model.state_dict(), self.local_state_path)
            with open(self.local_scaler_path, "wb") as f:
                pickle.dump(self.scaler, f)

        except Exception:
            self.print(
                f"Error saving local model: {traceback.format_exc()}", 0, 1
            )

    def _save_final_merged_model(self) -> None:
        """Persist the current (latest) MERGED model + scaler to the
        configured store paths (model_store_path / preprocess_store_path,
        resolved by the base class into self.model_path / self.preprocess_path).
        Called at the end of every merge and at graceful shutdown so the
        configured path always holds the FINAL merged weights; numbered
        per-merge artifacts stay at their hardcoded module paths."""
        try:
            if self.model is None or self.merge_count <= 0:
                return
            store_path = getattr(self, "model_path", None)
            prep_path = getattr(self, "preprocess_path", None)
            if not store_path or not prep_path:
                return
            os.makedirs(os.path.dirname(store_path), exist_ok=True)
            torch.save(
                {
                    "state_dict": self.model.state_dict(),
                    "model_class": self.model_class_name,
                    "merge_count": self.merge_count,
                },
                store_path,
            )
            os.makedirs(os.path.dirname(prep_path), exist_ok=True)
            with open(prep_path, "wb") as fh:
                pickle.dump(self.scaler, fh)
            self.print(
                f"final merged model -> {store_path} (merge {self.merge_count})",
                0,
                2,
            )
        except Exception:
            self.print(
                "final merged model save failed: " + traceback.format_exc(),
                0,
                1,
            )

    def _save_merged_model(self, merge_count: int):
        """Save merged model (full state dict; class-driven persistence)."""
        try:
            if self.model is None:
                return

            torch.save(
                self.model.state_dict(),
                os.path.join(
                    self.merged_dir, f"merged_{merge_count}_state.bin"
                ),
            )

        except Exception:
            self.print(
                f"Error saving merged model {merge_count}: {traceback.format_exc()}",
                0,
                1,
            )

    def store_model(self):
        """Override base class to save both local and merged models."""
        self.print("Storing models on graceful shutdown.", 0, 2)
        self._write_label_flips("shutdown")
        self._save_local_model()
        if self.merge_count > 0:
            self._save_merged_model(self.merge_count)
            self._save_final_merged_model()

    def train(self, sum_labeled_flows):
        """Train entrypoint - delegates to base class."""
        return self._train_default(sum_labeled_flows)

    def run_test_on_flow(self, flow: dict):
        """Test entrypoint - classify flow without creating evidence."""
        try:
            predicted = self._classify_flow(flow)
            if predicted is None:
                return

            ground_truth = self._get_simulated_gt(flow) or BENIGN
            self.store_testing_results(ground_truth, predicted)

            src_ip = flow.get("saddr", "unknown")
            dst_ip = flow.get("daddr", "unknown")
            self.print(f"Flow {src_ip}->{dst_ip}: {predicted}", 1, 1)

        except Exception:
            self.print(f"Error testing flow: {traceback.format_exc()}", 0, 1)

    @staticmethod
    def _blank_test_statistics() -> dict:
        """Fresh counters for one testing stream (cumulative within a window)."""
        return {
            "tp": 0,
            "fp": 0,
            "tn": 0,
            "fn": 0,
            "gt_mal": 0,
            "gt_ben": 0,
            "pred_mal": 0,
            "pred_ben": 0,
            "flows_since_snapshot": 0,
        }

    def _predict_with(self, model, flow):
        """Classify one flow with an arbitrary frozen model instance.

        Uses the module's own feature extraction, scaler and device; callers
        pass a deep-copied (frozen) model so the ACTIVE model is untouched.
        Returns  MALICIOUS/BENIGN or None.
        """
        if model is None or not self._is_fitted:
            return None
        try:
            features = self._extract_flow_features(flow)
            if features is None:
                return None
            X = np.array([features], dtype=np.float32)
            X_scaled = self.scaler.transform(X)
            model.eval()
            with torch.no_grad():
                outputs = model(torch.FloatTensor(X_scaled).to(self.device))
                probs = torch.softmax(outputs, dim=1)
                return (
                    MALICIOUS
                    if int(torch.argmax(probs, dim=1).item()) == 1
                    else BENIGN
                )
        except Exception:
            return None

    def _store_local_stream(self, gt_label: str, predicted: str) -> None:
        """Accumulate local-only (pre-merge snapshot) testing counters."""
        self._local_stream_used = True
        st = self._local_test
        st["flows_since_snapshot"] += 1
        if gt_label == MALICIOUS:
            st["gt_mal"] += 1
        else:
            st["gt_ben"] += 1
        if predicted == MALICIOUS:
            st["pred_mal"] += 1
        else:
            st["pred_ben"] += 1
        if gt_label == MALICIOUS and predicted == MALICIOUS:
            st["tp"] += 1
        elif gt_label != MALICIOUS and predicted == MALICIOUS:
            st["fp"] += 1
        elif gt_label == MALICIOUS:
            st["fn"] += 1
        else:
            st["tn"] += 1
        if st["flows_since_snapshot"] >= self.testing_log_batch_size:
            self._flush_local_stream()

    def _flush_local_stream(self) -> None:
        """Write the pending local-only testing snapshot to local_test.log."""
        st = self._local_test
        if st["flows_since_snapshot"] <= 0:
            return
        total = st["tp"] + st["fp"] + st["tn"] + st["fn"]
        acc = (st["tp"] + st["tn"]) / total if total else 0.0
        self.logger._write(
            "local_test",
            f"  flows={total} | "
            f"GT(Mal/Ben): {st['gt_mal']}/{st['gt_ben']} | "
            f"Pred(Mal/Ben): {st['pred_mal']}/{st['pred_ben']} | "
            f"TP/FP/TN/FN: {st['tp']}/{st['fp']}/{st['tn']}/{st['fn']} | "
            f"Acc={acc:.4f}",
        )
        st["flows_since_snapshot"] = 0

    def _write_testing_snapshot(self, batch_flows: int) -> None:
        """Write cumulative TP/FP/TN/FN/Acc snapshot (tests against GT)."""
        if batch_flows <= 0:
            return
        target = "merged_test" if self._using_merged_model else "local_test"
        tp = self.malware_metrics.get("TP", 0)
        fp = self.malware_metrics.get("FP", 0)
        tn = self.malware_metrics.get("TN", 0)
        fn = self.malware_metrics.get("FN", 0)
        total = tp + fp + tn + fn
        acc = (tp + tn) / total if total > 0 else 0.0
        self.logger._write(
            target,
            f"  flows={total} | "
            f"GT(Mal/Ben): {self.seen_labels.get(MALICIOUS,0)}/{self.seen_labels.get(BENIGN,0)} | "
            f"Pred(Mal/Ben): {self.predicted_labels.get(MALICIOUS,0)}/{self.predicted_labels.get(BENIGN,0)} | "
            f"TP/FP/TN/FN: {tp}/{fp}/{tn}/{fn} | Acc={acc:.4f}",
        )
