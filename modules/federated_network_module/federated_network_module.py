# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""
Federated Network Module - Federated Learning with Model Sharing

Architecture: input(N features, dynamic) -> RandomProjection(64,frozen,shared) -> Linear(64->16)+ReLU [fc1] -> Linear(16->2) [head]

Training Flow:
1. Local Training (on alert or window close):
   - Label flows (malicious from alert evidence, rest benign)
   - Train fc1 + head ONCE on training buffer
   - Save as latest_local model
   - Send to peers via P2P

2. Head Alignment (periodic):
   - Freeze fc1
   - Train head ONLY on alignment buffer (all accumulated flows)
   - Unfreeze fc1

3. Model Merging (periodic or event-based):
   - Collect all peer models + own latest local
   - Aggregate fc1 weights (AVERAGE)
   - Retrain head ONCE on alignment buffer (fc1 frozen)
   - Save as merged_N model (merged models NOT used in future merges)

Key Features:
- Dynamic input dimension (detected from first flow)
- Two buffers: training (small, for local training) and alignment (large, for head alignment)
- Model separation: latest_local (own data only) vs merged (aggregated)
- Off-sync windows: random time offset per peer to avoid network pulses
- Graceful shutdown: saves latest_local and latest merged model

Artifact Paths:
- Base (shared): artifacts/random_projection.bin, artifacts/scaler.bin
- Local: artifacts/latest_local_fc1.bin, latest_local_head.bin, latest_local_scaler.bin
- Merged: artifacts/merged_N_fc1.bin, merged_N_head.bin (N = merge count)
"""
import ipaddress
import json
import os
import pickle
import random
import shutil
import time
import traceback
from typing import Dict, Optional

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.preprocessing import StandardScaler

import slips_files.common.abstracts.ml_module_base as ml_base
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.core.structures.evidence import EvidenceType

BENIGN = ml_base.BENIGN
MALICIOUS = ml_base.MALICIOUS


class SimpleFederatedNet(nn.Module):
    """
    Federated network model: frozen shared random projection + learnable fc1 + head.

    Architecture: input(18) -> RandomProjection(64,frozen) -> Linear(64->16)+ReLU -> Linear(16->2)

    FIXED FEATURE COUNT: 18 Zeek-native features (see process_features for full list)
    """

    FIXED_INPUT_DIM = 18  # Must match len(feature_order) in process_features

    def __init__(
        self,
        input_dim: int,
        hidden1: int = 64,
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

        # Load or create frozen random projection with validation
        if rp_path and os.path.exists(rp_path):
            try:
                random_weights = torch.load(rp_path, weights_only=True)
                # Validate loaded weights have correct input dimension
                if random_weights.shape[0] != self.FIXED_INPUT_DIM:
                    raise ValueError(
                        f"Loaded random_projection has input_dim={random_weights.shape[0]}, "
                        f"expected {self.FIXED_INPUT_DIM}"
                    )
            except (RuntimeError, ValueError) as e:
                # Reconstruct from seed if loading fails or dimension mismatch
                print(
                    f"[FederatedNetworkModule] Random projection load failed: {e}. "
                    f"Reconstructing new random projection from seed={seed}."
                )
                random_weights = torch.rand(self.FIXED_INPUT_DIM, hidden1)
        else:
            torch.manual_seed(seed)
            random_weights = torch.rand(self.FIXED_INPUT_DIM, hidden1)

        if rp_path:
            os.makedirs(os.path.dirname(rp_path), exist_ok=True)
            torch.save(random_weights, rp_path)

        self.random_projection = nn.Linear(
            self.FIXED_INPUT_DIM, hidden1, bias=False
        )
        # nn.Linear expects (out_features, in_features) = (hidden1, FIXED_INPUT_DIM)
        # Our random_weights is (FIXED_INPUT_DIM, hidden1), so transpose
        self.random_projection.weight.data = random_weights.T
        self.random_projection.weight.requires_grad = False

        # fc1 layer (learnable)
        self.fc1 = nn.Linear(hidden1, hidden2, bias=True)

        # Head layer (learnable)
        self.head = nn.Linear(hidden2, 2)
        self.relu = nn.ReLU()

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.random_projection(x)
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


class ModuleLogger:
    """Centralized logging for training, testing, and label comparison."""

    def __init__(self, output_dir: str, enable: bool):
        self.enable = enable
        self._files = {}
        if enable:
            os.makedirs(output_dir, exist_ok=True)
            for name in [
                "local_train",
                "local_test",
                "merged_train",
                "merged_test",
                "label_comparison",
            ]:
                path = os.path.join(output_dir, f"{name}.log")
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

    def log_comparison_header(self, header: str) -> None:
        self._write("label_comparison", f"--- {header} ---")

    def log_comparison_line(self, line: str) -> None:
        self._write("label_comparison", f"  {line}")

    def close(self) -> None:
        for f in self._files.values():
            f.close()


class FederatedNetworkModule(ml_base.MLBaseDetection):
    """
    Federated network ML detector with model sharing and merging.

    Training triggers:
    1. New alert: Label connected flows malicious, rest benign -> Train fc1+head ONCE
    2. Time window closed: All remaining benign -> Train fc1+head ONCE
    3. Merge event: Aggregate peer models -> Retrain head ONCE on alignment buffer
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

        # Invalidate stale bytecode cache so every run compiles from source.
        _pycache = os.path.join(os.path.dirname(__file__), "__pycache__")
        if os.path.isdir(_pycache):
            shutil.rmtree(_pycache)

        # Artifact paths
        artifacts_dir = os.path.join(
            ".", "modules", "federated_network_module", "artifacts"
        )
        os.makedirs(artifacts_dir, exist_ok=True)
        self.rp_path = os.path.join(artifacts_dir, "random_projection.bin")
        self.local_fc1_path = os.path.join(
            artifacts_dir, "latest_local_fc1.bin"
        )
        self.local_head_path = os.path.join(
            artifacts_dir, "latest_local_head.bin"
        )
        self.local_scaler_path = os.path.join(
            artifacts_dir, "latest_local_scaler.bin"
        )
        self.merged_dir = os.path.join(artifacts_dir, "merged")
        os.makedirs(self.merged_dir, exist_ok=True)

        # Input dimension (determined from first flow)
        self.input_dim: Optional[int] = None

        # Initialize model (in memory)
        self.model: Optional[SimpleFederatedNet] = None

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
        self.optimizer: Optional[optim.Adam] = None
        self.criterion = nn.CrossEntropyLoss()

        # Buffers
        self.training_buffer_x: list = []
        self.training_buffer_y: list = []
        self.alignment_buffer_x: list = []
        self.alignment_buffer_y: list = []

        # Flow tracking
        self.window_flows: dict = {}  # flow_id -> flow_dict

        # Peer models storage
        self.peer_models: Dict[str, dict] = (
            {}
        )  # peer_id -> {fc1, head, timestamp}

        # Device
        self.device = torch.device(
            "cuda" if torch.cuda.is_available() else "cpu"
        )

        # Metrics
        self.last_batch_loss: float = 0.0
        self.merge_count: int = 0

        # Training counters
        self.training_count_alert: int = 0
        self.training_count_twclose: int = 0
        self._training_trigger: str = ""

        # Track whether current model is merged (affects testing log target)
        self._using_merged_model: bool = False

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

        # Sub-window size for our module (shorter than global Slips TW, default 20 minutes)
        self.window_size_seconds: int = self._read_module_config_int(
            "time_window_width", default=1200
        )

        # Random per-instance sub-window offset to desynchronize peers (≤ half window width)
        self._time_offset: float = random.uniform(
            0, self.window_size_seconds / 2.0
        )

        # Sub-window tracking
        self.window_start_ts: Optional[float] = None

        # Load existing local model if present and not training from scratch
        train_from_scratch = self._read_module_config_bool(
            "train_from_scratch", default=False
        )
        if not train_from_scratch:
            self._load_local_model()

    def subscribe_to_channels(self):
        """Subscribe to flows, alerts, and optionally P2P model channel."""
        # Always subscribe to these core channels
        self.c_flows = self.db.subscribe("new_flow")
        self.c_alerts = self.db.subscribe("new_alert")

        # Initialize channels dict with core subscriptions
        self.channels = {
            "new_flow": self.c_flows,
            "new_alert": self.c_alerts,
        }

        # Try to subscribe to P2P channel (optional)
        c_p2p_model = self.db.subscribe("p2p_model_received")
        if c_p2p_model and c_p2p_model is not True:
            self.channels["p2p_model_received"] = c_p2p_model
        else:
            self.print(
                "P2P model channel not available, model sharing disabled",
                0,
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
        """Load fc1, head, and scaler from disk if artifacts exist."""
        try:
            if not os.path.exists(self.local_fc1_path):
                return
            if not os.path.exists(self.local_head_path):
                return
            if not os.path.exists(self.local_scaler_path):
                return

            if self.model is None:
                self.model = self.create_empty_model().to(self.device)
                self.optimizer = optim.Adam(self.model.parameters(), lr=0.001)

            fc1_w = torch.load(self.local_fc1_path, weights_only=True)
            fc1_b = torch.load(
                self.local_fc1_path.replace("_fc1", "_fc1_bias"),
                weights_only=True,
            )
            head_w = torch.load(self.local_head_path, weights_only=True)
            head_b = torch.load(
                self.local_head_path.replace("_head", "_head_bias"),
                weights_only=True,
            )

            self.model.set_fc1_weights(fc1_w, fc1_b)
            self.model.set_head_weights(head_w, head_b)

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

    def create_empty_model(self) -> SimpleFederatedNet:
        """Create model with FIXED input dimension (18 features)."""
        # Always use fixed input dimension - don't rely on runtime detection
        self.input_dim = SimpleFederatedNet.FIXED_INPUT_DIM
        return SimpleFederatedNet(
            self.input_dim, rp_path=self.rp_path, seed=self.seed
        )

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

        Args:
            x_train: Normalized features
            y_train: Labels (BENIGN/MALICIOUS)
            classes: List of class labels (unused, kept for compatibility)
            train_target: Logger target ("local" for "local_train", "merged" for "merged_train")
        """
        freeze_fc1 = getattr(self, "_freeze_fc1_for_training", False)
        epochs = (
            self.merge_finetune_epochs
            if freeze_fc1
            else self.local_training_epochs
        )

        log_target = f"{train_target}_train"

        if self.model is None:
            self.model = self.create_empty_model().to(self.device)
            self.optimizer = optim.Adam(self.model.parameters(), lr=0.001)

        if freeze_fc1:
            self.model.freeze_fc1()
            self.optimizer = optim.Adam(self.model.head.parameters(), lr=0.001)
        else:
            self.model.unfreeze_fc1()
            if self.optimizer is None:
                self.optimizer = optim.Adam(self.model.parameters(), lr=0.001)

        X_tensor = torch.FloatTensor(x_train).to(self.device)
        y_tensor = torch.LongTensor(
            [0 if y == BENIGN else 1 for y in y_train]
        ).to(self.device)

        self.model.train()

        for epoch in range(epochs):
            self.optimizer.zero_grad()
            outputs = self.model(X_tensor)
            loss = self.criterion(outputs, y_tensor)
            loss.backward()
            self.optimizer.step()
            self.last_batch_loss = loss.item()

            with torch.no_grad():
                epoch_outputs = self.model(X_tensor)
                epoch_preds = torch.argmax(epoch_outputs, dim=1)
                epoch_correct = (epoch_preds == y_tensor).sum().item()
                epoch_acc = epoch_correct / len(y_tensor)
                self.logger.log_train_epoch(
                    log_target, epoch + 1, epochs, loss.item(), epoch_acc
                )

        with torch.no_grad():
            final_outputs = self.model(X_tensor)
            final_preds = torch.argmax(final_outputs, dim=1)
            final_loss = self.criterion(final_outputs, y_tensor).item()

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
        """Training main loop: buffer flows, train on alerts/sub-windows, test if model ready."""
        try:
            if msg := self.get_msg("new_flow"):
                data = json.loads(msg["data"])
                flow = data["flow"]
                flow_ts = float(data.get("stime", 0))

                # Buffer flow for later training
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

            if msg := self.get_msg("new_alert"):
                self.handle_new_alert(json.loads(msg["data"]))

            # Only check P2P channel if it exists
            if "p2p_model_received" in self.channels:
                if msg := self.get_msg("p2p_model_received"):
                    self.handle_p2p_model(json.loads(msg["data"]))

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
        """Store flow in current sub-window, close window on timestamp-based expiry."""
        flow_id = self._get_flow_id(flow)
        self.window_flows[flow_id] = flow

        if flow_ts > 0:
            # Initialize sub-window start skewed by random offset
            if self.window_start_ts is None:
                self.window_start_ts = flow_ts - self._time_offset

            # Check if sub-window has expired
            if flow_ts - self.window_start_ts >= self.window_size_seconds:
                self._close_sub_window()
                self.window_start_ts = flow_ts - self._time_offset
                # Re-add current flow to new window
                self.window_flows[flow_id] = flow

    def handle_new_alert(self, alert: dict):
        """
        Handle new alert: label connected flows as MALICIOUS, rest as BENIGN, train ONCE.

        Alert structure:
        - profile: {"ip": "..."}
        - timewindow: {"number": N, ...}
        - last_evidence: {"attacker": {"ip": "..."}, "victim": {"ip": "..."}, "ID": "..."}
        - correl_id: [list of evidence IDs]
        - id: alert ID
        """
        try:
            self.print("Alert received, preparing training batch", 0, 1)

            # Extract alert components
            profile_ip = alert.get("profile", {}).get("ip")
            tw_number = alert.get("timewindow", {}).get("number")
            if not profile_ip or not tw_number:
                self.print(
                    "Invalid alert structure: missing profile/twid",
                    0,
                    1,
                )
                return

            # Get evidence IDs from correl_id or last_evidence
            correl_id = alert.get("correl_id", [])
            last_evidence = alert.get("last_evidence", {})

            # Collect all evidence IDs
            evidence_ids = set()
            if correl_id:
                evidence_ids.update(correl_id)
            if last_evidence.get("ID"):
                evidence_ids.add(last_evidence["ID"])

            if not evidence_ids:
                self.print("No evidence IDs in alert, skipping", 0, 1)
                return

            self._last_alert_evidence_ids = list(evidence_ids)

            # Collect flow UIDs connected to this alert's evidence
            matched_uids: set = set()
            for evid_id in evidence_ids:
                uids = self.db.get_flows_causing_evidence(evid_id)
                if uids:
                    matched_uids.update(uids)

            # Build malicious flows from current window (uid-based matching)
            malicious_flows = []
            malicious_flow_ids = set()
            for flow_id, flow in self.window_flows.items():
                flow_uid = (flow.get("uid") or "").strip()
                if flow_uid and flow_uid in matched_uids:
                    malicious_flows.append(flow)
                    malicious_flow_ids.add(flow_id)

            # Also fetch evidence-connected flows from DB not in current window
            remaining_uids = matched_uids - set(
                (f.get("uid") or "").strip() for f in malicious_flows
            )
            for uid in remaining_uids:
                flow = self.db.get_flow(uid)
                if flow:
                    malicious_flows.append(flow)

            # Fallback: match by profile IP if no flows were connected via evidence
            if not malicious_flows:
                profile_ip_flows = self._get_flows_for_ip_in_window(profile_ip)
                malicious_flows.extend(profile_ip_flows)

            # Collect all other flows in window as benign
            benign_flows = []
            for flow_id, flow in self.window_flows.items():
                if flow_id not in malicious_flow_ids:
                    benign_flows.append(flow)

            self.print(
                f"Found {len(malicious_flows)} malicious, {len(benign_flows)} benign flows",
                0,
                1,
            )

            # Skip training if no flows labeled
            if len(malicious_flows) + len(benign_flows) == 0:
                self.print(
                    "No flows to train on, skipping training",
                    0,
                    1,
                )
                return

            # Prepare training data
            self.training_buffer_x.clear()
            self.training_buffer_y.clear()

            for flow in malicious_flows:
                x, _ = self._process_flow(flow, MALICIOUS)
                if x is not None:
                    self.training_buffer_x.append(x)
                    self.training_buffer_y.append(MALICIOUS)
                    self.alignment_buffer_x.append(x)
                    self.alignment_buffer_y.append(MALICIOUS)

            for flow in benign_flows:
                x, _ = self._process_flow(flow, BENIGN)
                if x is not None:
                    self.training_buffer_x.append(x)
                    self.training_buffer_y.append(BENIGN)
                    self.alignment_buffer_x.append(x)
                    self.alignment_buffer_y.append(BENIGN)

            # 3-way label comparison block
            self.training_count_alert += 1
            if len(self.training_buffer_x) > 0:
                evidence_ids_count = len(evidence_ids)
                connected_count = len(malicious_flows)
                total_batch = len(malicious_flows) + len(benign_flows)

                header = (
                    f"alert_{self.training_count_alert} | "
                    f"{evidence_ids_count} evidence, "
                    f"{connected_count} connected, "
                    f"{total_batch} total batch"
                )
                self.logger.log_comparison_header(header)

                # inferred vs GT
                gt_labels = []
                inferred_labels = []
                all_flows = malicious_flows + benign_flows
                for i, flow in enumerate(all_flows):
                    if i >= len(self.training_buffer_y):
                        break
                    gt_norm = self._get_simulated_gt(flow)
                    if gt_norm is None:
                        continue
                    inferred_labels.append(self.training_buffer_y[i])
                    gt_labels.append(gt_norm)
                if len(gt_labels) > 0:
                    inf_arr = np.array(inferred_labels)
                    gt_arr = np.array(gt_labels)
                    mal_inf = int(np.sum(inf_arr == MALICIOUS))
                    ben_inf = int(np.sum(inf_arr == BENIGN))
                    mal_gt = int(np.sum(gt_arr == MALICIOUS))
                    ben_gt = int(np.sum(gt_arr == BENIGN))
                    tp = int(
                        np.sum((inf_arr == MALICIOUS) & (gt_arr == MALICIOUS))
                    )
                    fp = int(
                        np.sum((inf_arr == MALICIOUS) & (gt_arr == BENIGN))
                    )
                    tn = int(np.sum((inf_arr == BENIGN) & (gt_arr == BENIGN)))
                    fn = int(
                        np.sum((inf_arr == BENIGN) & (gt_arr == MALICIOUS))
                    )
                    acc = (
                        (tp + tn) / len(gt_labels)
                        if len(gt_labels) > 0
                        else 0.0
                    )
                    self.logger.log_comparison_line(
                        f"inferred vs GT: {len(gt_labels)} samples | "
                        f"Mal/Ben: {mal_inf}/{ben_inf} vs {mal_gt}/{ben_gt} | "
                        f"TP/FP/TN/FN: {tp}/{fp}/{tn}/{fn} | Acc: {acc:.4f}"
                    )

                # Collect test-time preds with inferred labels and GT in one pass
                pred_data = []
                for flow in all_flows:
                    fid = self._get_flow_id(flow)
                    pred = self.test_time_predictions.pop(fid, None)
                    if pred is not None:
                        inferred = (
                            MALICIOUS if fid in malicious_flow_ids else BENIGN
                        )
                        gt_norm = self._get_simulated_gt(flow)
                        pred_data.append((pred, inferred, gt_norm))

                if len(pred_data) > 0:
                    pred_labels = [p for p, _, _ in pred_data]
                    pred_inferred_labels = [i for _, i, _ in pred_data]

                    # pred vs inferred
                    pred_arr = np.array(pred_labels)
                    pinf_arr = np.array(pred_inferred_labels)
                    mal_pred = int(np.sum(pred_arr == MALICIOUS))
                    ben_pred = int(np.sum(pred_arr == BENIGN))
                    mal_pinf = int(np.sum(pinf_arr == MALICIOUS))
                    ben_pinf = int(np.sum(pinf_arr == BENIGN))
                    tp = int(
                        np.sum(
                            (pred_arr == MALICIOUS) & (pinf_arr == MALICIOUS)
                        )
                    )
                    fp = int(
                        np.sum((pred_arr == MALICIOUS) & (pinf_arr == BENIGN))
                    )
                    tn = int(
                        np.sum((pred_arr == BENIGN) & (pinf_arr == BENIGN))
                    )
                    fn = int(
                        np.sum((pred_arr == BENIGN) & (pinf_arr == MALICIOUS))
                    )
                    acc = (
                        (tp + tn) / len(pred_labels)
                        if len(pred_labels) > 0
                        else 0.0
                    )
                    self.logger.log_comparison_line(
                        f"pred vs inferred: {len(pred_labels)} samples | "
                        f"Mal/Ben: {mal_pred}/{ben_pred} vs {mal_pinf}/{ben_pinf} | "
                        f"TP/FP/TN/FN: {tp}/{fp}/{tn}/{fn} | Acc: {acc:.4f}"
                    )

                    # pred vs GT (only flows with GT available)
                    pvg_pairs = [
                        (p, g) for p, _, g in pred_data if g is not None
                    ]
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
                            np.sum(
                                (pvg_arr == MALICIOUS) & (gt_arr2 == MALICIOUS)
                            )
                        )
                        fp = int(
                            np.sum(
                                (pvg_arr == MALICIOUS) & (gt_arr2 == BENIGN)
                            )
                        )
                        tn = int(
                            np.sum((pvg_arr == BENIGN) & (gt_arr2 == BENIGN))
                        )
                        fn = int(
                            np.sum(
                                (pvg_arr == BENIGN) & (gt_arr2 == MALICIOUS)
                            )
                        )
                        acc = (
                            (tp + tn) / len(pvg_preds)
                            if len(pvg_preds) > 0
                            else 0.0
                        )
                        self.logger.log_comparison_line(
                            f"pred vs GT: {len(pvg_preds)} samples | "
                            f"Mal/Ben: {mal_pvg}/{ben_pvg} vs {mal_gt2}/{ben_gt2} | "
                            f"TP/FP/TN/FN: {tp}/{fp}/{tn}/{fn} | Acc: {acc:.4f}"
                        )

                self._training_trigger = "alert"
                self._train_batch()

                target = (
                    "merged_test" if self._using_merged_model else "local_test"
                )
                self.logger.log_test_marker(
                    target,
                    f"New local model ({self._training_trigger}_{self.training_count_alert})",
                )

            # Consume entire window after training
            self.window_flows.clear()

            # Send model to peers
            self.send_model_to_peers()

        except Exception:
            self.print(f"Error handling alert: {traceback.format_exc()}", 0, 1)

    def _close_sub_window(self):
        """
        Close current sub-window: label all remaining flows as BENIGN, train ONCE.

        Called when flow timestamps indicate our sub-window has expired.
        Independent of Slips' global time windows.
        """
        try:
            self.print("Sub-window closed, preparing training batch", 0, 1)

            # All remaining flows are benign
            remaining_flows = list(self.window_flows.values())

            if not remaining_flows:
                self.print(
                    "No unlabeled flows in closed window, skipping training",
                    0,
                    1,
                )
                # Still clear window for next iteration
                for fid in list(self.window_flows.keys()):
                    self.test_time_predictions.pop(fid, None)
                self.window_flows.clear()
                return

            self.print(
                f"Training on {len(remaining_flows)} benign flows", 0, 1
            )

            # Prepare training data
            self.training_buffer_x.clear()
            self.training_buffer_y.clear()

            for flow in remaining_flows:
                x, _ = self._process_flow(flow, BENIGN)
                if x is not None:
                    self.training_buffer_x.append(x)
                    self.training_buffer_y.append(BENIGN)
                    self.alignment_buffer_x.append(x)
                    self.alignment_buffer_y.append(BENIGN)

            # 3-way label comparison block (no evidence count for twclose)
            self.training_count_twclose += 1
            if len(self.training_buffer_x) > 0:
                self.logger.log_comparison_header(
                    f"twclose_{self.training_count_twclose} | {len(remaining_flows)} benign flows"
                )

                # inferred vs GT
                gt_labels = []
                inferred_labels = []
                for i, flow in enumerate(remaining_flows):
                    if i >= len(self.training_buffer_y):
                        break
                    gt_norm = self._get_simulated_gt(flow)
                    if gt_norm is None:
                        continue
                    inferred_labels.append(self.training_buffer_y[i])
                    gt_labels.append(gt_norm)
                if len(gt_labels) > 0:
                    inf_arr = np.array(inferred_labels)
                    gt_arr = np.array(gt_labels)
                    mal_inf = int(np.sum(inf_arr == MALICIOUS))
                    ben_inf = int(np.sum(inf_arr == BENIGN))
                    mal_gt = int(np.sum(gt_arr == MALICIOUS))
                    ben_gt = int(np.sum(gt_arr == BENIGN))
                    tp = int(
                        np.sum((inf_arr == MALICIOUS) & (gt_arr == MALICIOUS))
                    )
                    fp = int(
                        np.sum((inf_arr == MALICIOUS) & (gt_arr == BENIGN))
                    )
                    tn = int(np.sum((inf_arr == BENIGN) & (gt_arr == BENIGN)))
                    fn = int(
                        np.sum((inf_arr == BENIGN) & (gt_arr == MALICIOUS))
                    )
                    acc = (
                        (tp + tn) / len(gt_labels)
                        if len(gt_labels) > 0
                        else 0.0
                    )
                    self.logger.log_comparison_line(
                        f"inferred vs GT: {len(gt_labels)} samples | "
                        f"Mal/Ben: {mal_inf}/{ben_inf} vs {mal_gt}/{ben_gt} | "
                        f"TP/FP/TN/FN: {tp}/{fp}/{tn}/{fn} | Acc: {acc:.4f}"
                    )

                # Collect test-time preds with inferred labels and GT in one pass
                pred_data = []
                for i, flow in enumerate(remaining_flows):
                    fid = self._get_flow_id(flow)
                    pred = self.test_time_predictions.pop(fid, None)
                    if pred is not None:
                        gt_norm = self._get_simulated_gt(flow)
                        pred_data.append((pred, gt_norm))

                if len(pred_data) > 0:
                    pred_labels = [p for p, _ in pred_data]
                    pred_inferred_labels = [BENIGN] * len(pred_data)

                    # pred vs inferred
                    pred_arr = np.array(pred_labels)
                    pinf_arr = np.array(pred_inferred_labels)
                    mal_pred = int(np.sum(pred_arr == MALICIOUS))
                    ben_pred = int(np.sum(pred_arr == BENIGN))
                    mal_pinf = int(np.sum(pinf_arr == MALICIOUS))
                    ben_pinf = int(np.sum(pinf_arr == BENIGN))
                    tp = int(
                        np.sum(
                            (pred_arr == MALICIOUS) & (pinf_arr == MALICIOUS)
                        )
                    )
                    fp = int(
                        np.sum((pred_arr == MALICIOUS) & (pinf_arr == BENIGN))
                    )
                    tn = int(
                        np.sum((pred_arr == BENIGN) & (pinf_arr == BENIGN))
                    )
                    fn = int(
                        np.sum((pred_arr == BENIGN) & (pinf_arr == MALICIOUS))
                    )
                    acc = (
                        (tp + tn) / len(pred_labels)
                        if len(pred_labels) > 0
                        else 0.0
                    )
                    self.logger.log_comparison_line(
                        f"pred vs inferred: {len(pred_labels)} samples | "
                        f"Mal/Ben: {mal_pred}/{ben_pred} vs {mal_pinf}/{ben_pinf} | "
                        f"TP/FP/TN/FN: {tp}/{fp}/{tn}/{fn} | Acc: {acc:.4f}"
                    )

                    # pred vs GT (only flows with GT available)
                    pvg_pairs = [(p, g) for p, g in pred_data if g is not None]
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
                            np.sum(
                                (pvg_arr == MALICIOUS) & (gt_arr2 == MALICIOUS)
                            )
                        )
                        fp = int(
                            np.sum(
                                (pvg_arr == MALICIOUS) & (gt_arr2 == BENIGN)
                            )
                        )
                        tn = int(
                            np.sum((pvg_arr == BENIGN) & (gt_arr2 == BENIGN))
                        )
                        fn = int(
                            np.sum(
                                (pvg_arr == BENIGN) & (gt_arr2 == MALICIOUS)
                            )
                        )
                        acc = (
                            (tp + tn) / len(pvg_preds)
                            if len(pvg_preds) > 0
                            else 0.0
                        )
                        self.logger.log_comparison_line(
                            f"pred vs GT: {len(pvg_preds)} samples | "
                            f"Mal/Ben: {mal_pvg}/{ben_pvg} vs {mal_gt2}/{ben_gt2} | "
                            f"TP/FP/TN/FN: {tp}/{fp}/{tn}/{fn} | Acc: {acc:.4f}"
                        )

                self._training_trigger = "twclose"
                self._train_batch()

                target = (
                    "merged_test" if self._using_merged_model else "local_test"
                )
                self.logger.log_test_marker(
                    target,
                    f"New local model ({self._training_trigger}_{self.training_count_twclose})",
                )

            # Clear window for next iteration
            self.window_flows.clear()

        except Exception:
            self.print(
                f"Error handling tw_closed: {traceback.format_exc()}", 0, 1
            )

    def handle_p2p_model(self, model_data: dict):
        """
        Store received model from peer.

        Args:
            model_data: Dict with peer_id and model weights
        """
        try:
            peer_id = model_data.get("peer_id")
            if not peer_id:
                return

            self.peer_models[peer_id] = {
                "fc1_weight": torch.tensor(model_data["fc1_weight"]),
                "fc1_bias": torch.tensor(model_data["fc1_bias"]),
                "head_weight": torch.tensor(model_data["head_weight"]),
                "head_bias": torch.tensor(model_data["head_bias"]),
                "timestamp": model_data.get("timestamp", time.time()),
            }

            self.print(f"Received model from peer {peer_id}", 0, 1)

            # Trigger merge if we have enough peers
            if len(self.peer_models) >= 1:
                self.trigger_merge()

        except Exception:
            self.print(
                f"Error handling P2P model: {traceback.format_exc()}", 0, 1
            )

    def _train_batch(self):
        """Train on accumulated training buffer with configured epochs, log metrics."""
        try:
            if len(self.training_buffer_x) == 0:
                return

            X = np.array(self.training_buffer_x)
            y = np.array(self.training_buffer_y)
            epochs = self.local_training_epochs

            mal_count = int(np.sum(y == MALICIOUS))
            ben_count = int(np.sum(y == BENIGN))

            evidence_count = 0
            counter = (
                self.training_count_alert
                if self._training_trigger == "alert"
                else self.training_count_twclose
            )
            if self._training_trigger == "alert":
                evidence_count = len(
                    getattr(self, "_last_alert_evidence_ids", [])
                )

            self.logger.log_train_header(
                "local_train",
                f"{self._training_trigger}_{counter} | {mal_count} mal ({evidence_count} evidence), {ben_count} ben",
            )

            self.update_preprocessor(pd.DataFrame(X))
            X_scaled = self.scaler.transform(X)

            self.print(
                f"Training for {epochs} epochs on {len(y)} samples",
                0,
                1,
            )
            self.fit_incremental_model(X_scaled, y, train_target="local")

            self._save_local_model()

            self._using_merged_model = False
            self._is_fitted = True

            self.training_buffer_x.clear()
            self.training_buffer_y.clear()

        except Exception:
            self.print(
                f"Error in _train_batch: {traceback.format_exc()}", 0, 1
            )

    def trigger_merge(self):
        """
        Merge all peer models + own latest, retrain head, save merged model.

        Only uses latest local models from each peer (not previous merges).
        """
        try:
            if len(self.peer_models) < 1:
                self.print("Not enough peers to merge", 0, 1)
                return

            self.print(
                f"Merging {len(self.peer_models)} peer models + own model",
                0,
                1,
            )

            self.logger.log_train_header(
                "merged_train",
                f"merge_{self.merge_count + 1} | {len(self.peer_models)} peers: {','.join(self.peer_models.keys())} + own",
            )

            all_fc1_weights = [
                m["fc1_weight"] for m in self.peer_models.values()
            ]
            all_fc1_biases = [m["fc1_bias"] for m in self.peer_models.values()]

            if self.model:
                own_fc1_w, own_fc1_b = self.model.get_fc1_weights()
                all_fc1_weights.append(own_fc1_w)
                all_fc1_biases.append(own_fc1_b)

            merged_fc1_weight = torch.stack(all_fc1_weights).mean(dim=0)
            merged_fc1_bias = torch.stack(all_fc1_biases).mean(dim=0)

            if self.model:
                self.model.set_fc1_weights(merged_fc1_weight, merged_fc1_bias)

            self._align_head_on_buffer()

            self._using_merged_model = True

            self.merge_count += 1
            self._save_merged_model(self.merge_count)

            self.print(
                f"Merged model saved as merged_{self.merge_count}", 0, 1
            )

        except Exception:
            self.print(
                f"Error in trigger_merge: {traceback.format_exc()}", 0, 1
            )

    def _align_head_on_buffer(self):
        """
        Freeze fc1, train head ONLY on alignment buffer with configured epochs.
        """
        try:
            if len(self.alignment_buffer_x) == 0:
                self.print(
                    "Alignment buffer empty, skipping head alignment", 0, 1
                )
                return

            X = np.array(self.alignment_buffer_x)
            y = np.array(self.alignment_buffer_y)

            self.update_preprocessor(pd.DataFrame(X))
            X_scaled = self.scaler.transform(X)

            # Get epochs from instance variable (set in init)
            epochs = self.merge_finetune_epochs

            # Train head ONLY (fc1 frozen) for specified epochs
            self.print(
                f"Fine-tuning head for {epochs} epochs on {len(y)} samples",
                0,
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
                0,
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
            if self.model is None:
                return

            fc1_w, fc1_b = self.model.get_fc1_weights()
            head_w, head_b = self.model.get_head_weights()

            model_data = {
                "fc1_weight": fc1_w.cpu().numpy().tolist(),
                "fc1_bias": fc1_b.cpu().numpy().tolist(),
                "head_weight": head_w.cpu().numpy().tolist(),
                "head_bias": head_b.cpu().numpy().tolist(),
                "timestamp": time.time(),
                "peer_id": getattr(self, "my_peer_id", "unknown"),
            }

            # Publish to P2P module (channel may not exist yet)
            try:
                self.db.publish("p2p_model_outgoing", json.dumps(model_data))
                self.print("Model sent to peers", 0, 1)
            except Exception:
                self.print(
                    "P2P publish channel not available, model not sent",
                    0,
                    1,
                )

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
        Derive ground-truth label from Slips flow metadata.

        Falls back through: ground_truth_label -> label -> None.
        Additionally, in simulation/testing contexts, labels any flow involving
        the attacker IP as MALICIOUS regardless of Slips metadata.
        Remove this block in production deployments.
        """
        # --- MONKEYPATCH: simulation-only attacker IP ---
        # TODO: Remove before production deployment
        saddr = str(flow.get("saddr", ""))
        daddr = str(flow.get("daddr", ""))
        if saddr == "172.20.1.4" or daddr == "172.20.1.4":
            return MALICIOUS
        # --- END MONKEYPATCH ---

        gt_raw = flow.get("ground_truth_label")
        if gt_raw is not None:
            return self._normalize_binary_label(gt_raw)
        gt_raw = flow.get("label")
        if gt_raw is not None:
            return self._normalize_binary_label(gt_raw)
        return None

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
        """Save latest local model weights."""
        try:
            if self.model is None:
                return

            fc1_w, fc1_b = self.model.get_fc1_weights()
            head_w, head_b = self.model.get_head_weights()

            torch.save(fc1_w, self.local_fc1_path)
            torch.save(fc1_b, self.local_fc1_path.replace("_fc1", "_fc1_bias"))
            torch.save(head_w, self.local_head_path)
            torch.save(
                head_b, self.local_head_path.replace("_head", "_head_bias")
            )

            with open(self.local_scaler_path, "wb") as f:
                pickle.dump(self.scaler, f)

        except Exception:
            self.print(
                f"Error saving local model: {traceback.format_exc()}", 0, 1
            )

    def _save_merged_model(self, merge_count: int):
        """Save merged model weights."""
        try:
            if self.model is None:
                return

            fc1_w, fc1_b = self.model.get_fc1_weights()
            head_w, head_b = self.model.get_head_weights()

            prefix = f"merged_{merge_count}"
            torch.save(
                fc1_w, os.path.join(self.merged_dir, f"{prefix}_fc1.bin")
            )
            torch.save(
                fc1_b, os.path.join(self.merged_dir, f"{prefix}_fc1_bias.bin")
            )
            torch.save(
                head_w, os.path.join(self.merged_dir, f"{prefix}_head.bin")
            )
            torch.save(
                head_b,
                os.path.join(self.merged_dir, f"{prefix}_head_bias.bin"),
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
        self._save_local_model()
        if self.merge_count > 0:
            self._save_merged_model(self.merge_count)

    def train(self, sum_labeled_flows):
        """Train entrypoint - delegates to base class."""
        return self._train_default(sum_labeled_flows)

    def run_test_on_flow(self, flow: dict):
        """Test entrypoint - classify flow without creating evidence."""
        try:
            predicted = self._classify_flow(flow)
            if predicted is None:
                return

            ground_truth = flow.get(
                "ground_truth_label",
                flow.get("label", BENIGN),
            )
            self.store_testing_results(ground_truth, predicted)

            src_ip = flow.get("saddr", "unknown")
            dst_ip = flow.get("daddr", "unknown")
            self.print(f"Flow {src_ip}->{dst_ip}: {predicted}", 1, 1)

        except Exception:
            self.print(f"Error testing flow: {traceback.format_exc()}", 0, 1)

    def _write_testing_snapshot(self, batch_flows: int) -> None:
        """Write cumulative TP/FP/TN/FN/Acc snapshot instead of per-flow UIDs."""
        if batch_flows <= 0:
            return
        target = "merged_test" if self._using_merged_model else "local_test"
        tp = self.malware_metrics.get("TP", 0)
        fp = self.malware_metrics.get("FP", 0)
        tn = self.malware_metrics.get("TN", 0)
        fn = self.malware_metrics.get("FN", 0)
        total = tp + fp + tn + fn
        acc = (tp + tn) / total if total > 0 else 0.0
        self.logger.log_test_flow(
            target,
            total,
            self.seen_labels,
            self.predicted_labels,
            tp,
            fp,
            tn,
            fn,
            acc,
        )
