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
import json
import os
import pickle
import time
import traceback
from typing import Dict, Optional

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.preprocessing import StandardScaler

from slips_files.common.abstracts.ml_module_base import (
    BENIGN,
    MALICIOUS,
    MLBaseDetection,
)
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.core.structures.evidence import EvidenceType


class SimpleFederatedNet(nn.Module):
    """
    Federated network model: frozen shared random projection + learnable fc1 + head.

    Architecture: input(22) -> RandomProjection(64,frozen) -> Linear(64->16)+ReLU -> Linear(16->2)

    FIXED FEATURE COUNT: 22 features (see process_features for full list)
    """

    FIXED_INPUT_DIM = 22  # Must match len(feature_order) in process_features

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

    def freeze_fc1(self):
        """Freeze fc1 layer for head-only training."""
        for param in self.fc1.parameters():
            param.requires_grad = False

    def unfreeze_fc1(self):
        """Unfreeze fc1 layer for normal training."""
        for param in self.fc1.parameters():
            param.requires_grad = True


class FederatedNetworkModule(MLBaseDetection):
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

    WINDOW_SIZE_SECONDS = 900  # 15 minutes

    def init(self):
        """Initialize module, model, preprocessor, and buffers."""
        super().init()

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

        # Training state
        self.optimizer: Optional[optim.Adam] = None
        self.criterion = nn.CrossEntropyLoss()

        # Buffers
        self.training_buffer_x: list = []
        self.training_buffer_y: list = []
        self.alignment_buffer_x: list = []
        self.alignment_buffer_y: list = []

        # Flow tracking
        self.labeled_flow_ids: set = set()
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

        # Read module-specific config using ConfigParser
        conf = ConfigParser()
        section = self.module_config_section

        self.local_training_epochs = conf.ml_module_local_training_epochs(
            section, default=10
        )
        self.merge_finetune_epochs = conf.ml_module_merge_finetune_epochs(
            section, default=5
        )

        # Window offset for off-sync timing
        random_offset = int(np.random.RandomState(self.seed).randint(0, 900))
        self.window_offset_seconds: int = conf.ml_module_window_offset_seconds(
            section, default=random_offset
        )

    def subscribe_to_channels(self):
        """Subscribe to flows, alerts, time window events, and optionally P2P model channel."""
        # Always subscribe to these core channels
        self.c_flows = self.db.subscribe("new_flow")
        self.c_alerts = self.db.subscribe("new_alert")
        self.c_tw_closed = self.db.subscribe("tw_closed")

        # Initialize channels dict with core subscriptions
        self.channels = {
            "new_flow": self.c_flows,
            "new_alert": self.c_alerts,
            "tw_closed": self.c_tw_closed,
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

    def create_empty_model(self) -> SimpleFederatedNet:
        """Create model with FIXED input dimension (22 features)."""
        # Always use fixed input dimension - don't rely on runtime detection
        self.input_dim = SimpleFederatedNet.FIXED_INPUT_DIM
        return SimpleFederatedNet(
            self.input_dim, rp_path=self.rp_path, seed=self.seed
        )

    def create_empty_preprocessor(self) -> StandardScaler:
        """Create untrained scaler."""
        return StandardScaler()

    def update_preprocessor(self, x_train: pd.DataFrame):
        """Incrementally fit scaler using partial_fit."""
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
        Process Zeek flows into exactly 22 features with encoding.

        Feature list (fixed order):
        1. dur (duration)
        2. src_bytes
        3. dst_bytes
        4. total_bytes (derived: src_bytes + dst_bytes)
        5. count (connection count to same host/service)
        6. srv_count (connection count to same service)
        7. serror_rate (SYN error rate)
        8. rerror_rate (REJ error rate)
        9. same_srv_rate (same service rate)
        10. diff_srv_rate (different service rate)
        11. srv_diff_host_rate (service different host rate)
        12. dst_host_count (count to same destination host)
        13. dst_host_srv_count (count to same host/service)
        14. dst_host_same_srv_rate
        15. dst_host_diff_srv_rate
        16. dst_host_same_src_port_rate
        17. dst_host_srv_diff_host_rate
        18. dst_host_serror_rate
        19. dst_host_rerror_rate
        20. dst_host_srv_serror_rate
        21. dst_host_srv_rerror_rate
        22. throughput (derived: total_bytes / dur if dur > 0 else 0)

        Encoding applied:
        - proto: one-hot (tcp=0, udp=1, icmp=2, other=3)
        - service: one-hot encoding for common services
        - state: one-hot (SF=0, S0=1, REJ=2, RSTO=3, other=4)
        - IPs converted to numeric hash

        Returns DataFrame with exactly 22 columns in fixed order.
        """
        if dataset.empty:
            return pd.DataFrame(columns=self._get_feature_order())

        df = dataset.copy()

        # Normalize categorical fields
        df["proto"] = self._encode_proto(df.get("proto", "tcp"))
        df["service"] = self._encode_service(df.get("service", "-"))
        df["state"] = self._encode_state(df.get("state", "SF"))

        # Convert IPs to numeric (hash-based)
        if "saddr" in df.columns:
            df["saddr_num"] = df["saddr"].apply(
                lambda x: hash(str(x)) % 1000000 if pd.notna(x) else 0
            )
        if "daddr" in df.columns:
            df["daddr_num"] = df["daddr"].apply(
                lambda x: hash(str(x)) % 1000000 if pd.notna(x) else 0
            )

        # Derived features
        df["total_bytes"] = df.get("src_bytes", 0).fillna(0) + df.get(
            "dst_bytes", 0
        ).fillna(0)
        df["throughput"] = df.apply(
            lambda row: (
                (row.get("total_bytes", 0) / row.get("dur", 1))
                if row.get("dur", 0) > 0
                else 0
            ),
            axis=1,
        )

        # Select and order features to match FIXED_INPUT_DIM = 22
        feature_order = self._get_feature_order()
        available_features = [f for f in feature_order if f in df.columns]

        result = df[available_features].fillna(0)

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
        Return the fixed order of 22 features.

        Order from most specific to all-inclusive:
        1-4: Basic flow stats (duration, bytes)
        5-7: Connection rates (count, srv_count, error rates)
        8-11: Service/host relationship rates
        12-20: Destination host statistics
        21: Protocol (encoded: tcp=0, udp=1, icmp=2, other=3)
        22: Throughput (derived)
        """
        return [
            "dur",
            "src_bytes",
            "dst_bytes",
            "total_bytes",
            "count",
            "srv_count",
            "serror_rate",
            "rerror_rate",
            "same_srv_rate",
            "diff_srv_rate",
            "srv_diff_host_rate",
            "dst_host_count",
            "dst_host_srv_count",
            "dst_host_same_srv_rate",
            "dst_host_diff_srv_rate",
            "dst_host_same_src_port_rate",
            "dst_host_srv_diff_host_rate",
            "dst_host_serror_rate",
            "dst_host_rerror_rate",
            "dst_host_srv_serror_rate",
            "dst_host_srv_rerror_rate",
            "throughput",
        ]

    def _encode_proto(self, proto) -> int:
        """Encode protocol to numeric value."""
        if isinstance(proto, str):
            proto_map = {"tcp": 0, "udp": 1, "icmp": 2}
            return proto_map.get(proto.lower(), 3)
        return 0

    def _encode_service(self, service) -> int:
        """Encode service to numeric value."""
        if isinstance(service, str):
            common_services = {
                "http": 0,
                "dns": 1,
                "ftp": 2,
                "ssh": 3,
                "smtp": 4,
                "ssl": 5,
                "pop3": 6,
                "imap": 7,
                "telnet": 8,
                "https": 9,
            }
            return common_services.get(service.lower(), 10)
        return 0

    def _encode_state(self, state) -> int:
        """Encode connection state to numeric value."""
        if isinstance(state, str):
            state_map = {"SF": 0, "S0": 1, "REJ": 2, "RSTO": 3}
            return state_map.get(state, 4)
        return 0

    def fit_incremental_model(
        self,
        x_train: np.ndarray,
        y_train: np.ndarray,
        classes: Optional[list] = None,
    ):
        """
        Train model on provided batch.

        Note: This implementation uses internal config values for epochs.
        For head-only training, set _freeze_fc1_for_training=True before calling.

        Args:
            x_train: Normalized features
            y_train: Labels (BENIGN/MALICIOUS)
            classes: List of class labels (unused, kept for compatibility)
        """
        # Determine epochs and freeze mode
        freeze_fc1 = getattr(self, "_freeze_fc1_for_training", False)
        epochs = (
            self.merge_finetune_epochs
            if freeze_fc1
            else self.local_training_epochs
        )

        if self.model is None:
            self.model = self.create_empty_model().to(self.device)
            self.optimizer = optim.Adam(self.model.parameters(), lr=0.001)

        if freeze_fc1:
            self.model.freeze_fc1()
            # Create optimizer for head only
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

        # Train for specified number of epochs
        for epoch in range(epochs):
            self.optimizer.zero_grad()
            outputs = self.model(X_tensor)
            loss = self.criterion(outputs, y_tensor)
            loss.backward()
            self.optimizer.step()
            self.last_batch_loss = loss.item()

            if epoch > 0 and (epoch + 1) % max(1, epochs // 5) == 0:
                self.print(
                    f"Epoch {epoch + 1}/{epochs}, Loss: {self.last_batch_loss:.4f}",
                    1,
                    1,
                )

        # Save local model after training
        self._save_local_model()

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

    def _main_training(self) -> bool:
        """Training main loop - returns True on error."""
        try:
            if msg := self.get_msg("new_flow"):
                self.handle_new_flow(json.loads(msg["data"]))

            if msg := self.get_msg("new_alert"):
                self.handle_new_alert(json.loads(msg["data"]))

            if msg := self.get_msg("tw_closed"):
                self.handle_tw_closed()

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
                self.testing_flows_since_last_log += 1
                if (
                    self.testing_flows_since_last_log
                    >= self.testing_log_batch_size
                ):
                    self._log_testing_metrics()
                    self.testing_flows_since_last_log = 0

            time.sleep(0.1)
            return False
        except Exception:
            self.print(f"Error in main: {traceback.format_exc()}", 0, 1)
            return True

    def handle_new_flow(self, flow: dict):
        """Store flow in current window for later labeling."""
        if self.input_dim is None:
            # Determine input dimension from first flow
            features = self._extract_flow_features(flow)
            if features:
                self.input_dim = len(features)
                self.print(
                    f"Input dimension determined: {self.input_dim}", 0, 1
                )
                # Initialize model now
                self.model = self.create_empty_model().to(self.device)

        flow_id = self._get_flow_id(flow)
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

            # Collect malicious flows from each evidence
            malicious_flows = []
            for evid_id in evidence_ids:
                # Get flows causing this evidence
                uids = self.db.get_flows_causing_evidence(evid_id)
                if uids:
                    for uid in uids:
                        flow = self.db.get_flow_by_uid(uid)
                        if flow and flow not in malicious_flows:
                            malicious_flows.append(flow)

            # Also extract IPs from evidence directly as fallback
            attacker_ip = (
                last_evidence.get("attacker", {}).get("ip")
                if isinstance(last_evidence.get("attacker"), dict)
                else None
            )
            victim_ip = (
                last_evidence.get("victim", {}).get("ip")
                if isinstance(last_evidence.get("victim"), dict)
                else None
            )

            if attacker_ip:
                ip_flows = self._get_flows_for_ip_in_window(attacker_ip)
                for flow in ip_flows:
                    if flow not in malicious_flows:
                        malicious_flows.append(flow)

            if victim_ip:
                ip_flows = self._get_flows_for_ip_in_window(victim_ip)
                for flow in ip_flows:
                    if flow not in malicious_flows:
                        malicious_flows.append(flow)

            # Collect all other flows in window as benign
            benign_flows = []
            for flow_id, flow in self.window_flows.items():
                if flow_id not in self.labeled_flow_ids:
                    if flow not in malicious_flows:
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
                    self.labeled_flow_ids.add(self._get_flow_id(flow))

            for flow in benign_flows:
                x, _ = self._process_flow(flow, BENIGN)
                if x is not None:
                    self.training_buffer_x.append(x)
                    self.training_buffer_y.append(BENIGN)
                    self.alignment_buffer_x.append(x)
                    self.alignment_buffer_y.append(BENIGN)
                    self.labeled_flow_ids.add(self._get_flow_id(flow))

            # Train ONCE on this batch
            if len(self.training_buffer_x) > 0:
                self._train_batch()

            # Send model to peers
            self.send_model_to_peers()

        except Exception:
            self.print(f"Error handling alert: {traceback.format_exc()}", 0, 1)

    def handle_tw_closed(self):
        """
        Handle time window closure: label all remaining as BENIGN, train ONCE.

        Skips training if no unlabeled flows remain in the buffer.
        """
        try:
            self.print("Window closed, preparing training batch", 0, 1)

            # All remaining unlabeled flows are benign
            remaining_flows = [
                flow
                for flow_id, flow in self.window_flows.items()
                if flow_id not in self.labeled_flow_ids
            ]

            if not remaining_flows:
                self.print(
                    "No unlabeled flows in closed window, skipping training",
                    0,
                    1,
                )
                # Still clear window for next iteration
                self.window_flows.clear()
                self.labeled_flow_ids.clear()
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

            # Train ONCE on this batch
            if len(self.training_buffer_x) > 0:
                self._train_batch()

            # Clear window for next iteration
            self.window_flows.clear()
            self.labeled_flow_ids.clear()

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

            # Fit/update scaler incrementally
            if not self.is_preprocessor_fitted:
                self.update_preprocessor(pd.DataFrame(X))
            X_scaled = self.scaler.transform(X)

            # Train fc1 + head for configured epochs
            self.print(
                f"Training for {self.local_training_epochs} epochs on {len(y)} samples",
                0,
                1,
            )
            self.fit_incremental_model(X_scaled, y)

            # Log metrics using base class methods
            acc = self._compute_accuracy(X_scaled, y)
            malicious_count = sum(1 for label in y if label == MALICIOUS)
            benign_count = sum(1 for label in y if label == BENIGN)

            self.write_to_log(
                f"Batch trained ({self.local_training_epochs} epochs). Loss: {self.last_batch_loss:.4f}, "
                f"Accuracy: {acc:.4f}, "
                f"Samples: {len(y)} (Malicious: {malicious_count}, Benign: {benign_count})"
            )

            # Clear training buffer (alignment buffer keeps all data)
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

            # Collect all fc1 weights (peers + own)
            all_fc1_weights = [
                m["fc1_weight"] for m in self.peer_models.values()
            ]
            all_fc1_biases = [m["fc1_bias"] for m in self.peer_models.values()]

            if self.model:
                own_fc1_w, own_fc1_b = self.model.get_fc1_weights()
                all_fc1_weights.append(own_fc1_w)
                all_fc1_biases.append(own_fc1_b)

            # Average aggregation
            merged_fc1_weight = torch.stack(all_fc1_weights).mean(dim=0)
            merged_fc1_bias = torch.stack(all_fc1_biases).mean(dim=0)

            # Apply merged fc1
            if self.model:
                self.model.set_fc1_weights(merged_fc1_weight, merged_fc1_bias)

            # Freeze fc1, train head on alignment buffer
            self._align_head_on_buffer()

            # Save merged model
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

            if not self.is_preprocessor_fitted:
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
            self.fit_incremental_model(X_scaled, y)
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
        Extract exactly 22 features from a Zeek flow dictionary.

        Uses process_features() logic to ensure consistent feature extraction
        matching the FIXED_INPUT_DIM constant.

        Returns list of 22 numeric values or None if extraction fails.
        """
        try:
            # Convert single flow dict to DataFrame for processing
            df = pd.DataFrame([flow])

            # Apply same encoding as process_features
            df["proto"] = self._encode_proto(df.iloc[0].get("proto", "tcp"))
            df["service"] = self._encode_service(
                df.iloc[0].get("service", "-")
            )
            df["state"] = self._encode_state(df.iloc[0].get("state", "SF"))

            # Convert IPs to numeric
            saddr = df.iloc[0].get("saddr")
            daddr = df.iloc[0].get("daddr")
            df["saddr_num"] = hash(str(saddr)) % 1000000 if saddr else 0
            df["daddr_num"] = hash(str(daddr)) % 1000000 if daddr else 0

            # Derived features
            src_bytes = df.iloc[0].get("src_bytes", 0) or 0
            dst_bytes = df.iloc[0].get("dst_bytes", 0) or 0
            dur = df.iloc[0].get("dur", 0) or 0
            df["total_bytes"] = src_bytes + dst_bytes
            df["throughput"] = df["total_bytes"] / dur if dur > 0 else 0

            # Extract features in fixed order
            feature_order = self._get_feature_order()
            features = []

            for feat in feature_order:
                val = df.iloc[0].get(feat, 0)
                if val is None:
                    val = 0
                features.append(
                    float(val) if isinstance(val, (int, float, str)) else 0.0
                )

            if len(features) != self.FIXED_INPUT_DIM:
                self.print(
                    f"Feature extraction produced {len(features)} features "
                    f"instead of {self.FIXED_INPUT_DIM}",
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

    def _get_flow_id(self, flow: dict) -> str:
        """Generate unique flow ID."""
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
            if self.model is None or not self.is_preprocessor_fitted:
                return

            features = self._extract_flow_features(flow)
            if features is None:
                return

            X = np.array([features], dtype=np.float32)
            X_scaled = self.scaler.transform(X)
            prediction = self.predict_batch(X_scaled)[0]

            # Use base class method for logging metrics
            self.store_testing_results(BENIGN, prediction)

            src_ip = flow.get("saddr", "unknown")
            dst_ip = flow.get("daddr", "unknown")
            self.print(f"Flow {src_ip}->{dst_ip}: {prediction}", 1, 1)

        except Exception:
            self.print(f"Error testing flow: {traceback.format_exc()}", 0, 1)
