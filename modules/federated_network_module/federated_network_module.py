# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""
Federated Network Module - Simple PyTorch ML detector with frozen random projection.

Architecture: flow_features -> RandomProjection(64,frozen) -> Linear(16)+ReLU -> Linear(2)
Training trigger: new_alert (get evidence, mark connected flows malicious) or tw_closed (all rest benign)
Only flows from last 15-minute window are considered for training.
"""
import json
import os
import time
import traceback
from typing import Optional

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
from slips_files.core.structures.evidence import EvidenceType


class SimpleFederatedNet(nn.Module):
    """
    Simple federated network: frozen random projection + learnable classifier.

    Architecture: input(30) -> RandomProjection(64,frozen,0-1 weights) -> Linear(64->16)+ReLU -> Linear(16->2)
    Random projection and linear layer weights are loaded from artifacts or created with seed.
    """

    def __init__(
        self,
        input_dim: int,
        hidden1: int = 64,
        hidden2: int = 16,
        seed: int = 1111,
        rp_path: Optional[str] = None,
        fc1_path: Optional[str] = None,
    ):
        super().__init__()
        self.seed = seed
        self.hidden1 = hidden1
        self.hidden2 = hidden2

        # Create or load random projection (frozen, 0-1 weights, NOT stochastic)
        if rp_path and os.path.exists(rp_path):
            random_weights = torch.load(rp_path, weights_only=True)
        else:
            torch.manual_seed(seed)
            random_weights = torch.rand(input_dim, hidden1)
            if rp_path:
                os.makedirs(os.path.dirname(rp_path), exist_ok=True)
                torch.save(random_weights, rp_path)

        self.random_projection = nn.Linear(input_dim, hidden1, bias=False)
        self.random_projection.weight.data = random_weights
        self.random_projection.weight.requires_grad = False

        # Create or load first linear layer weights (learnable)
        if fc1_path and os.path.exists(fc1_path):
            fc1_weight = torch.load(fc1_path, weights_only=True)
            fc1_bias = torch.load(
                fc1_path.replace("weight", "bias"), weights_only=True
            )
        else:
            fc1_weight = torch.randn(hidden1, hidden2)
            fc1_bias = torch.randn(hidden2)
            if fc1_path:
                os.makedirs(os.path.dirname(fc1_path), exist_ok=True)
                torch.save(fc1_weight, fc1_path)
                torch.save(fc1_bias, fc1_path.replace("weight", "bias"))

        self.fc1 = nn.Linear(hidden1, hidden2, bias=True)
        self.fc1.weight.data = fc1_weight
        self.fc1.bias.data = fc1_bias

        # Head layer (always created fresh, learnable)
        self.head = nn.Linear(hidden2, 2)

        self.relu = nn.ReLU()

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.random_projection(x)
        x = self.fc1(x)
        x = self.relu(x)
        x = self.head(x)
        return x

    def save_fc1_weights(self, weight_path: str, bias_path: str):
        """Save fc1 layer weights."""
        os.makedirs(os.path.dirname(weight_path), exist_ok=True)
        torch.save(self.fc1.weight.data, weight_path)
        torch.save(self.fc1.bias.data, bias_path)


class FederatedNetworkModule(MLBaseDetection):
    """
    Federated network ML flow detector using PyTorch with frozen random projection.

    Training is triggered by:
    1. New alert: get evidence, find connected flows in current 15-min window, mark as malicious
    2. Time window closed: all remaining unlabeled flows in window are benign, then train

    Only flows from the last 15-minute window are used for training.
    """

    name = "federated_network_module"
    description = "Federated network ML detector with frozen random projection"
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

    # 15 minutes in seconds
    WINDOW_SIZE_SECONDS = 900

    def init(self):
        """Initialize module, model, preprocessor, and training state."""
        super().init()

        self.input_dim = 30  # Fixed input dimension

        # Artifact paths for random projection and fc1 weights
        artifacts_dir = os.path.join(
            ".", "modules", "federated_network_module", "artifacts"
        )
        os.makedirs(artifacts_dir, exist_ok=True)
        self.rp_path = os.path.join(artifacts_dir, "random_projection.pt")
        self.fc1_weight_path = os.path.join(artifacts_dir, "fc1_weight.pt")
        self.fc1_bias_path = os.path.join(artifacts_dir, "fc1_bias.pt")

        # Initialize model and preprocessor
        self.model: Optional[SimpleFederatedNet] = None
        self.scaler = StandardScaler()
        self.is_preprocessor_fitted = False

        # Training state
        self.optimizer = None
        self.criterion = nn.CrossEntropyLoss()

        # Flow buffers for training (only current window)
        self.flow_buffer_x: list = []
        self.flow_buffer_y: list = []
        self.flow_buffer_metadata: list = []

        # Track which flows have been labeled
        self.labeled_flow_ids: set = set()

        # Current window flows (for labeling as benign when window closes)
        self.current_window_flows: dict = {}  # flow_id -> flow_dict

        # Device
        self.device = torch.device(
            "cuda" if torch.cuda.is_available() else "cpu"
        )

        # Loss logging
        self.last_batch_loss: float = 0.0

        # Current time window ID
        self.current_tw_id: Optional[int] = None

    def subscribe_to_channels(self):
        """Subscribe to flows, alerts, and time window closed events."""
        self.c_flows = self.db.subscribe("new_flow")
        self.c_alerts = self.db.subscribe("new_alert")
        self.c_tw_closed = self.db.subscribe("tw_closed")
        self.channels = {
            "new_flow": self.c_flows,
            "new_alert": self.c_alerts,
            "tw_closed": self.c_tw_closed,
        }

    def create_empty_model(self) -> SimpleFederatedNet:
        """Create model with frozen random projection from artifacts."""
        return SimpleFederatedNet(
            self.input_dim,
            seed=self.seed,
            rp_path=self.rp_path,
            fc1_path=self.fc1_weight_path,
        )

    def create_empty_preprocessor(self) -> StandardScaler:
        """Create untrained scaler."""
        return StandardScaler()

    def update_preprocessor(self, x_train: pd.DataFrame):
        """Fit scaler on training data."""
        self.scaler.fit(x_train.fillna(0))
        self.is_preprocessor_fitted = True

    def transform_features(self, x_data: pd.DataFrame) -> np.ndarray:
        """Transform features to normalized numpy array."""
        if not self.is_preprocessor_fitted:
            self.update_preprocessor(x_data)
        return self.scaler.transform(x_data.fillna(0)).astype(np.float32)

    def process_features(self, dataset: pd.DataFrame) -> pd.DataFrame:
        """Keep numerical features, fill NaN with 0."""
        numerical_cols = dataset.select_dtypes(include=[np.number]).columns
        return dataset[numerical_cols].fillna(0)

    def fit_incremental_model(
        self,
        x_train: np.ndarray,
        y_train: np.ndarray,
        classes: Optional[list] = None,
    ):
        """Train model on one batch using backprop with cross-entropy loss."""
        if self.model is None:
            self.model = self.create_empty_model().to(self.device)
            self.optimizer = optim.Adam(self.model.parameters(), lr=0.001)

        X_tensor = torch.FloatTensor(x_train).to(self.device)
        y_tensor = torch.LongTensor(
            [0 if y == BENIGN else 1 for y in y_train]
        ).to(self.device)

        self.model.train()
        self.optimizer.zero_grad()
        outputs = self.model(X_tensor)
        loss = self.criterion(outputs, y_tensor)
        loss.backward()
        self.optimizer.step()

        self.last_batch_loss = loss.item()

        # Save fc1 weights after each batch
        if self.model_path:
            self.model.save_fc1_weights(
                self.fc1_weight_path, self.fc1_bias_path
            )
            # Also save full model state
            torch.save(self.model.state_dict(), self.model_path)
        if self.scaler_path:
            import pickle

            with open(self.scaler_path, "wb") as f:
                pickle.dump(self.scaler, f)

    def predict_batch(self, x_data: np.ndarray) -> np.ndarray:
        """Predict labels for a batch of samples."""
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

    def run(self):
        """Main loop - handle flows, alerts, and time window events."""
        try:
            if self.mode == "train":
                self.run_training_loop()
            elif self.mode == "test":
                self.run_testing_loop()
        except Exception:
            self.print(f"Error in run(): {traceback.format_exc()}", 0, 1)

    def run_training_loop(self):
        """Training loop triggered by alerts and time window closure."""
        self.print("Starting federated_network_module in TRAIN mode", 0, 1)

        while True:
            # Check for new alerts (trigger malicious flow collection)
            if msg := self.get_msg("new_alert"):
                self.handle_new_alert(json.loads(msg["data"]))

            # Check for time window closed
            if msg := self.get_msg("tw_closed"):
                self.handle_tw_closed(json.loads(msg["data"]))

            # Train if we have enough labeled data
            if len(self.flow_buffer_y) >= self.batch_size:
                self.train_batch()

            time.sleep(0.1)

    def run_testing_loop(self):
        """Testing loop - classify incoming flows."""
        self.print("Starting federated_network_module in TEST mode", 0, 1)

        test_count = 0
        while True:
            if msg := self.get_msg("new_flow"):
                flow = json.loads(msg["data"])
                self.run_test_on_flow(flow)
                test_count += 1
                if test_count % self.testing_log_batch_size == 0:
                    self.print(f"Tested {test_count} flows", 0, 1)

            time.sleep(0.1)

    def handle_new_alert(self, alert: dict):
        """
        Handle new alert by getting evidence and marking connected flows as malicious.
        Only considers flows from the current 15-minute window.

        Args:
            alert: Alert dictionary containing evidence about malicious activity
        """
        try:
            # Get evidence from the alert
            evidence_list = self.db.get_evidence_from_alert(alert)

            if not evidence_list:
                return

            self.print(
                f"Alert received with {len(evidence_list)} evidence items",
                0,
                1,
            )

            # For each evidence, find connected flows in current window
            for evidence in evidence_list:
                # Get IPs from evidence
                attacker_ip = getattr(evidence, "attacker", None)
                victim_ip = getattr(evidence, "victim", None)

                attacker_ip = attacker_ip.ip if attacker_ip else None
                victim_ip = victim_ip.ip if victim_ip else None

                if not attacker_ip and not victim_ip:
                    continue

                # Find flows connected to this evidence in current window
                related_flows = self.get_flows_for_evidence_in_window(
                    attacker_ip, victim_ip
                )

                for flow in related_flows:
                    flow_id = self.get_flow_id(flow)
                    if flow_id not in self.labeled_flow_ids:
                        x, y = self.process_flow_for_training(flow, MALICIOUS)
                        if x is not None:
                            self.flow_buffer_x.append(x)
                            self.flow_buffer_y.append(y)
                            self.flow_buffer_metadata.append(flow)
                            self.labeled_flow_ids.add(flow_id)

            self.print(
                f"Collected {len(self.flow_buffer_y)} malicious flows so far",
                0,
                1,
            )

        except Exception:
            self.print(f"Error handling alert: {traceback.format_exc()}", 0, 1)

    def handle_tw_closed(self, tw_data: dict):
        """
        Handle time window closure by labeling remaining flows as benign and training.
        Only processes flows from the closed window.

        Args:
            tw_data: Time window closure data
        """
        try:
            tw_id = tw_data.get("id") or self.db.get_current_time_window_id()
            tw_start = tw_data.get("start_time", 0)
            tw_end = tw_data.get("end_time", time.time())

            self.print(
                f"Time window {tw_id} closed ({tw_end - tw_start:.0f}s), "
                f"labeling {len(self.current_window_flows) - len(self.labeled_flow_ids)} flows as benign",
                0,
                1,
            )

            # Label all unlabeled flows in this window as benign
            for flow_id, flow in self.current_window_flows.items():
                if flow_id not in self.labeled_flow_ids:
                    x, y = self.process_flow_for_training(flow, BENIGN)
                    if x is not None:
                        self.flow_buffer_x.append(x)
                        self.flow_buffer_y.append(y)
                        self.flow_buffer_metadata.append(flow)

                self.labeled_flow_ids.add(flow_id)

            # Clear current window flows
            self.current_window_flows.clear()

            # Train on accumulated data
            if len(self.flow_buffer_y) >= self.minimum_labels_to_retrain:
                self.train_batch()

        except Exception:
            self.print(
                f"Error handling tw_closed: {traceback.format_exc()}", 0, 1
            )

    def get_flows_for_evidence_in_window(
        self, attacker_ip: Optional[str], victim_ip: Optional[str]
    ) -> list:
        """
        Get flows connected to evidence that are in the current 15-minute window.

        Args:
            attacker_ip: Source IP from evidence
            victim_ip: Destination IP from evidence

        Returns:
            List of flow dictionaries matching the criteria
        """
        related = []
        current_time = time.time()
        window_start = current_time - self.WINDOW_SIZE_SECONDS

        for flow_id, flow in self.current_window_flows.items():
            flow_time = flow.get("starttime", 0)

            # Ensure flow is within current window
            if flow_time < window_start or flow_time > current_time:
                continue

            saddr = flow.get("saddr", "")
            daddr = flow.get("daddr", "")

            # Check if flow matches evidence IPs
            if attacker_ip and saddr == attacker_ip:
                related.append(flow)
            elif victim_ip and daddr == victim_ip:
                related.append(flow)
            elif attacker_ip and daddr == attacker_ip:
                related.append(flow)
            elif victim_ip and saddr == victim_ip:
                related.append(flow)

        return related

    def train_batch(self):
        """Train on accumulated batch and log results."""
        try:
            if len(self.flow_buffer_x) == 0:
                return

            X = np.array(self.flow_buffer_x)
            y = np.array(self.flow_buffer_y)

            # Scale features
            if not self.is_preprocessor_fitted:
                self.update_preprocessor(pd.DataFrame(X))
            X_scaled = self.scaler.transform(X)

            # Train
            self.fit_incremental_model(X_scaled, y)

            # Log
            acc = self.compute_accuracy(X_scaled, y)
            self.write_to_log(
                f"Batch trained. Loss: {self.last_batch_loss:.4f}, "
                f"Accuracy: {acc:.4f}, Samples: {len(y)}, "
                f"Malicious: {sum(1 for label in y if label == MALICIOUS)}, "
                f"Benign: {sum(1 for label in y if label == BENIGN)}"
            )

            # Clear buffer
            self.flow_buffer_x.clear()
            self.flow_buffer_y.clear()
            self.flow_buffer_metadata.clear()

        except Exception:
            self.print(f"Error in train_batch: {traceback.format_exc()}", 0, 1)

    def process_flow_for_training(self, flow: dict, label: str) -> tuple:
        """
        Process a flow into features and label.

        Args:
            flow: Flow dictionary
            label: BENIGN or MALICIOUS

        Returns:
            Tuple of (feature_array, label) or (None, None) if invalid
        """
        try:
            features = self.extract_flow_features(flow)
            if features is None or len(features) == 0:
                return None, None
            return np.array(features, dtype=np.float32), label
        except Exception:
            return None, None

    def extract_flow_features(self, flow: dict) -> Optional[list]:
        """Extract numerical features from a flow."""
        try:
            feature_names = [
                "dur",
                "src_bytes",
                "dst_bytes",
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
                "wrong_fragment",
                "urgent",
                "hot",
                "num_failed_logins",
                "logged_in",
                "compromised",
                "root_shell",
                "su_attempted",
                "num_root",
                "num_file_creations",
                "num_shells",
                "num_access_files",
                "num_outbound_cmds",
                "is_host_login",
                "is_guest_login",
                "protocol_type_num",
                "service_num",
                "flag_num",
                "land",
                "syn_flag",
                "ack_flag",
                "fin_flag",
                "rst_flag",
                "psh_flag",
                "urg_flag",
            ]

            features = []
            for feat in feature_names[: self.input_dim]:
                val = flow.get(feat, 0)
                features.append(
                    float(val) if isinstance(val, (int, float)) else 0.0
                )
            return features
        except Exception:
            return None

    def get_flow_id(self, flow: dict) -> str:
        """Generate unique ID for a flow."""
        return f"{flow.get('saddr', '')}:{flow.get('sport', '')}-{flow.get('daddr', '')}:{flow.get('dport', '')}-{flow.get('starttime', '')}"

    def compute_accuracy(self, X: np.ndarray, y: np.ndarray) -> float:
        """Compute accuracy on given data."""
        preds = self.predict_batch(X)
        correct = sum(1 for p, t in zip(preds, y) if p == t)
        return correct / len(y) if len(y) > 0 else 0.0

    def train(self, sum_labeled_flows):
        """Train entrypoint - delegates to base class."""
        return self._train_default(sum_labeled_flows)

    def run_test_on_flow(self, flow: dict):
        """Test entrypoint - classify flow without creating evidence."""
        try:
            if self.model is None or not self.is_preprocessor_fitted:
                return

            features = self.extract_flow_features(flow)
            if features is None:
                return

            X = np.array([features], dtype=np.float32)
            X_scaled = self.scaler.transform(X)
            prediction = self.predict_batch(X_scaled)[0]

            # Log prediction (no evidence creation in test mode)
            src_ip = flow.get("saddr", "unknown")
            dst_ip = flow.get("daddr", "unknown")
            self.print(f"Flow {src_ip}->{dst_ip}: {prediction}", 1, 1)

        except Exception:
            self.print(f"Error testing flow: {traceback.format_exc()}", 0, 1)
