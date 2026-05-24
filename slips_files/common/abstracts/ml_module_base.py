import json
import ipaddress
import os
import pickle
import random
import traceback
from abc import ABC, abstractmethod
from typing import Any, Optional

import numpy
import pandas as pd

from slips_files.common.abstracts.imodule import IModule
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from slips_files.core.structures.evidence import (
    Attacker,
    Direction,
    Evidence,
    EvidenceType,
    IoCType,
    Method,
    ProfileID,
    ThreatLevel,
    TimeWindow,
    Victim,
)

BACKGROUND = "Background"
BENIGN = "Benign"
MALICIOUS = "Malicious"


class MLBaseDetection(IModule, ABC):
    """
    Generic base class for standalone ML detection modules.

    Subclasses implement only model specific pieces:
      - feature processing
      - model/preprocessor creation
      - incremental fit and inference
    """

    name = "imodule"
    description = (
        "Train or test a Machine Learning model to detect malicious flows"
    )
    authors = ["Jan Svoboda"]
    module_key = "ml_module"
    module_config_section = "ml_module"
    malicious_flow_evidence_type = None
    malicious_flow_description_template = (
        "Flow with malicious characteristics detected by {module_name}. "
        "Src IP {src_ip}:{sport} to {dst_ip}:{dport}"
    )

    def subscribe_to_channels(self):
        self.c1 = self.db.subscribe("new_flow")
        self.channels = {"new_flow": self.c1}
        if self.mode == "train":
            self.c2 = self.db.subscribe("tw_closed")
            self.channels["tw_closed"] = self.c2

    def init(self):
        """Initialize channels, config, reproducibility, artifact paths, and logging."""
        self.fieldseparator = self.db.get_field_separator()

        if not isinstance(self.malicious_flow_evidence_type, EvidenceType):
            raise ValueError(
                "ML modules must define malicious_flow_evidence_type as a module-specific EvidenceType."
            )
        if not isinstance(self.malicious_flow_description_template, str) or (
            not self.malicious_flow_description_template.strip()
        ):
            raise ValueError(
                "ML modules must define malicious_flow_description_template as a non-empty string."
            )

        self.read_configuration()

        self.classifier_initialized = False
        self.all_classes = [MALICIOUS, BENIGN]

        self.labeled_counter = 0
        self.training_flows = []
        self.testing_flows_since_last_log = 0
        self.last_closed_twid = None

        conf = ConfigParser()
        section = self.module_config_section
        configured_model_load = conf.ml_module_model_load_path(
            section,
            None,
        )
        configured_preprocess_load = conf.ml_module_preprocess_load_path(
            section,
            None,
        )
        configured_model_store = conf.ml_module_model_store_path(
            section,
            None,
        )
        configured_preprocess_store = conf.ml_module_preprocess_store_path(
            section,
            None,
        )

        configured_seed = conf.ml_module_seed(section, default=self.seed)
        self.seed = int(configured_seed)
        random.seed(self.seed)
        numpy.random.seed(self.seed)
        self.rng = numpy.random.default_rng(self.seed)

        self.model_load_path = self.resolve_artifact_path(
            explicit_path=configured_model_load,
        )
        self.preprocess_load_path = self.resolve_artifact_path(
            explicit_path=configured_preprocess_load,
        )
        self.model_path = self.resolve_artifact_path(
            explicit_path=configured_model_store,
        )
        self.preprocess_path = self.resolve_artifact_path(
            explicit_path=configured_preprocess_store,
        )

        configured_test_log_batch_size = conf.ml_module_test_log_batch_size(
            section,
            default=self.batch_size,
        )
        self.testing_log_batch_size = max(
            1, int(configured_test_log_batch_size)
        )

        configured_log_suffix = conf.ml_module_log_suffix(
            section,
            default=self.module_key,
        )
        self.log_suffix = configured_log_suffix

        # Backward compatibility for existing sklearn-specific references.
        self.scaler_load_path = self.preprocess_load_path
        self.scaler_path = self.preprocess_path

        self.init_log_file()

    def resolve_artifact_path(
        self,
        explicit_path: Optional[str],
        env_var: Optional[str] = None,
        fallback_env_var: Optional[str] = None,
    ) -> str:
        """Resolve artifact path from config and normalize relative paths."""
        _ = env_var
        _ = fallback_env_var
        if explicit_path is None or str(explicit_path).strip() == "":
            raise ValueError(
                "Missing ML artifact path in slips.yaml. "
                "Set model/preprocess load/store paths in the module config section."
            )
        path = str(explicit_path)
        if os.path.isabs(path):
            return path
        return os.path.join(".", path.lstrip("./"))

    @staticmethod
    def _to_bool(value, default: bool) -> bool:
        """Convert common string/number representations into bool with fallback."""
        if isinstance(value, bool):
            return value
        if value is None:
            return default
        if isinstance(value, (int, float)):
            return bool(value)
        text = str(value).strip().lower()
        if text in {"1", "true", "yes", "y", "on"}:
            return True
        if text in {"0", "false", "no", "n", "off"}:
            return False
        return default

    def init_log_file(self):
        """Open train/test performance log file for the active module mode."""
        if not self.enable_logs:
            self.log_file = None
            return

        suffix = self.log_suffix.strip()
        if suffix:
            training_filename = f"training_{suffix}.log"
            testing_filename = f"testing_{suffix}.log"
        else:
            training_filename = "training.log"
            testing_filename = "testing.log"

        if self.mode == "train":
            log_path = os.path.join(self.output_dir, training_filename)
        else:
            log_path = os.path.join(self.output_dir, testing_filename)

        os.makedirs(self.output_dir, exist_ok=True)
        self.log_file = open(log_path, "w")

        self.print(
            f"{self.name} module initialized in {self.mode} mode. "
            f"Seed: {self.seed}. "
            f"Minimum labels to start training: {self.minimum_labels_to_start_train}, "
            f"minimum labels to retrain: {self.minimum_labels_to_retrain}, "
            f"minimum labels to finalize training: {self.minimum_labels_to_finalize_train}.",
            1,
            1,
        )

    def read_configuration(self):
        """Load module-scoped ML settings from config parser into runtime fields."""
        conf = ConfigParser()
        section = self.module_config_section

        self.mode = conf.ml_module_mode(section, default=conf.get_ml_mode())
        self.ground_truth_config_label = conf.label()
        self.enable_logs = conf.ml_module_enable_logs(
            section,
            default=conf.create_performance_metrics_log_files(),
        )
        self.batch_size = conf.ml_module_training_batch_size(
            section,
            default=conf.flow_ml_detection_training_batch_size(),
        )
        self.minimum_labels_to_start_train = self.batch_size
        self.minimum_labels_to_retrain = self.batch_size
        self.minimum_labels_to_finalize_train = int(self.batch_size / 4)
        self.validate_on_train = conf.ml_module_validate_on_train(
            section,
            default=conf.validate_on_train(),
        )
        self.percentage_validation = conf.ml_module_validation_percentage(
            section,
            default=0.1,
        )
        self.seed = conf.ml_module_seed(section, default=1111)
        self.train_from_scratch = conf.ml_module_train_from_scratch(
            section,
            default=False,
        )

    def write_to_log(self, message: str):
        """Append one log line when metrics logging is enabled."""
        if not self.enable_logs or self.log_file is None:
            return
        try:
            self.log_file.write(message + "\n")
        except Exception as exc:
            self.print(f"Error writing to log: {exc}", 0, 1)

    @abstractmethod
    def process_features(self, dataset: pd.DataFrame) -> pd.DataFrame:
        """Convert raw flow dataframe to backend-ready numeric feature dataframe."""
        pass

    @abstractmethod
    def create_empty_model(self) -> Any:
        """Create a new untrained backend model instance."""
        pass

    @abstractmethod
    def create_empty_preprocessor(self) -> Any:
        """Create a new untrained preprocessing object."""
        pass

    @abstractmethod
    def update_preprocessor(self, x_train: pd.DataFrame):
        """Incrementally fit/update preprocessing state from training features."""
        pass

    @abstractmethod
    def transform_features(self, x_data: pd.DataFrame) -> numpy.ndarray:
        """Transform processed dataframe into model input matrix."""
        pass

    @abstractmethod
    def fit_incremental_model(
        self,
        x_train: numpy.ndarray,
        y_train: numpy.ndarray,
        classes: Optional[list] = None,
    ):
        """Incrementally train/update the model for one batch."""
        pass

    @abstractmethod
    def predict_batch(self, x_data: numpy.ndarray) -> numpy.ndarray:
        """Return predictions for a transformed batch."""
        pass

    @abstractmethod
    def is_preprocessor_initialized(self) -> bool:
        """Report whether preprocessing has enough state for inference."""
        pass

    @abstractmethod
    def train(
        self,
        sum_labeled_flows,
    ):
        """Backend train entrypoint; typically delegates to `_train_default`."""

    @abstractmethod
    def run_test_on_flow(self, flow: dict):
        """Backend test entrypoint; typically delegates to `_test_default`."""

    def get_dummy_flows(self) -> dict:
        """Provide per-label fallback samples for first partial fit if needed."""
        return {}

    def store_training_results(
        self,
        y_pred_train,
        y_gt_train,
        y_pred_val,
        y_gt_val,
        sum_labeled_flows,
    ):
        """Compute train/validation metrics, persist model, and write one log snapshot."""
        relevant_labels = [MALICIOUS, BENIGN]

        y_pred_train = self._normalize_binary_labels(y_pred_train)
        y_gt_train = self._normalize_binary_labels(y_gt_train)
        y_pred_val = self._normalize_binary_labels(y_pred_val)
        y_gt_val = self._normalize_binary_labels(y_gt_val)

        def compute_metrics(y_true, y_pred):
            metrics = {
                "TP": numpy.sum((y_pred == MALICIOUS) & (y_true == MALICIOUS)),
                "FP": numpy.sum((y_pred == MALICIOUS) & (y_true == BENIGN)),
                "FN": numpy.sum((y_pred == BENIGN) & (y_true == MALICIOUS)),
                "TN": numpy.sum((y_pred == BENIGN) & (y_true == BENIGN)),
            }
            seen_labels = {
                label: numpy.sum(y_true == label) for label in relevant_labels
            }
            predicted_labels = {
                label: numpy.sum(y_pred == label) for label in relevant_labels
            }
            return metrics, seen_labels, predicted_labels

        def filter_labels(y_true, y_pred):
            mask = numpy.isin(y_true, relevant_labels)
            return y_true[mask], y_pred[mask]

        if (
            y_pred_val is not None
            and y_gt_val is not None
            and y_pred_train is not None
            and y_gt_train is not None
            and not numpy.array_equal(y_gt_train, y_gt_val)
        ):
            y_gt_val_filt, y_pred_val_filt = filter_labels(
                y_gt_val, y_pred_val
            )
            y_gt_train_filt, y_pred_train_filt = filter_labels(
                y_gt_train, y_pred_train
            )

            metrics_val, seen_labels_val, predicted_labels_val = (
                compute_metrics(y_gt_val_filt, y_pred_val_filt)
            )
            metrics_train, seen_labels_train, predicted_labels_train = (
                compute_metrics(y_gt_train_filt, y_pred_train_filt)
            )

            self.write_to_log(
                f"Total labels: {sum_labeled_flows}, "
                f"Validation size: {len(y_pred_val_filt)}, "
                f"Validation seen labels: {seen_labels_val}, "
                f"Validation predicted labels: {predicted_labels_val}, "
                f"Validation metrics: {metrics_val}, "
                f"Training size: {len(y_gt_train_filt)}, "
                f"Training seen labels: {seen_labels_train}, "
                f"Training predicted labels: {predicted_labels_train}, "
                f"Training metrics: {metrics_train}"
            )
        else:
            y_gt_val_filt, y_pred_val_filt = filter_labels(
                y_gt_val, y_pred_val
            )
            metrics, seen_labels, predicted_labels = compute_metrics(
                y_gt_val_filt, y_pred_val_filt
            )

            self.write_to_log(
                f"Total labels: {sum_labeled_flows}, "
                f"Training size: {len(y_pred_val_filt)}, "
                f"Training seen labels: {seen_labels}, "
                f"Training predicted labels: {predicted_labels}, "
                f"Training metrics: {metrics}"
            )

    def store_testing_results(self, original_label, predicted_label):
        """Accumulate online test metrics and flush snapshots in configured batches."""
        if original_label in [
            BACKGROUND,
            BACKGROUND.upper(),
            BACKGROUND.lower(),
        ]:
            return

        original_label = self._normalize_binary_label(original_label)
        predicted_label = self._normalize_binary_label(predicted_label)

        if not hasattr(self, "malware_metrics"):
            self.malware_metrics = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
        if not hasattr(self, "seen_labels"):
            self.seen_labels = {MALICIOUS: 0, BENIGN: 0}
        if not hasattr(self, "predicted_labels"):
            self.predicted_labels = {MALICIOUS: 0, BENIGN: 0}

        if original_label in self.seen_labels:
            self.seen_labels[original_label] += 1
        else:
            self.seen_labels[original_label] = 1

        if predicted_label in self.predicted_labels:
            self.predicted_labels[predicted_label] += 1
        else:
            self.predicted_labels[predicted_label] = 1

        if original_label == MALICIOUS and predicted_label == MALICIOUS:
            self.malware_metrics["TP"] += 1
        elif original_label == BENIGN and predicted_label == MALICIOUS:
            self.malware_metrics["FP"] += 1
        elif original_label == MALICIOUS and predicted_label == BENIGN:
            self.malware_metrics["FN"] += 1
        elif original_label == BENIGN and predicted_label == BENIGN:
            self.malware_metrics["TN"] += 1

        self.testing_flows_since_last_log += 1
        if self.testing_flows_since_last_log < self.testing_log_batch_size:
            return

        self._write_testing_snapshot(self.testing_flows_since_last_log)
        self.testing_flows_since_last_log = 0

    def _write_testing_snapshot(self, batch_flows: int):
        """Write one aggregated testing metrics snapshot to the log."""
        if batch_flows <= 0:
            return

        total_flows = sum(self.seen_labels.values())
        log_str = (
            f"Batch flows: {batch_flows}; "
            f"Total flows: {total_flows}; "
            f"Seen labels: {self.seen_labels}; "
            f"Predicted labels: {self.predicted_labels}; "
            f"Malware metrics (TP/FP/TN/FN): {self.malware_metrics}; "
        )
        self.write_to_log(log_str)

    def flush_testing_results(self):
        """Force-write pending test metrics when shutting down or window closes."""
        if self.testing_flows_since_last_log > 0:
            self._write_testing_snapshot(self.testing_flows_since_last_log)
            self.testing_flows_since_last_log = 0

    def drop_labels(self, df: pd.DataFrame) -> pd.DataFrame:
        """Remove label-related columns before model preprocessing/inference."""
        return df.drop(
            [
                "ground_truth_label",
                "detailed_ground_truth_label",
                "label",
                "module_labels",
            ],
            axis=1,
            errors="ignore",
        )

    def _debug_training_dataframe(
        self, x_data: Optional[pd.DataFrame], stage: str
    ):
        """Print compact debug info for training dataframe shape/schema issues."""
        if x_data is None:
            self.print(f"[debug][{stage}] x_data is None", 0, 1)
            return

        self.print(
            f"[debug][{stage}] shape={x_data.shape}, columns={list(x_data.columns)}",
            0,
            1,
        )

        non_numeric_cols = [
            col
            for col in x_data.columns
            if not pd.api.types.is_numeric_dtype(x_data[col])
        ]
        if non_numeric_cols:
            dtype_map = {
                col: str(x_data[col].dtype) for col in non_numeric_cols
            }
            sample_values = {
                col: x_data[col].astype(str).dropna().head(3).tolist()
                for col in non_numeric_cols
            }
            self.print(
                f"[debug][{stage}] non_numeric_cols={non_numeric_cols}",
                0,
                1,
            )
            self.print(
                f"[debug][{stage}] non_numeric_dtypes={dtype_map}", 0, 1
            )
            self.print(
                f"[debug][{stage}] non_numeric_samples={sample_values}",
                0,
                1,
            )

        if hasattr(self.preprocessor, "feature_names_in_"):
            expected = list(
                getattr(self.preprocessor, "feature_names_in_", [])
            )
            incoming = list(x_data.columns)
            unseen = sorted(set(incoming) - set(expected))
            missing = sorted(set(expected) - set(incoming))
            self.print(
                f"[debug][{stage}] expected_feature_count={len(expected)}, incoming_feature_count={len(incoming)}",
                0,
                1,
            )
            if unseen:
                self.print(
                    f"[debug][{stage}] unseen_features={unseen}",
                    0,
                    1,
                )
            if missing:
                self.print(
                    f"[debug][{stage}] missing_features={missing}",
                    0,
                    1,
                )

    def _train_default(self, sum_labeled_flows):
        """Shared incremental training flow used by backend `train` hooks."""
        if self.flows is None or self.flows.empty:
            self.print("No flows to train on. Skipping training.", 0, 1)
            return

        x_train = None
        try:
            if hasattr(self.flows, "ground_truth_label"):
                gt = self.flows.ground_truth_label
                if hasattr(gt, "iloc"):
                    try:
                        y_gt_train = numpy.asarray(
                            self.flows["ground_truth_label"]
                        )
                    except Exception:
                        y_gt_train = numpy.full(
                            self.flows.shape[0], gt.iloc[0]
                        )
                else:
                    y_gt_train = numpy.full(self.flows.shape[0], gt)
            else:
                y_gt_train = numpy.full(
                    self.flows.shape[0], self.ground_truth_config_label
                )

            x_train = self.drop_labels(self.flows.copy())
            x_val = x_train
            y_gt_val = y_gt_train

            if self.validate_on_train and x_train.shape[0] > 1:
                val_size = int(self.percentage_validation * x_train.shape[0])
                val_size = max(1, val_size)
                val_size = min(val_size, x_train.shape[0] - 1)

                validation_indices = self.rng.choice(
                    x_train.shape[0],
                    size=val_size,
                    replace=False,
                )
                train_indices = numpy.array(
                    list(
                        set(range(x_train.shape[0])) - set(validation_indices)
                    )
                )

                x_val = x_train.iloc[validation_indices]
                y_gt_val = y_gt_train[validation_indices]
                x_train = x_train.iloc[train_indices]
                y_gt_train = y_gt_train[train_indices]

            self._debug_training_dataframe(
                x_train, "before_update_preprocessor"
            )
            self.update_preprocessor(x_train)
            x_train_arr = self.transform_features(x_train)

            unique_labels = numpy.unique(y_gt_train)
            if not self.classifier_initialized:
                missing_labels = [
                    label
                    for label in [MALICIOUS, BENIGN]
                    if label not in unique_labels
                ]
                if missing_labels:
                    dummies = self.get_dummy_flows()
                    for label in missing_labels:
                        if label in dummies:
                            x_train_arr = numpy.vstack(
                                [x_train_arr, dummies[label]]
                            )
                            y_gt_train = numpy.append(y_gt_train, [label])

                self.fit_incremental_model(
                    x_train=x_train_arr,
                    y_train=y_gt_train,
                    classes=[MALICIOUS, BENIGN],
                )
                self.classifier_initialized = True
            else:
                self.fit_incremental_model(
                    x_train=x_train_arr,
                    y_train=y_gt_train,
                    classes=None,
                )

            y_pred_train = self.predict_batch(x_train_arr)

            if self.validate_on_train:
                if x_val.shape[0] == 0:
                    self.print(
                        "Validation set is empty after split. Skipping validation.",
                        0,
                        1,
                    )
                    y_pred_val = numpy.array([])
                else:
                    x_val_arr = self.transform_features(x_val)
                    y_pred_val = self.predict_batch(x_val_arr)
            else:
                y_pred_val = y_pred_train

            self.store_training_results(
                y_pred_train=y_pred_train,
                y_gt_train=y_gt_train,
                y_pred_val=y_pred_val,
                y_gt_val=y_gt_val,
                sum_labeled_flows=sum_labeled_flows,
            )

        except Exception as exc:
            self.print(f"Error in train(): {type(exc).__name__}: {exc}", 0, 1)
            self._debug_training_dataframe(x_train, "train_exception")
            self.print(traceback.format_exc(), 0, 1)
            self.write_to_log("Error occurred during training.")

        self.labeled_counter = 0
        self.training_flows = []

    def _test_default(self, flow: dict):
        """Shared per-flow inference flow used by backend `run_test_on_flow` hooks."""
        processed_flow = self.process_flow(flow)
        if processed_flow is None or processed_flow.empty:
            return

        try:
            original_label = processed_flow["ground_truth_label"].iloc[0]
        except KeyError:
            original_label = self.ground_truth_config_label
        original_label = self._normalize_binary_label(original_label)

        processed_flow = self.drop_labels(processed_flow)
        pred = self.detect(processed_flow)
        if pred is None or getattr(pred, "size", 0) == 0:
            return

        predicted_label = self._normalize_binary_label(pred[0])

        if predicted_label == MALICIOUS:
            self.set_evidence_malicious_flow(flow, self.twid)
            self.print(
                f"Prediction {predicted_label} for label {original_label}"
                f' flow {flow["saddr"]}:'
                f'{flow["sport"]} -> '
                f'{flow["daddr"]}:'
                f'{flow["dport"]}/'
                f'{flow["proto"]}',
                0,
                2,
            )

        self.store_testing_results(
            original_label,
            predicted_label,
        )

    def process_training_flows(self):
        """Build and preprocess one training batch from buffered labeled flows."""
        try:
            new_flows = self.training_flows
            if len(new_flows) > self.batch_size:
                self.print(
                    f"Expected {self.batch_size} new flows, but got {len(new_flows)}. "
                    "Skipping training.",
                    0,
                    1,
                )
                return None

            df_flows = pd.DataFrame(new_flows)
            self.print(
                f"Processing {len(df_flows)} new flows for training.", 1, 1
            )
            df_flows = self.process_features(df_flows)
            self.print(
                f"Processed {len(df_flows)} new flows for training.", 1, 1
            )
            self.flows = df_flows
        except Exception:
            self.print("Error in process_flows()")
            self.print(traceback.format_exc(), 0, 1)

    def process_flow(self, flow_to_process: dict):
        """Convert one raw flow dict into processed single-row dataframe."""
        try:
            raw_flow = pd.DataFrame(flow_to_process, index=[0])
            dflow = self.process_features(raw_flow)
            if dflow.empty:
                return None
            return dflow
        except Exception:
            self.print("Error in process_flow()")
            self.print(traceback.format_exc(), 0, 1)
            return None

    def detect(self, x_flow) -> Optional[numpy.ndarray]:
        """Run preprocess + model prediction on already selected feature columns."""
        if (
            not self.classifier_initialized
            or not self.is_preprocessor_initialized()
        ):
            self.print(
                "Classifier/preprocessor is not initialized. Please train the model before detecting.",
                0,
                1,
            )
            return None

        try:
            x_flow_arr = self.transform_features(x_flow)
            pred = self.predict_batch(x_flow_arr)
            return pred
        except Exception as exc:
            self.print(
                f"Error in detect() while preprocessing or predicting the flow: {exc}",
                0,
                1,
            )
            self.print(traceback.format_exc(), 0, 1)
            return None

    def store_model(self):
        """Persist current model and preprocessor artifacts to disk paths."""
        self.print("Storing the trained model and preprocessor on disk.", 0, 2)

        model_dir = os.path.dirname(self.model_path)
        preprocess_dir = os.path.dirname(self.preprocess_path)
        if model_dir:
            os.makedirs(model_dir, exist_ok=True)
        if preprocess_dir:
            os.makedirs(preprocess_dir, exist_ok=True)

        with open(self.model_path, "wb") as model_file:
            model_file.write(pickle.dumps(self.clf))
        with open(self.preprocess_path, "wb") as preprocess_file:
            preprocess_file.write(pickle.dumps(self.preprocessor))

    def _read_pickle_or_none(self, path: str) -> Optional[Any]:
        """Load a pickle artifact or return None when missing/empty."""
        try:
            with open(path, "rb") as file_handler:
                return pickle.load(file_handler)
        except (FileNotFoundError, EOFError):
            return None

    def read_model(self):
        """Load model/preprocessor artifacts or initialize empty backend objects."""
        self.print("Reading trained artifacts from disk.", 0, 2)

        if self.mode == "train" and self.train_from_scratch:
            self.print(
                "train_from_scratch=true in train mode: creating empty model and preprocessor.",
                0,
                2,
            )
            self.clf = self.create_empty_model()
            self.preprocessor = self.create_empty_preprocessor()
            self.classifier_initialized = False
            self.scaler = self.preprocessor
            return

        loaded_model = self._read_pickle_or_none(self.model_load_path)
        if loaded_model is None:
            self.print("No model found, creating a new empty model.", 0, 2)
            self.clf = self.create_empty_model()
            self.classifier_initialized = False
        else:
            self.clf = loaded_model
            self.classifier_initialized = True

        loaded_preprocessor = self._read_pickle_or_none(
            self.preprocess_load_path
        )
        if loaded_preprocessor is None:
            self.print("No preprocessor found, creating a new one.", 0, 2)
            self.preprocessor = self.create_empty_preprocessor()
        else:
            self.preprocessor = loaded_preprocessor

        # Backward compatibility for existing sklearn-specific references.
        self.scaler = self.preprocessor

    def set_evidence_malicious_flow(
        self,
        flow: dict,
        twid: str,
    ):
        """Emit Slips evidence object when a flow is predicted as malicious."""
        try:
            src_ip = str(ipaddress.ip_address(flow["saddr"]))
            dst_ip = str(ipaddress.ip_address(flow["daddr"]))
        except (ValueError, KeyError) as exc:
            self.print(
                f"Skipping ML evidence with invalid attacker/victim IPs: {exc}",
                0,
                1,
            )
            return

        confidence = 0.1
        try:
            description = self.malicious_flow_description_template.format(
                module_name=self.name,
                src_ip=src_ip,
                sport=flow["sport"],
                dst_ip=dst_ip,
                dport=flow["dport"],
            )
        except (KeyError, ValueError) as exc:
            self.print(
                f"Invalid ML evidence description template/flow values: {exc}. Falling back to default description.",
                0,
                1,
            )
            description = (
                f"Flow with malicious characteristics detected by {self.name}. "
                f"Src IP {src_ip}:{flow.get('sport')} to {dst_ip}:{flow.get('dport')}"
            )
        twid_number = int(twid.replace("timewindow", ""))
        evidence = Evidence(
            evidence_type=self.malicious_flow_evidence_type,
            attacker=Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value=src_ip,
            ),
            victim=Victim(
                direction=Direction.DST,
                ioc_type=IoCType.IP,
                value=dst_ip,
            ),
            threat_level=ThreatLevel.LOW,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=src_ip),
            timewindow=TimeWindow(twid_number),
            uid=[flow["uid"]],
            timestamp=flow["starttime"],
            method=Method.AI,
            src_port=flow["sport"],
            dst_port=flow["dport"],
        )

        self.db.set_evidence(evidence)

    def shutdown_gracefully(self):
        """Flush pending training/testing state and logs during module shutdown."""
        if self.mode == "train":
            self.last_training_in_window()
            self.store_model()
        elif self.mode == "test":
            self.flush_testing_results()

        if self.log_file is not None:
            self.log_file.flush()

    def last_training_in_window(self):
        """Optionally train on residual labeled flows before window/module ends."""
        if not self.classifier_initialized:
            self.print(
                "Classifier is not initialized. No training will be done.",
                0,
                1,
            )
            return

        flows_left = self.labeled_counter
        self.print(f"Flows left to train on: {flows_left}", 0, 1)

        if flows_left >= self.minimum_labels_to_finalize_train:
            self.print(
                f"Training on the last {flows_left} flows in the window", 0, 1
            )
            self.process_training_flows()
            self.print(
                f"Size of the last training batch: {len(self.flows)}", 0, 1
            )
            self.train(self.labeled_counter)
        else:
            self.print(
                f"Not enough flows to finalize training. "
                f"Need at least {self.minimum_labels_to_finalize_train}, but got {flows_left}.",
                0,
                1,
            )
            self.labeled_counter = 0
            self.training_flows = []

    def pre_main(self):
        """Drop privileges and load model artifacts before the main loop starts."""
        utils.drop_root_privs_permanently()
        self.read_model()
        print("\n")

    @staticmethod
    def _extract_twid_from_tw_closed(msg: dict) -> Optional[str]:
        """Extract timewindow id from a tw_closed message payload."""
        payload = msg.get("data") if isinstance(msg, dict) else None
        if payload is None:
            return None
        payload = str(payload)
        if "_" in payload:
            return payload.split("_")[-1]
        return payload

    def handle_tw_closed(self, msg: dict):
        """Finalize residual train batch and persist artifacts once per closed TW."""
        if self.mode != "train":
            return

        twid = self._extract_twid_from_tw_closed(msg)
        if twid and twid == self.last_closed_twid:
            return
        if twid:
            self.last_closed_twid = twid

        self.last_training_in_window()
        self.store_model()

    def main(self):
        """Consume incoming flows, route to train/test path, and maintain buffers."""
        if msg := self.get_msg("new_flow"):
            msg = json.loads(msg["data"])
            self.twid = msg["twid"]
            self.profileid = msg["profileid"]
            self.flow = msg["flow"]

            self.flow.update(
                {
                    "state": msg["interpreted_state"],
                    "label": msg["label"],
                    "module_labels": msg["module_labels"],
                }
            )

            if (not self.flow.get("ground_truth_label")) or (
                self.flow.get("ground_truth_label") == ""
            ):
                self.flow["ground_truth_label"] = (
                    self.ground_truth_config_label
                )

            self.flow["ground_truth_label"] = self._normalize_binary_label(
                self.flow["ground_truth_label"]
            )

            if self.flow["ground_truth_label"] in [
                BACKGROUND,
                BACKGROUND.upper(),
                BACKGROUND.lower(),
            ]:
                return

            if self.mode == "train":
                if self.flow["ground_truth_label"] in [MALICIOUS, BENIGN]:
                    self.labeled_counter += 1
                    self.training_flows += [self.flow]

                if self.labeled_counter < self.minimum_labels_to_retrain:
                    return

                self.process_training_flows()
                self.train(self.labeled_counter)

            elif self.mode == "test":
                self.run_test_on_flow(self.flow)

        if "tw_closed" in self.channels and (msg := self.get_msg("tw_closed")):
            self.handle_tw_closed(msg)

    def _infer_state(self, state: str, spkts: float, dpkts: float) -> float:
        pkts = int(float(spkts or 0) + float(dpkts or 0))
        pre = state.split("_")[0]
        st = state.lower()
        if "new" in st or st == "established":
            return 1.0
        if "closed" in st or st == "not established":
            return 0.0
        if state in ("S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR"):
            return 0.0
        if state in ("S1", "SF", "S2", "S3", "RSTO", "RSTP", "OTH"):
            return 1.0
        if "S" in pre and "A" in pre:
            return 1.0
        if "PA" in pre:
            return 1.0
        if any(x in pre for x in ("ECO", "ECR", "URH", "URP")):
            return 1.0
        if "EST" in pre:
            return 1.0
        if "RST" in pre or "FIN" in pre:
            return 0.0 if pkts <= 3 else 1.0
        return 0.0

    def _encode_proto(self, proto: str) -> float:
        proto_map = {
            "tcp": 0.0,
            "udp": 1.0,
            "icmp-ipv6": 3.0,
            "icmp": 2.0,
            "arp": 4.0,
        }
        return proto_map.get(str(proto).strip().lower(), 0.0)

    def _is_scaler_initialized(self) -> bool:
        """Works for StandardScaler, MinMaxScaler, RobustScaler, etc."""
        attrs = ["mean_", "scale_", "var_", "data_min_", "data_max_"]
        return any(hasattr(self.preprocessor, attr) for attr in attrs)

    @staticmethod
    def _normalize_binary_label(label):
        if isinstance(label, str):
            normalized = label.strip().lower()
            if normalized in {"benign", "normal"}:
                return BENIGN
            if normalized in {"malicious", "malware"}:
                return MALICIOUS
        return label

    def _normalize_binary_labels(self, labels):
        if labels is None:
            return None
        return numpy.asarray(
            [self._normalize_binary_label(label) for label in labels]
        )
