import traceback
import warnings
import os
from typing import Optional
import pickle

import numpy
import pandas as pd
from sklearn.decomposition import IncrementalPCA
from sklearn.linear_model import SGDClassifier
from sklearn.preprocessing import StandardScaler

import slips_files.common.abstracts.ml_module_base as ml_base
from slips_files.common.parsers.config_parser import ConfigParser

BENIGN = ml_base.BENIGN
MALICIOUS = ml_base.MALICIOUS


def warn(*args, **kwargs):
    pass


warnings.warn = warn


class MLLinearModel(ml_base.MLBaseDetection):
    name = "ml_linear_model"
    description = "Standalone linear sklearn-based ML flow detector"
    authors = ["Jan Svoboda"]
    module_key = "ml_linear_model"
    module_config_section = "ml_linear_model"
    malicious_flow_evidence_type = (
        ml_base.EvidenceType.ML_LINEAR_MALICIOUS_FLOW
    )
    malicious_flow_description_template = (
        "Flow with malicious characteristics detected by ml_linear_model. "
        "Src IP {src_ip}:{sport} to {dst_ip}:{dport}"
    )

    def init(self):
        super().init()
        self._add_dummy_flows()
        self._fit_pca_next_transform = False

        conf = ConfigParser()
        section = self.module_config_section

        configured_pca_load = conf.ml_module_pca_load_path(
            section,
            None,
        )
        configured_pca_store = conf.ml_module_pca_store_path(
            section,
            None,
        )

        self.pca_load_path = self.resolve_artifact_path(
            explicit_path=configured_pca_load,
        )
        self.pca_store_path = self.resolve_artifact_path(
            explicit_path=configured_pca_store,
        )

        self.pca_n_components = conf.ml_module_pca_n_components(
            section,
            default=None,
        )
        self.pca_batch_size = conf.ml_module_pca_batch_size(
            section,
            default=self.batch_size,
        )
        self.pca = None

        self.benign_target_value = conf.ml_module_benign_target_value(
            section,
            default=0.0,
        )
        self.malicious_target_value = conf.ml_module_malicious_target_value(
            section,
            default=1.0,
        )
        self._label_to_target = {
            BENIGN: self.benign_target_value,
            MALICIOUS: self.malicious_target_value,
        }

    def _add_dummy_flows(self):
        self.dummy_malicious_flow = numpy.array(
            [
                1.9424750804901123,
                0.0,
                49733.0,
                443.0,
                17.0,
                27.0,
                25517.0,
                17247.0,
                1.0,
                42764.0,
                44.0,
            ]
        ).reshape(1, -1)

        self.dummy_benign_flow = numpy.array(
            [
                10.896695,
                0.0,
                47956.0,
                80.0,
                1.0,
                0.0,
                100.0,
                67596.0,
                1.0,
                67696.0,
                1.0,
            ]
        ).reshape(1, -1)

    def get_dummy_flows(self) -> dict:
        return {
            MALICIOUS: self.dummy_malicious_flow,
            BENIGN: self.dummy_benign_flow,
        }

    def process_features(self, dataset: pd.DataFrame) -> pd.DataFrame:
        try:
            dataset = dataset.copy()

            # normalize proto to lowercase string before filtering
            if "proto" in dataset.columns:
                dataset["proto"] = (
                    dataset["proto"].astype(str).str.strip().str.lower()
                )

            # filter unsupported protocols
            discard_set = {"arp", "icmp", "igmp", "ipv6-icmp", ""}
            if "proto" in dataset.columns:
                dataset = dataset[
                    ~dataset["proto"].fillna("").isin(discard_set)
                ]

            if dataset.empty:
                return dataset

            # drop non-feature columns
            to_drop = [
                "appproto",
                "daddr",
                "saddr",
                "starttime",
                "type_",
                "smac",
                "dmac",
                "history",
                "uid",
                "dir_",
                "endtime",
                "flow_source",
                "interface",
            ]
            dataset = dataset.drop(columns=to_drop, errors="ignore")

            # coerce base numeric fields before deriving from them
            for col in ["sbytes", "dbytes", "spkts", "dpkts"]:
                if col not in dataset.columns:
                    dataset[col] = 0.0
                dataset[col] = pd.to_numeric(
                    dataset[col], errors="coerce"
                ).fillna(0.0)

            # derived columns
            dataset["bytes"] = dataset["sbytes"] + dataset["dbytes"]
            dataset["pkts"] = dataset["spkts"] + dataset["dpkts"]

            # encode proto via shared base class static
            if "proto" in dataset.columns:
                dataset["proto"] = dataset["proto"].apply(self._encode_proto)

            # encode state via shared base class static
            dataset["state"] = dataset.apply(
                lambda row: self._infer_state(
                    str(row.get("state", "")),
                    row.get("spkts", 0.0),
                    row.get("dpkts", 0.0),
                ),
                axis=1,
            )

            # enforce feature order and float64, fill missing with 0.0
            feature_order = [
                "dur",
                "proto",
                "sport",
                "dport",
                "spkts",
                "dpkts",
                "sbytes",
                "dbytes",
                "state",
                "bytes",
                "pkts",
            ]
            label_cols = [
                "ground_truth_label",
                "detailed_ground_truth_label",
                "label",
                "module_labels",
                "detailed_label",
            ]

            for col in feature_order:
                if col not in dataset.columns:
                    dataset[col] = 0.0
                dataset[col] = (
                    pd.to_numeric(dataset[col], errors="coerce")
                    .fillna(0.0)
                    .astype("float64")
                )

            existing_label_cols = [
                col for col in label_cols if col in dataset.columns
            ]
            dataset = dataset[feature_order + existing_label_cols]
            return dataset

        except Exception:
            self.print("Error in process_features()")
            self.print(traceback.format_exc(), 0, 1)
            return dataset.iloc[0:0]

    def create_empty_model(self):
        return SGDClassifier(
            warm_start=False,
            loss="hinge",
            penalty="l2",
            random_state=self.seed,
        )

    def create_empty_preprocessor(self):
        return StandardScaler()

    def is_preprocessor_initialized(self) -> bool:
        return self._is_scaler_initialized() and self._is_pca_initialized()

    def update_preprocessor(self, x_train: pd.DataFrame):
        try:
            if not self.is_preprocessor_initialized():
                self.print(
                    "First fitting the scaler to the training data.", 0, 2
                )
                self.preprocessor.fit(x_train)
            else:
                self.print("Updating the scaler with the training data.", 0, 2)
                self.preprocessor.partial_fit(x_train)
        except Exception as exc:
            self.print(
                f"[debug][update_preprocessor] failed with {type(exc).__name__}: {exc}",
                0,
                1,
            )
            incoming = list(x_train.columns)
            non_numeric_cols = [
                col
                for col in incoming
                if not pd.api.types.is_numeric_dtype(x_train[col])
            ]
            self.print(
                f"[debug][update_preprocessor] incoming_columns={incoming}",
                0,
                1,
            )
            if non_numeric_cols:
                sample_values = {
                    col: x_train[col].astype(str).dropna().head(3).tolist()
                    for col in non_numeric_cols
                }
                self.print(
                    f"[debug][update_preprocessor] non_numeric_columns={non_numeric_cols}",
                    0,
                    1,
                )
                self.print(
                    f"[debug][update_preprocessor] non_numeric_samples={sample_values}",
                    0,
                    1,
                )
            raise
        self._fit_pca_next_transform = True

    def _create_incremental_pca(self) -> IncrementalPCA:
        kwargs = {"batch_size": self.pca_batch_size}
        if self.pca_n_components is not None:
            kwargs["n_components"] = self.pca_n_components
        return IncrementalPCA(**kwargs)

    def _is_pca_initialized(self) -> bool:
        return self.pca is not None and hasattr(self.pca, "components_")

    def _fit_or_update_pca(self, x_scaled: numpy.ndarray):
        if self.pca is None:
            self.pca = self._create_incremental_pca()

        n_samples, n_features = x_scaled.shape
        if n_samples < 2:
            raise ValueError("PCA requires at least 2 samples to fit.")

        if self.pca_n_components is not None and self.pca_n_components > min(
            n_samples, n_features
        ):
            raise ValueError(
                f"Configured pca_n_components={self.pca_n_components} exceeds "
                f"allowed maximum {min(n_samples, n_features)} for current batch."
            )

        if not self._is_pca_initialized():
            self.pca.fit(x_scaled)
        else:
            if hasattr(self.pca, "partial_fit"):
                self.pca.partial_fit(x_scaled)
            else:
                self.print(
                    "Loaded PCA has no partial_fit(); keeping it fixed during training.",
                    0,
                    1,
                )

    def transform_features(self, x_data: pd.DataFrame) -> numpy.ndarray:
        x_scaled = self.preprocessor.transform(x_data)

        if self._fit_pca_next_transform:
            self._fit_or_update_pca(x_scaled)
            self._fit_pca_next_transform = False

        if self._is_pca_initialized():
            return self.pca.transform(x_scaled)

        raise ValueError(
            "PCA is required but not initialized. "
            "Ensure pca_load_path points to a fitted PCA in test mode "
            "or train with enough samples to fit PCA."
        )

    def fit_incremental_model(
        self,
        x_train: numpy.ndarray,
        y_train: numpy.ndarray,
        classes: Optional[list] = None,
    ):
        numeric_targets = self._guess_numeric_targets()
        encoded_targets = self._encode_targets(y_train, numeric_targets)
        if classes is None:
            self.clf.partial_fit(x_train, encoded_targets)
        else:
            encoded_classes = self._encode_targets(
                numpy.asarray(classes), numeric_targets
            )
            self.clf.partial_fit(
                x_train, encoded_targets, classes=encoded_classes
            )

    def predict_batch(self, x_data: numpy.ndarray) -> numpy.ndarray:
        preds = self.clf.predict(x_data)
        return numpy.asarray([self._decode_target(pred) for pred in preds])

    def _guess_numeric_targets(self) -> bool:
        module_name = getattr(self.clf.__class__, "__module__", "")
        if module_name.startswith("sklearn."):
            return False
        target_transform = getattr(self.clf, "_target_transform", None)
        if callable(target_transform):
            try:
                target_transform(MALICIOUS)
                return False
            except Exception:
                return True
        return False

    @staticmethod
    def _normalize_label(label):
        if isinstance(label, str):
            normalized = label.strip().lower()
            if normalized in {"benign", "normal"}:
                return BENIGN
            if normalized in {"malicious", "malware"}:
                return MALICIOUS
        return label

    def _encode_targets(
        self, targets: numpy.ndarray, numeric_targets: bool
    ) -> numpy.ndarray:
        normalized_targets = [
            self._normalize_label(target) for target in targets
        ]
        if not numeric_targets:
            return numpy.asarray(normalized_targets)
        encoded = [
            self._label_to_target.get(target, target)
            for target in normalized_targets
        ]
        return numpy.asarray(encoded)

    def _decode_target(self, value):
        if isinstance(value, (float, int, numpy.floating, numpy.integer)):
            value = float(value)
            if numpy.isclose(value, self.malicious_target_value):
                return MALICIOUS
            if numpy.isclose(value, self.benign_target_value):
                return BENIGN
        return self._normalize_label(value)

    def store_model(self):
        super().store_model()
        if self.pca is None:
            return

        pca_dir = os.path.dirname(self.pca_store_path)
        if pca_dir:
            os.makedirs(pca_dir, exist_ok=True)

        with open(self.pca_store_path, "wb") as pca_file:
            pca_file.write(pickle.dumps(self.pca))

    def read_model(self):
        super().read_model()
        self.pca = None

        loaded_pca = self._read_pickle_or_none(self.pca_load_path)
        if loaded_pca is not None:
            self.pca = loaded_pca
            return

        if self.mode == "test":
            self.print(
                "No PCA found in test mode. PCA is mandatory for ml_linear_model.",
                0,
                1,
            )
            return

        self.pca = self._create_incremental_pca()

    def train(self, sum_labeled_flows):
        self._train_default(sum_labeled_flows)

    def run_test_on_flow(self, flow: dict):
        self._test_default(flow)
