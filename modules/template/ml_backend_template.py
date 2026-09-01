from typing import Any, Optional

import numpy
import pandas as pd

from slips_files.common.abstracts.ml_module_base import MLBaseDetection


# New backend checklist:
# - Copy this file to modules/<module_name>/<module_name>.py
# - Rename class, module_key, and module_config_section
# - Set artifact paths in slips.yaml for your backend
# - Implement all NotImplementedError methods


class MLBackendTemplate(MLBaseDetection):
    name = "ML backend template"
    description = "Skeleton backend for a standalone ML flow detector"
    authors = ["Your Name"]
    module_key = "ml_template"
    module_config_section = "ml_template"
    # Add a dedicated EvidenceType for your ML module in
    # slips_files/core/structures/evidence.py and set it here.
    malicious_flow_evidence_type = None
    malicious_flow_description_template = (
        "Flow with malicious characteristics detected by ml_backend_template. "
        "Src IP {src_ip}:{sport} to {dst_ip}:{dport}"
    )

    def process_features(self, dataset: pd.DataFrame) -> pd.DataFrame:
        return dataset

    def create_empty_model(self) -> Any:
        raise NotImplementedError(
            "Return an untrained backend model instance."
        )

    def create_empty_preprocessor(self) -> Any:
        raise NotImplementedError("Return an untrained preprocessor or None.")

    def update_preprocessor(self, x_train: pd.DataFrame):
        raise NotImplementedError(
            "Incrementally fit/update preprocessing on x_train."
        )

    def transform_features(self, x_data: pd.DataFrame) -> numpy.ndarray:
        raise NotImplementedError(
            "Convert features to model-ready numpy array."
        )

    def fit_incremental_model(
        self,
        x_train: numpy.ndarray,
        y_train: numpy.ndarray,
        classes: Optional[list] = None,
    ):
        raise NotImplementedError(
            "Incrementally train model on current batch."
        )

    def predict_batch(self, x_data: numpy.ndarray) -> numpy.ndarray:
        raise NotImplementedError("Return batch predictions for x_data.")

    def is_preprocessor_initialized(self) -> bool:
        raise NotImplementedError(
            "Return True when preprocessor can transform data."
        )

    def train(self, sum_labeled_flows):
        return self._train_default(sum_labeled_flows)

    def run_test_on_flow(self, flow: dict):
        return self._test_default(flow)
