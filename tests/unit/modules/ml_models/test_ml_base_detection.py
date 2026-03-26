import numpy
import pandas as pd
import pytest

from slips_files.common.abstracts.ml_module_base import (
    BENIGN,
    MALICIOUS,
    MLBaseDetection,
)


class _DummyBaseModule(MLBaseDetection):
    name = "dummy_ml"
    module_key = "dummy_ml"
    module_config_section = "dummy_ml"

    def get_default_artifact_paths(self):
        return "", "", "", ""

    def process_features(self, dataset: pd.DataFrame) -> pd.DataFrame:
        return dataset

    def create_empty_model(self):
        return object()

    def create_empty_preprocessor(self):
        return object()

    def update_preprocessor(self, x_train: pd.DataFrame):
        return None

    def transform_features(self, x_data: pd.DataFrame) -> numpy.ndarray:
        return x_data.to_numpy(dtype=float)

    def fit_incremental_model(self, x_train, y_train, classes=None):
        self.fit_calls.append(
            {
                "x_train": x_train,
                "y_train": numpy.asarray(y_train),
                "classes": classes,
            }
        )

    def predict_batch(self, x_data: numpy.ndarray) -> numpy.ndarray:
        return numpy.asarray([BENIGN] * len(x_data))

    def is_preprocessor_initialized(self) -> bool:
        return True

    def train(self, sum_labeled_flows, last_number_of_flows_when_trained):
        return None

    def run_test_on_flow(self, flow: dict):
        return None


@pytest.fixture
def base_module():
    module = _DummyBaseModule.__new__(_DummyBaseModule)
    module.flows = pd.DataFrame(
        {
            "dur": [1.0, 2.0],
            "proto": [0.0, 1.0],
            "sport": [10.0, 11.0],
            "dport": [80.0, 443.0],
            "spkts": [1.0, 1.0],
            "dpkts": [1.0, 1.0],
            "sbytes": [100.0, 200.0],
            "dbytes": [50.0, 70.0],
            "state": [1.0, 1.0],
            "bytes": [150.0, 270.0],
            "pkts": [2.0, 2.0],
            "ground_truth_label": [BENIGN, MALICIOUS],
        }
    )
    module.ground_truth_config_label = BENIGN
    module.validate_on_train = False
    module.percentage_validation = 0.1
    module.rng = numpy.random.default_rng(123)
    module.classifier_initialized = False
    module.fit_calls = []
    module.print = lambda *args, **kwargs: None
    module._debug_training_dataframe = lambda *args, **kwargs: None
    module.store_training_results = lambda **kwargs: None
    module.write_to_log = lambda *args, **kwargs: None
    module.labeled_counter = 0
    module.training_flows = []
    module.last_number_of_flows_when_trained = 0
    module.preprocessor = object()
    return module


class TestMLBaseModule:
    def test_drop_labels_removes_known_label_columns(self, base_module):
        raw = pd.DataFrame(
            {
                "dur": [1.0],
                "ground_truth_label": [BENIGN],
                "detailed_ground_truth_label": [BENIGN],
                "label": [BENIGN],
                "module_labels": [{"m": BENIGN}],
            }
        )
        cleaned = base_module.drop_labels(raw)
        assert list(cleaned.columns) == ["dur"]

    def test_train_default_passes_both_classes_on_first_fit(self, base_module):
        base_module._train_default(
            sum_labeled_flows=2, last_number_of_flows_when_trained=0
        )
        assert len(base_module.fit_calls) == 1
        assert base_module.fit_calls[0]["classes"] == [MALICIOUS, BENIGN]
