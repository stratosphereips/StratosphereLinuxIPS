import numpy
import pandas as pd
import pytest

from slips_files.common.abstracts.ml_module_base import (
    BENIGN,
    MALICIOUS,
    MLBaseDetection,
)
from modules.ml_online_model.ml_online_model import MLOnlineModel
from modules.ml_linear_model.ml_linear_model import MLLinearModel


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

    def train(self, sum_labeled_flows):
        return None

    def run_test_on_flow(self, flow: dict):
        return None


class _DummyOnlineClassifierNumeric:
    def __init__(self):
        self.learned_targets = []
        self.predictions = [1.0, 0.0]

    def _target_transform(self, y):
        return float(y)

    def learn_one(self, x, y):
        self.learned_targets.append(y)

    def predict_one(self, x):
        return self.predictions.pop(0)


class _DummyOnlineClassifierCategorical:
    def __init__(self):
        self.learned_targets = []

    def _target_transform(self, y):
        return y

    def learn_one(self, x, y):
        self.learned_targets.append(y)

    def predict_one(self, x):
        return MALICIOUS


class _DummySklearnClassifier:
    __module__ = "sklearn.linear_model"

    def __init__(self):
        self.calls = []
        self._predictions = numpy.asarray([MALICIOUS, BENIGN])

    def partial_fit(self, x_train, y_train, classes=None):
        self.calls.append(
            {
                "x_train": x_train,
                "y_train": numpy.asarray(y_train),
                "classes": classes,
            }
        )

    def predict(self, x_data):
        return self._predictions[: len(x_data)]


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
    module.preprocessor = object()
    return module


@pytest.fixture
def online_model_numeric():
    model = MLOnlineModel.__new__(MLOnlineModel)
    model.benign_target_value = 0.0
    model.malicious_target_value = 1.0
    model._label_to_target = {BENIGN: 0.0, MALICIOUS: 1.0}
    model.clf = _DummyOnlineClassifierNumeric()
    return model


@pytest.fixture
def online_model_categorical():
    model = MLOnlineModel.__new__(MLOnlineModel)
    model.benign_target_value = 0.0
    model.malicious_target_value = 1.0
    model._label_to_target = {BENIGN: 0.0, MALICIOUS: 1.0}
    model.clf = _DummyOnlineClassifierCategorical()
    return model


@pytest.fixture
def linear_model():
    model = MLLinearModel.__new__(MLLinearModel)
    model.benign_target_value = 0.0
    model.malicious_target_value = 1.0
    model._label_to_target = {BENIGN: 0.0, MALICIOUS: 1.0}
    model.clf = _DummySklearnClassifier()
    return model


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
            sum_labeled_flows=2
        )

        assert len(base_module.fit_calls) == 1
        assert base_module.fit_calls[0]["classes"] == [MALICIOUS, BENIGN]


class TestMLOfflineOnlineLabels:
    def test_online_model_numeric_conversion_for_river(
        self, online_model_numeric
    ):
        x_train = numpy.array([[1.0, 2.0], [3.0, 4.0]])
        y_train = numpy.array([BENIGN, MALICIOUS], dtype=object)

        online_model_numeric.fit_incremental_model(
            x_train, y_train, classes=[MALICIOUS, BENIGN]
        )

        assert online_model_numeric.clf.learned_targets == [0.0, 1.0]

    def test_online_model_keeps_categorical_when_supported(
        self, online_model_categorical
    ):
        x_train = numpy.array([[1.0, 2.0], [3.0, 4.0]])
        y_train = numpy.array([BENIGN, MALICIOUS], dtype=object)

        online_model_categorical.fit_incremental_model(
            x_train, y_train, classes=[MALICIOUS, BENIGN]
        )

        assert online_model_categorical.clf.learned_targets == [
            BENIGN,
            MALICIOUS,
        ]

    def test_online_model_decodes_numeric_predictions(
        self, online_model_numeric
    ):
        preds = online_model_numeric.predict_batch(
            numpy.array([[1.0, 2.0], [3.0, 4.0]])
        )

        assert preds.tolist() == [MALICIOUS, BENIGN]


class TestMLLinearModelLabels:
    def test_linear_model_fit_uses_categorical_targets_for_sklearn(
        self, linear_model
    ):
        x_train = numpy.array([[1.0, 2.0], [3.0, 4.0]])
        y_train = numpy.array([BENIGN, MALICIOUS], dtype=object)

        linear_model.fit_incremental_model(
            x_train, y_train, classes=[MALICIOUS, BENIGN]
        )

        assert len(linear_model.clf.calls) == 1
        assert linear_model.clf.calls[0]["y_train"].tolist() == [
            BENIGN,
            MALICIOUS,
        ]
        assert list(linear_model.clf.calls[0]["classes"]) == [
            MALICIOUS,
            BENIGN,
        ]

    def test_linear_model_prediction_returns_canonical_labels(
        self, linear_model
    ):
        preds = linear_model.predict_batch(
            numpy.array([[1.0, 2.0], [3.0, 4.0]])
        )

        assert preds.tolist() == [MALICIOUS, BENIGN]
