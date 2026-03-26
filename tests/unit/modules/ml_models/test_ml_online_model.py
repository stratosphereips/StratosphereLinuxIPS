import numpy
import pytest
from slips_files.common.abstracts.ml_module_base import BENIGN, MALICIOUS
from modules.ml_online_model.ml_online_model import MLOnlineModel


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
