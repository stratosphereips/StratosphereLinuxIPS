import numpy
import pytest
from slips_files.common.abstracts.ml_module_base import BENIGN, MALICIOUS
from modules.ml_linear_model.ml_linear_model import MLLinearModel


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
def linear_model():
    model = MLLinearModel.__new__(MLLinearModel)
    model.benign_target_value = 0.0
    model.malicious_target_value = 1.0
    model._label_to_target = {BENIGN: 0.0, MALICIOUS: 1.0}
    model.clf = _DummySklearnClassifier()
    return model


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
