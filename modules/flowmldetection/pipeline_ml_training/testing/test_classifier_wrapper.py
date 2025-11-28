# test_classifier_wrapper.py
import sys
import types
from unittest import mock

import numpy as np
import pytest

# Import the module under test
from pipeline_ml_training import classifier_wrapper as cw


# Provide a tiny 'commons' module for the imported code to use.
commons = types.ModuleType("commons")
commons.BENIGN = "benign"
commons.MALICIOUS = "malicious"
sys.modules["commons"] = commons


@pytest.fixture
def identity_preprocessor():
    """A preprocessing handler with a transform method that returns input unchanged
    but tracks calls."""
    m = mock.Mock()
    m.transform = mock.Mock(side_effect=lambda x: x)
    return m


@pytest.fixture
def shrinking_preprocessor():
    """A preprocessing handler that shrinks input data to 7 features."""
    m = mock.Mock()

    def transform(x):
        return x[:, :7]  # keep only first 7 features

    m.transform = mock.Mock(side_effect=transform)
    return m


@pytest.fixture
def simple_X_y():
    """Return a small toy X and y where only BENIGN is present."""
    X = np.array(
        [
            [10.0] * 11,
            [20.0] * 11,
        ]
    )  # shape (2,11)
    y = np.array([cw.BENIGN, cw.BENIGN])
    return X, y


class TestClassifierWrapperProcess:
    def test_process_flows_adds_missing_class_and_calls_preprocessing(
        self, identity_preprocessor, simple_X_y
    ):
        X, y = simple_X_y
        wrapper = cw.SKLearnClassifierWrapper(
            classifier=mock.Mock(), preprocessing_handler=identity_preprocessor
        )

        X2, y2 = wrapper.process_flows(X.copy(), y.copy())

        # original length 2, after adding dummy -> 3
        assert X2.shape[0] == X.shape[0] + 1
        assert y2.shape[0] == y.shape[0] + 1
        assert cw.BENIGN in y2
        assert cw.MALICIOUS in y2

        identity_preprocessor.transform.assert_called()
        assert wrapper.is_trained is True

    def test_process_flows_no_missing_class_leaves_data_unchanged(
        self, identity_preprocessor, simple_X_y
    ):
        X, y = simple_X_y
        wrapper = cw.SKLearnClassifierWrapper(
            classifier=mock.Mock(), preprocessing_handler=identity_preprocessor
        )
        # Compose input with both classes
        X_both = np.vstack([X, wrapper.dummy_flows[cw.MALICIOUS][0]])
        y_both = np.concatenate([y, np.array([cw.MALICIOUS])])

        X2, y2 = wrapper.process_flows(X_both.copy(), y_both.copy())
        # No addition performed
        assert X2.shape[0] == X_both.shape[0]
        assert y2.shape[0] == y_both.shape[0]
        identity_preprocessor.transform.assert_not_called()

    def test_process_flows_shrinks_dummy_class_when_missing(
        self, shrinking_preprocessor, simple_X_y
    ):
        X, y = simple_X_y
        wrapper = cw.SKLearnClassifierWrapper(
            classifier=mock.Mock(),
            preprocessing_handler=shrinking_preprocessor,
        )
        X2 = shrinking_preprocessor.transform(X.copy())
        X2, y2 = wrapper.process_flows(X2, y.copy())

        # The dummy added should be transformed/shrunk to 7 features
        dummy_added = X2[-1]  # last row is the dummy for MALICIOUS
        assert dummy_added.shape[0] == 7
        assert y2[-1] == cw.MALICIOUS
        shrinking_preprocessor.transform.assert_called()


class TestNativeFittingCall:
    def test_native_fitting_function_is_called_on_partial_fit(
        self, identity_preprocessor, simple_X_y
    ):
        X, y = simple_X_y

        # Use SKLearn wrapper
        wrapper = cw.SKLearnClassifierWrapper(
            classifier=mock.Mock(), preprocessing_handler=identity_preprocessor
        )

        # Patch the native_fitting_function method on the instance
        wrapper.native_fitting_function = mock.Mock()

        # First call, is_trained = False -> process_flows should add dummy
        wrapper.is_trained = False
        wrapper.partial_fit(X.copy(), y.copy())

        # Ensure native_fitting_function was called once with X and y
        wrapper.native_fitting_function.assert_called()
        called_args, called_kwargs = wrapper.native_fitting_function.call_args

        # Check that X and y were passed
        np.testing.assert_array_equal(
            called_args[0][: len(X)], X
        )  # the original X is part of the batch
        np.testing.assert_array_equal(
            called_args[1][: len(y)], y
        )  # original y included

        # Second call, already trained -> native_fitting_function called again without classes kwarg
        wrapper.partial_fit(X.copy(), y.copy())
        assert wrapper.native_fitting_function.call_count == 2


class TestSKLearnWrapperPartialFitAndIO:
    def test_partial_fit_calls_classifier_partial_fit_with_classes_on_first_fit(
        self, identity_preprocessor, simple_X_y
    ):
        X, y = simple_X_y
        clf = mock.Mock()
        wrapper = cw.SKLearnClassifierWrapper(
            classifier=clf, preprocessing_handler=identity_preprocessor
        )
        wrapper.partial_fit(X.copy(), y.copy())
        assert clf.partial_fit.called
        found_classes_kw = any(
            (
                "classes" in call.kwargs
                and set(call.kwargs["classes"]) == set(wrapper.classes)
            )
            for call in clf.partial_fit.mock_calls
            if isinstance(call, mock._Call)
        )
        assert found_classes_kw is True

    def test_partial_fit_calls_classifier_partial_fit_without_classes_when_already_trained(
        self, identity_preprocessor, simple_X_y
    ):
        X, y = simple_X_y
        clf = mock.Mock()
        wrapper = cw.SKLearnClassifierWrapper(
            classifier=clf, preprocessing_handler=identity_preprocessor
        )
        wrapper.is_trained = True
        wrapper.partial_fit(X.copy(), y.copy())
        assert clf.partial_fit.called
        has_call_without_classes = any(
            "classes" not in call.kwargs for call in clf.partial_fit.mock_calls
        )
        assert has_call_without_classes

    def test_save_and_load_classifier_roundtrip(self, tmp_path):
        clf = {"some": "object", "value": 123}
        wrapper = cw.SKLearnClassifierWrapper(
            classifier=clf, preprocessing_handler=None
        )
        wrapper.save_classifier(path=tmp_path, name="classifier.pkl")
        saved_file = tmp_path / "classifier.pkl"
        assert saved_file.exists()
        new_wrapper = cw.SKLearnClassifierWrapper(
            classifier=None, preprocessing_handler=None
        )
        new_wrapper.load_classifier(path=tmp_path, name="classifier.pkl")
        assert isinstance(new_wrapper.classifier, dict)
        assert new_wrapper.classifier["value"] == 123
        assert new_wrapper.is_trained is True


class DummyRiverLearnMany:
    def __init__(self, make_predict_many=True):
        self.learn_many = mock.Mock()
        if make_predict_many:
            self.predict_many = mock.Mock(return_value=[cw.BENIGN] * 2)
        else:

            def raise_fn(*a, **kw):
                raise RuntimeError("predict_many failing")

            self.predict_many = mock.Mock(side_effect=raise_fn)
        self.learn_one = mock.Mock()
        self.predict_one = mock.Mock(side_effect=lambda xi: cw.BENIGN)


class TestRiverWrapper:
    def test_partial_fit_uses_learn_many_when_available(
        self, identity_preprocessor, simple_X_y
    ):
        river = DummyRiverLearnMany(make_predict_many=True)
        wrapper = cw.RiverClassifierWrapper(
            classifier=river, preprocessing_handler=identity_preprocessor
        )
        X, y = simple_X_y
        wrapper.partial_fit(X, y)
        assert river.learn_many.called

    def test_predict_prefers_predict_many_and_falls_back_when_it_raises(
        self, identity_preprocessor, simple_X_y
    ):
        river1 = DummyRiverLearnMany(make_predict_many=True)
        wrapper1 = cw.RiverClassifierWrapper(
            classifier=river1, preprocessing_handler=identity_preprocessor
        )
        X, y = simple_X_y
        preds1 = wrapper1.predict(X)
        assert isinstance(preds1, np.ndarray)
        assert preds1.shape[0] == X.shape[0]
        assert all(p == cw.BENIGN for p in preds1)

        river2 = DummyRiverLearnMany(make_predict_many=False)
        wrapper2 = cw.RiverClassifierWrapper(
            classifier=river2, preprocessing_handler=identity_preprocessor
        )
        preds2 = wrapper2.predict(X)
        assert isinstance(preds2, np.ndarray)
        assert preds2.shape[0] == X.shape[0]
        assert river2.predict_one.called


if __name__ == "__main__":
    pytest.main([__file__])
