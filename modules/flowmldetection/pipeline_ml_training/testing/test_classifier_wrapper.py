# test_classifier_wrapper.py
import sys
import types
from unittest import mock

import numpy as np
import pytest

# Now import the module-under-test (assumes you saved your class code to classifier_wrapper.py)
from pipeline_ml_training import classifier_wrapper as cw

# Provide a tiny 'commons' module for the imported code to use.
# This avoids requiring a real commons file during tests.
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
        # use a dummy classifier (not used by process_flows)
        wrapper = cw.SKLearnClassifierWrapper(
            classifier=mock.Mock(), preprocessing_handler=identity_preprocessor
        )

        # ensure the dummy_flows include malicious (they are created in __init__)
        assert cw.MALICIOUS in wrapper.dummy_flows

        X2, y2 = wrapper.process_flows(X.copy(), y.copy())

        # original length 2, after adding missing class length should be 3
        assert X2.shape[0] == X.shape[0] + 1
        assert y2.shape[0] == y.shape[0] + 1

        # ensure both classes present in returned y
        assert cw.BENIGN in y2
        assert cw.MALICIOUS in y2

        # transform should have been called once for the missing dummy class
        identity_preprocessor.transform.assert_called()
        # confirm wrapper marked as trained
        assert wrapper.is_trained is True

    def test_process_flows_no_missing_class_leaves_data_unchanged(
        self, identity_preprocessor, simple_X_y
    ):
        X, y = simple_X_y
        # add a malicious sample so both classes exist
        wrapper = None
        wrapper = cw.SKLearnClassifierWrapper(
            classifier=mock.Mock(), preprocessing_handler=identity_preprocessor
        )
        # Compose an input with both classes present
        X_both = np.vstack([X, wrapper.dummy_flows[cw.MALICIOUS][0]])
        y_both = np.concatenate([y, np.array([cw.MALICIOUS])])

        X2, y2 = wrapper.process_flows(X_both.copy(), y_both.copy())
        # no addition performed -> same sample count
        assert X2.shape[0] == X_both.shape[0]
        assert y2.shape[0] == y_both.shape[0]
        # transform shouldn't be called because no dummy needed
        identity_preprocessor.transform.assert_not_called()


class TestSKLearnWrapperPartialFitAndIO:
    def test_partial_fit_calls_classifier_partial_fit_with_classes_on_first_fit(
        self, identity_preprocessor, simple_X_y
    ):
        X, y = simple_X_y
        # create a classifier mock implementing partial_fit
        clf = mock.Mock()
        wrapper = cw.SKLearnClassifierWrapper(
            classifier=clf, preprocessing_handler=identity_preprocessor
        )

        # call partial_fit when not trained yet -> process_flows will add missing class and then call classifier.partial_fit
        wrapper.partial_fit(X.copy(), y.copy())

        # classifier.partial_fit should have been called at least once
        assert clf.partial_fit.called

        # The first call should have had classes=... as a keyword argument (passed by wrapper.native_fitting_function)
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

        # mark as trained (simulate subsequent partial_fit)
        wrapper.is_trained = True

        wrapper.partial_fit(X.copy(), y.copy())

        # classifier.partial_fit should be called and at least one call should not include 'classes' kwarg
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

        # save classifier under classifier.pkl
        wrapper.save_classifier(path=tmp_path, name="classifier.pkl")
        saved_file = tmp_path / "classifier.pkl"
        assert saved_file.exists()

        # create a new wrapper and load from disk
        new_wrapper = cw.SKLearnClassifierWrapper(
            classifier=None, preprocessing_handler=None
        )
        new_wrapper.load_classifier(path=tmp_path, name="classifier.pkl")

        # After load_classifier the classifier attribute should be the pickled object
        assert isinstance(new_wrapper.classifier, dict)
        assert new_wrapper.classifier["value"] == 123
        assert new_wrapper.is_trained is True


class DummyRiverLearnMany:
    def __init__(self, make_predict_many=True):
        self.learn_many = mock.Mock()
        if make_predict_many:
            self.predict_many = mock.Mock(return_value=[cw.BENIGN] * 2)
        else:
            # create a predict_many that raises to force fallback
            def raise_fn(*a, **kw):
                raise RuntimeError("predict_many failing")

            self.predict_many = mock.Mock(side_effect=raise_fn)

        # fallback per-sample
        self.learn_one = mock.Mock()
        self.predict_one = mock.Mock(side_effect=lambda xi: cw.BENIGN)


class TestRiverWrapper:
    def test_partial_fit_uses_learn_many_when_available(self):
        river = DummyRiverLearnMany(make_predict_many=True)
        wrapper = cw.RiverClassifierWrapper(
            classifier=river, preprocessing_handler=None
        )

        # small batch X,y
        X = np.array([[1.0, 2.0, 3.0], [4.0, 5.0, 6.0]])
        y = np.array([cw.BENIGN, cw.BENIGN])

        wrapper.partial_fit(X, y)

        # learn_many should have been called once
        assert river.learn_many.called

    def test_predict_prefers_predict_many_and_falls_back_when_it_raises(self):
        # Case 1: predict_many available
        river1 = DummyRiverLearnMany(make_predict_many=True)
        wrapper1 = cw.RiverClassifierWrapper(
            classifier=river1, preprocessing_handler=None
        )
        X = np.array([[0.1, 0.2], [0.3, 0.4]])
        preds1 = wrapper1.predict(X)
        assert isinstance(preds1, np.ndarray)
        assert preds1.shape[0] == X.shape[0]
        assert all(p == cw.BENIGN for p in preds1)

        # Case 2: predict_many raises -> fallback to predict_one
        river2 = DummyRiverLearnMany(make_predict_many=False)
        wrapper2 = cw.RiverClassifierWrapper(
            classifier=river2, preprocessing_handler=None
        )
        preds2 = wrapper2.predict(X)
        assert isinstance(preds2, np.ndarray)
        assert preds2.shape[0] == X.shape[0]
        # ensure predict_one was used on fallback
        assert river2.predict_one.called


# If you want to run test module directly
if __name__ == "__main__":
    pytest.main([__file__])
