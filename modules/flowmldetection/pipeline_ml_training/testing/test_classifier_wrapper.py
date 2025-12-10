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


class TestClassifierWrapperCustomClasses:
    """Test suite for custom classes parameter in ClassifierWrapper."""

    def test_initialization_with_default_classes(self, identity_preprocessor):
        """Test ClassifierWrapper initializes with default [BENIGN, MALICIOUS] when classes=None."""
        wrapper = cw.SKLearnClassifierWrapper(
            classifier=mock.Mock(),
            preprocessing_handler=identity_preprocessor,
            classes=None,
        )
        assert wrapper.classes == [cw.BENIGN, cw.MALICIOUS]

    def test_initialization_requires_at_least_two_classes(
        self, identity_preprocessor
    ):
        """Test ClassifierWrapper requires at least 2 classes."""
        with pytest.raises(AssertionError):
            cw.SKLearnClassifierWrapper(
                classifier=mock.Mock(),
                preprocessing_handler=identity_preprocessor,
                classes=["only_one"],
            )

    def test_initialization_with_exactly_two_classes(
        self, identity_preprocessor
    ):
        """Test ClassifierWrapper accepts exactly 2 classes."""
        wrapper = cw.SKLearnClassifierWrapper(
            classifier=mock.Mock(),
            preprocessing_handler=identity_preprocessor,
            classes=["class_a", "class_b"],
        )
        assert wrapper.classes == ["class_a", "class_b"]

    def test_dummy_flows_includes_default(self, identity_preprocessor):
        """Test that dummy_flows includes default flow for fallback."""
        wrapper = cw.SKLearnClassifierWrapper(
            classifier=mock.Mock(),
            preprocessing_handler=identity_preprocessor,
            classes=None,
        )
        assert "default" in wrapper.dummy_flows
        assert cw.BENIGN in wrapper.dummy_flows
        assert cw.MALICIOUS in wrapper.dummy_flows
        assert len(wrapper.dummy_flows) == 3

    def test_custom_classes_without_benign_malicious_dummy_flows(
        self, identity_preprocessor
    ):
        """Test that custom classes use default dummy flow as fallback."""
        custom_classes = ["safe", "dangerous"]
        wrapper = cw.SKLearnClassifierWrapper(
            classifier=mock.Mock(),
            preprocessing_handler=identity_preprocessor,
            classes=custom_classes,
        )
        # dummy_flows has BENIGN, MALICIOUS, and default
        assert wrapper.dummy_flows.get(cw.BENIGN) is not None
        assert wrapper.dummy_flows.get(cw.MALICIOUS) is not None
        assert wrapper.dummy_flows.get("default") is not None
        # Custom classes don't have specific dummies, but will use default
        assert wrapper.dummy_flows.get("safe") is None
        assert wrapper.dummy_flows.get("dangerous") is None

    def test_process_flows_with_custom_classes_missing_class_raises_error(
        self, identity_preprocessor
    ):
        """Test process_flows uses default dummy for missing custom class."""
        custom_classes = ["safe", "dangerous"]
        X = np.array([[10.0] * 11])
        y = np.array(["safe"])  # Missing "dangerous"

        wrapper = cw.SKLearnClassifierWrapper(
            classifier=mock.Mock(),
            preprocessing_handler=identity_preprocessor,
            classes=custom_classes,
        )

        # Should NOT raise - will use default dummy for "dangerous"
        X2, y2 = wrapper.process_flows(X, y)

        assert X2.shape[0] == 2  # Original + 1 dummy
        assert y2.shape[0] == 2
        assert "dangerous" in y2

    def test_process_flows_with_custom_classes_all_present(
        self, identity_preprocessor
    ):
        """Test process_flows doesn't add dummies when all custom classes are present."""
        custom_classes = ["safe", "dangerous"]
        X = np.array(
            [
                [10.0] * 11,
                [20.0] * 11,
            ]
        )
        y = np.array(["safe", "dangerous"])

        wrapper = cw.SKLearnClassifierWrapper(
            classifier=mock.Mock(),
            preprocessing_handler=identity_preprocessor,
            classes=custom_classes,
        )

        X2, y2 = wrapper.process_flows(X.copy(), y.copy())

        # No dummies added
        assert X2.shape[0] == X.shape[0]
        assert y2.shape[0] == y.shape[0]
        assert set(y2) == {"safe", "dangerous"}

    def test_partial_fit_with_custom_classes_uses_correct_classes_kwarg(
        self, identity_preprocessor
    ):
        """Test partial_fit passes custom classes to classifier on first fit (when all classes present)."""
        custom_classes = ["type_a", "type_b", "type_c"]
        X = np.array(
            [
                [10.0] * 11,
                [20.0] * 11,
                [30.0] * 11,
            ]
        )
        y = np.array(["type_a", "type_b", "type_c"])  # All classes present

        clf = mock.Mock()
        wrapper = cw.SKLearnClassifierWrapper(
            classifier=clf,
            preprocessing_handler=identity_preprocessor,
            classes=custom_classes,
        )

        wrapper.partial_fit(X, y)

        # Check that classifier.partial_fit was called with classes kwarg
        assert clf.partial_fit.called
        call_kwargs = clf.partial_fit.call_args[1]
        assert "classes" in call_kwargs
        assert set(call_kwargs["classes"]) == set(custom_classes)

    def test_partial_fit_first_fit_with_default_classes(
        self, identity_preprocessor, simple_X_y
    ):
        """Test partial_fit with default classes uses [BENIGN, MALICIOUS]."""
        X, y = simple_X_y  # Only has BENIGN
        clf = mock.Mock()

        wrapper = cw.SKLearnClassifierWrapper(
            classifier=clf,
            preprocessing_handler=identity_preprocessor,
            classes=None,  # Default
        )

        wrapper.partial_fit(X, y)

        call_kwargs = clf.partial_fit.call_args[1]
        assert "classes" in call_kwargs
        assert set(call_kwargs["classes"]) == {cw.BENIGN, cw.MALICIOUS}

    def test_predict_with_custom_classes(self, identity_preprocessor):
        """Test predict works with custom classes."""
        custom_classes = ["red", "blue", "green"]
        X = np.array([[10.0] * 11, [20.0] * 11])

        clf = mock.Mock()
        clf.predict = mock.Mock(return_value=np.array(["red", "blue"]))

        wrapper = cw.SKLearnClassifierWrapper(
            classifier=clf,
            preprocessing_handler=identity_preprocessor,
            classes=custom_classes,
        )

        predictions = wrapper.predict(X)

        assert np.array_equal(predictions, np.array(["red", "blue"]))
        clf.predict.assert_called_once()

    def test_get_classifier_returns_correct_classifier_custom_classes(
        self, identity_preprocessor
    ):
        """Test getClassifier returns the classifier regardless of custom classes."""
        custom_classes = ["a", "b"]
        test_clf = {"test": "classifier"}

        wrapper = cw.SKLearnClassifierWrapper(
            classifier=test_clf,
            preprocessing_handler=identity_preprocessor,
            classes=custom_classes,
        )

        assert wrapper.getClassifier() is test_clf


class TestRiverWrapperWithCustomClasses:
    """Test River wrapper with custom classes."""

    def test_river_partial_fit_with_custom_classes(
        self, identity_preprocessor
    ):
        """Test River wrapper partial_fit with custom classes (missing class uses default dummy)."""
        custom_classes = ["stream_a", "stream_b"]
        X = np.array([[10.0] * 11])
        y = np.array(["stream_a"])  # Missing stream_b

        river = DummyRiverLearnMany(make_predict_many=True)
        wrapper = cw.RiverClassifierWrapper(
            classifier=river,
            preprocessing_handler=identity_preprocessor,
            classes=custom_classes,
        )

        # Should NOT raise - will use default dummy for stream_b
        wrapper.partial_fit(X, y)

        # River wrapper uses learn_many
        assert wrapper.classes == custom_classes
        assert river.learn_many.called
        # Verify default dummy was used for missing class
        call_args = river.learn_many.call_args[0]
        X_batch_data = call_args[0]
        # X should have 2 samples (original + default dummy)
        assert X_batch_data[0].shape[0] == 2

    def test_river_predict_with_custom_classes(self, identity_preprocessor):
        """Test River wrapper predict works with custom classes."""
        custom_classes = ["x", "y", "z"]
        X = np.array([[10.0] * 11, [20.0] * 11])

        river = DummyRiverLearnMany(make_predict_many=True)
        river.predict_many = mock.Mock(return_value=["x", "y"])

        wrapper = cw.RiverClassifierWrapper(
            classifier=river,
            preprocessing_handler=identity_preprocessor,
            classes=custom_classes,
        )

        predictions = wrapper.predict(X)

        assert wrapper.classes == custom_classes
        assert np.array_equal(predictions, np.array(["x", "y"]))


class TestCustomClassesEdgeCases:
    """Test edge cases and special scenarios with custom classes."""

    def test_custom_classes_empty_list_raises_error_during_training(
        self, identity_preprocessor
    ):
        """Test that empty classes list raises assertion error."""
        with pytest.raises(AssertionError):
            cw.SKLearnClassifierWrapper(
                classifier=mock.Mock(),
                preprocessing_handler=identity_preprocessor,
                classes=[],
            )

    def test_custom_classes_with_duplicate_values(self, identity_preprocessor):
        """Test initialization with duplicate classes in list."""
        classes_with_dupes = ["a", "b", "a"]
        wrapper = cw.SKLearnClassifierWrapper(
            classifier=mock.Mock(),
            preprocessing_handler=identity_preprocessor,
            classes=classes_with_dupes,
        )
        # Wrapper stores classes as-is (duplicates allowed at init level)
        assert wrapper.classes == classes_with_dupes

    def test_custom_classes_numeric_types(self, identity_preprocessor):
        """Test custom classes with numeric types."""
        numeric_classes = [0, 1, 2]
        X = np.array([[10.0] * 11, [20.0] * 11])
        y = np.array([0, 1])

        clf = mock.Mock()
        wrapper = cw.SKLearnClassifierWrapper(
            classifier=clf,
            preprocessing_handler=identity_preprocessor,
            classes=numeric_classes,
        )

        wrapper.partial_fit(X, y)

        call_kwargs = clf.partial_fit.call_args[1]
        assert set(call_kwargs["classes"]) == {0, 1, 2}

    def test_partial_fit_with_custom_classes_missing_one_class(
        self, identity_preprocessor
    ):
        """Test partial_fit with custom classes when one class is missing uses default dummy."""
        custom_classes = ["type_a", "type_b", "type_c"]
        X = np.array(
            [
                [10.0] * 11,
                [20.0] * 11,
            ]
        )
        y = np.array(["type_a", "type_b"])  # Missing type_c

        clf = mock.Mock()
        wrapper = cw.SKLearnClassifierWrapper(
            classifier=clf,
            preprocessing_handler=identity_preprocessor,
            classes=custom_classes,
        )

        # Should NOT raise - will use default dummy for type_c
        wrapper.partial_fit(X, y)

        # Verify classifier was called with all 3 classes
        assert clf.partial_fit.called
        call_args, call_kwargs = clf.partial_fit.call_args
        assert call_kwargs["classes"] == custom_classes
        # X should have been augmented with default dummy for type_c
        assert call_args[0].shape[0] == 3  # 2 original + 1 dummy

    def test_classes_order_preserved_in_partial_fit(
        self, identity_preprocessor
    ):
        """Test that classes order is preserved when passed to classifier."""
        classes = ["z_class", "a_class", "m_class"]  # Non-alphabetical order
        X = np.array([[10.0] * 11])
        y = np.array(["z_class"])

        clf = mock.Mock()
        wrapper = cw.SKLearnClassifierWrapper(
            classifier=clf,
            preprocessing_handler=identity_preprocessor,
            classes=classes,
        )

        wrapper.partial_fit(X, y)

        call_kwargs = clf.partial_fit.call_args[1]
        # Classes should be passed in the exact order specified
        assert call_kwargs["classes"] == classes
