import pytest
import tempfile
import numpy as np
from pathlib import Path
from unittest.mock import Mock
from pipeline_ml_training.preprocessing_wrapper import PreprocessingWrapper


class DummyTransformer:
    """Dummy transformer for testing with fit, partial_fit, and transform."""

    def __init__(self):
        self.fitted = False
        self.partial_fit_called = 0
        self.transform_called = 0
        self.stored_X = None

    def fit(self, X, y=None):
        self.fitted = True
        self.stored_X = X
        return self

    def partial_fit(self, X, y=None):
        self.fitted = True
        self.partial_fit_called += 1
        self.stored_X = X
        return self

    def transform(self, X):
        self.transform_called += 1
        return X * 2  # Simple transformation


class DummyTransformerNoPartialFit:
    """Dummy transformer with only fit and transform, no partial_fit."""

    def __init__(self):
        self.fitted = False
        self.stored_X = None

    def fit(self, X, y=None):
        self.fitted = True
        self.stored_X = X
        return self

    def transform(self, X):
        return X + 1  # Simple transformation


class TestPreprocessingWrapper:
    """Comprehensive test suite for PreprocessingWrapper class."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for model storage."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    @pytest.fixture
    def sample_data(self):
        """Create sample X and y data for testing."""
        X = np.array([[1, 2], [3, 4], [5, 6]])
        y = np.array([0, 1, 0])
        return X, y

    # ========== Initialization Tests ==========
    def test_initialization_defaults(self):
        """Test PreprocessingWrapper initializes with defaults."""
        wrapper = PreprocessingWrapper()

        assert wrapper.steps == []
        assert wrapper.experiment_name == "default"
        assert wrapper.is_fitted == {}
        assert wrapper._has_been_fitted_once is False

    def test_initialization_with_steps(self):
        """Test PreprocessingWrapper initializes with provided steps."""
        transformer1 = DummyTransformer()
        transformer2 = DummyTransformer()
        steps = [("step1", transformer1), ("step2", transformer2)]

        wrapper = PreprocessingWrapper(steps=steps, experiment_name="test_exp")

        assert len(wrapper.steps) == 2
        assert wrapper.experiment_name == "test_exp"
        assert wrapper.is_fitted == {"step1": False, "step2": False}

    # ========== Add Step Tests ==========
    def test_add_step_before_fitting(self):
        """Test adding steps before any fitting occurs."""
        wrapper = PreprocessingWrapper(experiment_name="test")
        transformer = DummyTransformer()

        wrapper.add_step("new_step", transformer)

        assert len(wrapper.steps) == 1
        assert wrapper.steps[0] == ("new_step", transformer)
        assert wrapper.is_fitted["new_step"] is False

    def test_add_step_after_fitting_warns(self, capsys):
        """Test adding step after fitting produces warning."""
        wrapper = PreprocessingWrapper(experiment_name="test")
        transformer1 = DummyTransformer()

        wrapper.add_step("step1", transformer1)
        wrapper.partial_fit(np.array([[1, 2]]))

        # Add another step after fitting
        transformer2 = DummyTransformer()
        wrapper.add_step("step2", transformer2)

        captured = capsys.readouterr()
        assert "[WARNING]" in captured.out
        assert "Adding new step" in captured.out

    def test_add_multiple_steps(self):
        """Test adding multiple steps sequentially."""
        wrapper = PreprocessingWrapper()

        for i in range(3):
            wrapper.add_step(f"step{i}", DummyTransformer())

        assert len(wrapper.steps) == 3
        assert all(f"step{i}" in dict(wrapper.steps).keys() for i in range(3))

    # ========== Partial Fit Tests ==========
    def test_partial_fit_first_time_calls_fit(self, sample_data):
        """Test partial_fit calls fit() on first invocation."""
        X, y = sample_data
        transformer = DummyTransformer()
        wrapper = PreprocessingWrapper(steps=[("step1", transformer)])

        wrapper.partial_fit(X, y)

        assert transformer.fitted is True
        assert wrapper.is_fitted["step1"] is True
        assert wrapper._has_been_fitted_once is True
        np.testing.assert_array_equal(transformer.stored_X, X)

    def test_partial_fit_subsequent_calls_use_partial_fit(self, sample_data):
        """Test partial_fit uses partial_fit() method on subsequent calls."""
        X, y = sample_data
        transformer = DummyTransformer()
        wrapper = PreprocessingWrapper(steps=[("step1", transformer)])

        wrapper.partial_fit(X, y)
        assert transformer.partial_fit_called == 0  # First call uses fit()

        wrapper.partial_fit(X, y)
        assert (
            transformer.partial_fit_called == 1
        )  # Second call uses partial_fit()

    def test_partial_fit_multiple_steps(self, sample_data):
        """Test partial_fit processes all steps in sequence."""
        X, y = sample_data
        transformer1 = DummyTransformer()
        transformer2 = DummyTransformer()

        steps = [("step1", transformer1), ("step2", transformer2)]
        wrapper = PreprocessingWrapper(steps=steps)

        wrapper.partial_fit(X, y)

        assert transformer1.fitted is True
        assert transformer2.fitted is True
        assert wrapper.is_fitted["step1"] is True
        assert wrapper.is_fitted["step2"] is True

    def test_partial_fit_without_fit_method_raises_error(self, sample_data):
        """Test partial_fit raises error if transformer lacks fit method."""
        X, y = sample_data
        bad_transformer = Mock(spec=[])  # No fit or partial_fit

        wrapper = PreprocessingWrapper(steps=[("bad_step", bad_transformer)])

        with pytest.raises(AttributeError):
            wrapper.partial_fit(X, y)

    def test_partial_fit_with_only_partial_fit_no_fit(self, sample_data):
        """Test partial_fit with transformer having only partial_fit method."""
        X, y = sample_data
        transformer = DummyTransformer()
        # Remove fit method to simulate transformer with only partial_fit
        transformer.fit = None

        wrapper = PreprocessingWrapper(steps=[("step1", transformer)])

        # Should not fail because transformer has partial_fit
        try:
            wrapper.partial_fit(X, y)
        except Exception as e:
            pytest.fail(f"partial_fit raised an unexpected exception: {e}")

    def test_partial_fit_error_propagation(self, sample_data):
        """Test partial_fit propagates errors from transformers."""
        X, y = sample_data
        bad_transformer = Mock()
        bad_transformer.fit.side_effect = ValueError("Fitting failed")

        wrapper = PreprocessingWrapper(steps=[("bad_step", bad_transformer)])

        with pytest.raises(ValueError):
            wrapper.partial_fit(X, y)

    # ========== Transform Tests ==========
    def test_transform_applies_all_steps(self, sample_data):
        """Test transform applies transformations from all steps in sequence."""
        X, y = sample_data
        transformer1 = DummyTransformer()
        transformer2 = DummyTransformer()

        steps = [("step1", transformer1), ("step2", transformer2)]
        wrapper = PreprocessingWrapper(steps=steps)
        wrapper.partial_fit(X, y)

        result = wrapper.transform(X)

        # Step1: X * 2, Step2: (X * 2) * 2 = X * 4
        expected = X * 4
        np.testing.assert_array_equal(result, expected)
        assert transformer1.transform_called == 1
        assert transformer2.transform_called == 1

    def test_transform_unfitted_step_raises_error(self, sample_data):
        """Test transform raises error if any step not fitted."""
        X, y = sample_data
        transformer = DummyTransformer()
        wrapper = PreprocessingWrapper(steps=[("step1", transformer)])

        with pytest.raises(RuntimeError):
            wrapper.transform(X)

    def test_transform_error_propagation(self, sample_data):
        """Test transform propagates errors from transformers."""
        X, y = sample_data
        transformer = Mock()
        transformer.transform.side_effect = ValueError("Transform failed")

        wrapper = PreprocessingWrapper(steps=[("bad_step", transformer)])
        wrapper.is_fitted["bad_step"] = True  # Mark as fitted to bypass check

        with pytest.raises(ValueError):
            wrapper.transform(X)

    def test_transform_chaining_order(self, sample_data):
        """Test transform applies steps in correct order."""
        X, y = sample_data

        # Create transformers that multiply and add
        class MultiplyTransformer:
            def fit(self, X, y=None):
                return self

            def transform(self, X):
                return X * 3

        class AddTransformer:
            def fit(self, X, y=None):
                return self

            def transform(self, X):
                return X + 10

        steps = [
            ("multiply", MultiplyTransformer()),
            ("add", AddTransformer()),
        ]
        wrapper = PreprocessingWrapper(steps=steps)
        wrapper.partial_fit(X, y)

        result = wrapper.transform(X)

        # (X * 3) + 10
        expected = X * 3 + 10
        np.testing.assert_array_equal(result, expected)

    def test_save_creates_nested_directories(self, temp_dir, sample_data):
        """Test save creates nested directory structure with default path."""
        X, y = sample_data
        transformer = DummyTransformer()

        wrapper = PreprocessingWrapper(
            steps=[("step1", transformer)],
            experiment_name="nested/exp",
            base_models_dir=temp_dir,
        )
        wrapper.partial_fit(X, y)
        wrapper.save()  # No base_path - uses default

        assert (Path(temp_dir) / "nested" / "exp" / "preprocessing").exists()
        assert (
            Path(temp_dir) / "nested" / "exp" / "preprocessing" / "step1.bin"
        ).exists()

    def test_load_nonexistent_directory_raises_error(self, temp_dir):
        """Test load raises error if preprocessing directory doesn't exist."""
        wrapper = PreprocessingWrapper(
            steps=[("step1", None)], experiment_name="nonexistent"
        )

        with pytest.raises(FileNotFoundError):
            wrapper.load(base_path=temp_dir)

    def test_load_missing_step_file_raises_error(self, temp_dir, sample_data):
        """Test load raises error if step file not found."""
        X, y = sample_data
        transformer = DummyTransformer()

        # Save only one step
        wrapper1 = PreprocessingWrapper(
            steps=[("scaler", transformer)], experiment_name="test_exp"
        )
        wrapper1.partial_fit(X, y)
        wrapper1.save(base_path=temp_dir)

        # Try to load with missing step
        wrapper2 = PreprocessingWrapper(
            steps=[("scaler", None), ("missing", None)],
            experiment_name="test_exp",
        )

        with pytest.raises(FileNotFoundError):
            wrapper2.load(base_path=temp_dir)

    # ========== Replace Transformer Tests ==========
    def test_replace_transformer_updates_step(self):
        """Test _replace_transformer updates transformer in steps list."""
        transformer1 = DummyTransformer()
        transformer2 = DummyTransformer()
        transformer3 = DummyTransformer()

        wrapper = PreprocessingWrapper(
            steps=[("step1", transformer1), ("step2", transformer2)]
        )

        wrapper._replace_transformer("step1", transformer3)

        steps_dict = dict(wrapper.steps)
        assert steps_dict["step1"] is transformer3
        assert steps_dict["step2"] is transformer2

    def test_replace_transformer_preserves_step_order(self):
        """Test _replace_transformer preserves step order."""
        transformers = [DummyTransformer() for _ in range(3)]
        steps = [(f"step{i}", transformers[i]) for i in range(3)]

        wrapper = PreprocessingWrapper(steps=steps)
        new_transformer = DummyTransformer()
        wrapper._replace_transformer("step1", new_transformer)

        step_names = [name for name, _ in wrapper.steps]
        assert step_names == ["step0", "step1", "step2"]

    # ========== Get Steps Tests ==========
    def test_get_steps_returns_steps_list(self):
        """Test get_steps returns the steps list."""
        transformer1 = DummyTransformer()
        transformer2 = DummyTransformer()
        steps = [("step1", transformer1), ("step2", transformer2)]

        wrapper = PreprocessingWrapper(steps=steps)

        assert wrapper.get_steps() == steps

    # ========== Integration Tests ==========
    def test_integration_full_workflow(self, temp_dir, sample_data):
        """Integration test: full workflow from init to save/load."""
        X, y = sample_data

        # Create, fit, and save
        transformer1 = DummyTransformer()
        transformer2 = DummyTransformer()
        steps = [("scaler", transformer1), ("encoder", transformer2)]

        wrapper1 = PreprocessingWrapper(
            steps=steps, experiment_name="workflow_test"
        )
        wrapper1.partial_fit(X, y)
        result1 = wrapper1.transform(X)
        wrapper1.save(base_path=temp_dir)

        # Load and verify
        wrapper2 = PreprocessingWrapper(
            steps=[("scaler", None), ("encoder", None)],
            experiment_name="workflow_test",
        )
        wrapper2.load(base_path=temp_dir)
        result2 = wrapper2.transform(X)

        # Results should match
        np.testing.assert_array_equal(result1, result2)

    def test_integration_multiple_partial_fits(self, sample_data):
        """Integration test: multiple partial_fit calls."""
        X1, y1 = sample_data
        X2 = sample_data[0] * 2
        y2 = sample_data[1]

        transformer = DummyTransformer()
        wrapper = PreprocessingWrapper(steps=[("step1", transformer)])

        wrapper.partial_fit(X1, y1)
        first_partial_count = transformer.partial_fit_called

        wrapper.partial_fit(X2, y2)
        second_partial_count = transformer.partial_fit_called

        # Should have called partial_fit once on second call
        assert second_partial_count == first_partial_count + 1

    def test_integration_add_step_and_refit(self, sample_data):
        """Integration test: add step, fit all, transform."""
        X, y = sample_data

        transformer1 = DummyTransformer()
        wrapper = PreprocessingWrapper(steps=[("step1", transformer1)])
        wrapper.partial_fit(X, y)

        # Add another step
        transformer2 = DummyTransformer()
        wrapper.add_step("step2", transformer2)

        # Partial fit should fit the new step
        wrapper.partial_fit(X, y)

        assert wrapper.is_fitted["step2"] is True
        result = wrapper.transform(X)
        assert result.shape == X.shape

    def test_partial_fit_calls_fit_first_time(self, sample_data):
        """
        Test that fit is called on the first partial_fit and not partial_fit.
        """
        X, y = sample_data
        transformer = DummyTransformer()
        wrapper = PreprocessingWrapper(steps=[("step1", transformer)])

        wrapper.partial_fit(X, y)

        assert transformer.fitted is True
        assert transformer.partial_fit_called == 0

    def test_partial_fit_calls_partial_fit_after_first(self, sample_data):
        """
        Test that partial_fit is called on subsequent partial_fit calls.
        """
        X, y = sample_data
        transformer = DummyTransformer()
        wrapper = PreprocessingWrapper(steps=[("step1", transformer)])

        wrapper.partial_fit(X, y)
        wrapper.partial_fit(X, y)

        assert transformer.partial_fit_called == 1

    def test_partial_fit_uses_fit_if_partial_fit_not_available(
        self, sample_data
    ):
        """
        Test that fit is called every time if partial_fit is not available.
        """
        X, y = sample_data
        transformer = DummyTransformerNoPartialFit()
        wrapper = PreprocessingWrapper(steps=[("step1", transformer)])

        wrapper.partial_fit(X, y)
        wrapper.partial_fit(X, y)

        # DummyTransformerNoPartialFit does not have partial_fit, so fit should be called again
        assert transformer.fitted is True
        assert transformer.stored_X is X

    def test_partial_fit_multiple_steps_calls_fit_and_partial_fit(
        self, sample_data
    ):
        """
        Test that fit is called for all steps on first partial_fit, and partial_fit on subsequent calls.
        """
        X, y = sample_data
        t1 = DummyTransformer()
        t2 = DummyTransformer()
        wrapper = PreprocessingWrapper(steps=[("step1", t1), ("step2", t2)])

        wrapper.partial_fit(X, y)
        assert t1.fitted and t2.fitted
        assert t1.partial_fit_called == 0
        assert t2.partial_fit_called == 0

        wrapper.partial_fit(X, y)
        assert t1.partial_fit_called == 1
        assert t2.partial_fit_called == 1

    def test_partial_fit_with_mixed_transformers(self, sample_data):
        """
        Test that fit/partial_fit logic works with mixed transformers (some with only fit).
        """
        X, y = sample_data
        t1 = DummyTransformer()
        t2 = DummyTransformerNoPartialFit()
        wrapper = PreprocessingWrapper(steps=[("step1", t1), ("step2", t2)])

        wrapper.partial_fit(X, y)
        wrapper.partial_fit(X, y)

        assert t1.partial_fit_called == 1
        assert t2.fitted is True  # fit called again

    def test_partial_fit_sets_is_fitted_flag(self, sample_data):
        """
        Test that is_fitted flag is set to True after fitting.
        """
        X, y = sample_data
        transformer = DummyTransformer()
        wrapper = PreprocessingWrapper(steps=[("step1", transformer)])

        assert wrapper.is_fitted["step1"] is False
        wrapper.partial_fit(X, y)
        assert wrapper.is_fitted["step1"] is True

    def test_partial_fit_does_not_call_fit_if_already_fitted(
        self, sample_data
    ):
        """
        Test that fit is not called again if already fitted, only partial_fit.
        """
        X, y = sample_data
        transformer = DummyTransformer()
        wrapper = PreprocessingWrapper(steps=[("step1", transformer)])

        wrapper.partial_fit(X, y)
        wrapper.partial_fit(X, y)
        wrapper.partial_fit(X, y)

        assert transformer.partial_fit_called == 2

    def test_partial_fit_updates_scaler_mean(self, sample_data):
        """
        Test that calling partial_fit twice on a simple scaler updates the mean correctly.
        """

        class SimpleScaler:
            def __init__(self):
                self.n_samples = 0
                self.mean_ = None

            def fit(self, X, y=None):
                self.n_samples = X.shape[0]
                self.mean_ = np.mean(X, axis=0)
                return self

            def partial_fit(self, X, y=None):
                if self.mean_ is None:
                    self.fit(X, y)
                else:
                    total_samples = self.n_samples + X.shape[0]
                    new_mean = (
                        self.mean_ * self.n_samples + np.sum(X, axis=0)
                    ) / total_samples
                    self.mean_ = new_mean
                    self.n_samples = total_samples
                return self

            def transform(self, X):
                return X - self.mean_

        # First batch
        X1 = np.array([[1, 2], [3, 4]])
        # Second batch
        X2 = np.array([[5, 6]])

        scaler = SimpleScaler()
        wrapper = PreprocessingWrapper(steps=[("scaler", scaler)])

        wrapper.partial_fit(X1)
        wrapper.partial_fit(X2)

        # After both fits, mean should be mean of all three samples
        expected_mean = np.mean(np.vstack([X1, X2]), axis=0)
        np.testing.assert_array_almost_equal(scaler.mean_, expected_mean)

    # ========== Updated Initialization Tests ==========
    def test_initialization_with_custom_base_models_dir(self):
        """Test PreprocessingWrapper initializes with custom base_models_dir."""
        wrapper = PreprocessingWrapper(
            base_models_dir="/custom/models", experiment_name="test_exp"
        )
        assert wrapper.base_models_dir == Path("/custom/models")
        assert wrapper.experiment_name == "test_exp"

    def test_initialization_with_custom_step_filename_template(self):
        """Test PreprocessingWrapper initializes with custom step_filename_template."""
        wrapper = PreprocessingWrapper(step_filename_template="{name}.pkl")
        assert wrapper.step_filename_template == "{name}.pkl"

    def test_initialization_defaults_include_base_models_dir(self):
        """Test default base_models_dir is ./experiments."""
        wrapper = PreprocessingWrapper()
        assert wrapper.base_models_dir == Path("./experiments")
        assert wrapper.step_filename_template == "{name}.bin"

    # ========== Updated Save Tests ==========
    def test_save_without_base_path_uses_default(self, temp_dir, sample_data):
        """Test save uses base_models_dir/experiment_name/preprocessing when base_path is None."""
        X, y = sample_data
        transformer = DummyTransformer()

        wrapper = PreprocessingWrapper(
            steps=[("scaler", transformer)],
            experiment_name="test_exp",
            base_models_dir=temp_dir,
        )
        wrapper.partial_fit(X, y)
        wrapper.save()  # No base_path argument

        expected_path = (
            Path(temp_dir) / "test_exp" / "preprocessing" / "scaler.bin"
        )
        assert expected_path.exists()

    def test_save_with_explicit_base_path(self, temp_dir, sample_data):
        """Test save uses provided base_path when given."""
        X, y = sample_data
        transformer = DummyTransformer()
        custom_path = Path(temp_dir) / "custom_save"

        wrapper = PreprocessingWrapper(steps=[("scaler", transformer)])
        wrapper.partial_fit(X, y)
        wrapper.save(base_path=custom_path)

        assert (custom_path / "scaler.bin").exists()

    def test_save_uses_step_filename_template(self, temp_dir, sample_data):
        """Test save respects custom step_filename_template."""
        X, y = sample_data
        transformer1 = DummyTransformer()
        transformer2 = DummyTransformer()

        wrapper = PreprocessingWrapper(
            steps=[("scaler", transformer1), ("encoder", transformer2)],
            base_models_dir=temp_dir,
            experiment_name="test_exp",
            step_filename_template="{name}.pkl",
        )
        wrapper.partial_fit(X, y)
        wrapper.save()

        base_path = Path(temp_dir) / "test_exp" / "preprocessing"
        assert (base_path / "scaler.pkl").exists()
        assert (base_path / "encoder.pkl").exists()
        assert not (base_path / "scaler.bin").exists()

    def test_save_creates_files_with_default_template(
        self, temp_dir, sample_data
    ):
        """Test save creates .bin files by default."""
        X, y = sample_data
        transformer1 = DummyTransformer()
        transformer2 = DummyTransformer()

        wrapper = PreprocessingWrapper(
            steps=[("scaler", transformer1), ("encoder", transformer2)],
            base_models_dir=temp_dir,
            experiment_name="test_exp",
        )
        wrapper.partial_fit(X, y)
        wrapper.save()

        base_path = Path(temp_dir) / "test_exp" / "preprocessing"
        assert (base_path / "scaler.bin").exists()
        assert (base_path / "encoder.bin").exists()

    # ========== Updated Load Tests ==========
    def test_load_without_base_path_uses_default(self, temp_dir, sample_data):
        """Test load uses base_models_dir/experiment_name/preprocessing when base_path is None."""
        X, y = sample_data
        transformer1 = DummyTransformer()
        transformer2 = DummyTransformer()

        # Save
        wrapper1 = PreprocessingWrapper(
            steps=[("scaler", transformer1), ("encoder", transformer2)],
            experiment_name="test_exp",
            base_models_dir=temp_dir,
        )
        wrapper1.partial_fit(X, y)
        wrapper1.save()  # Uses default path

        # Load
        wrapper2 = PreprocessingWrapper(
            steps=[("scaler", None), ("encoder", None)],
            experiment_name="test_exp",
            base_models_dir=temp_dir,
        )
        wrapper2.load()  # Uses same default path

        assert wrapper2.is_fitted["scaler"] is True
        assert wrapper2.is_fitted["encoder"] is True

    def test_load_with_explicit_base_path(self, temp_dir, sample_data):
        """Test load uses provided base_path when given."""
        X, y = sample_data
        transformer = DummyTransformer()
        custom_path = Path(temp_dir) / "custom_save"

        # Save
        wrapper1 = PreprocessingWrapper(steps=[("scaler", transformer)])
        wrapper1.partial_fit(X, y)
        wrapper1.save(base_path=custom_path)

        # Load
        wrapper2 = PreprocessingWrapper(steps=[("scaler", None)])
        wrapper2.load(base_path=custom_path)

        assert wrapper2.is_fitted["scaler"] is True

    def test_load_uses_step_filename_template(self, temp_dir, sample_data):
        """Test load respects custom step_filename_template."""
        X, y = sample_data
        transformer1 = DummyTransformer()
        transformer2 = DummyTransformer()

        # Save with custom template
        wrapper1 = PreprocessingWrapper(
            steps=[("scaler", transformer1), ("encoder", transformer2)],
            base_models_dir=temp_dir,
            experiment_name="test_exp",
            step_filename_template="{name}.pkl",
        )
        wrapper1.partial_fit(X, y)
        wrapper1.save()

        # Load with same custom template
        wrapper2 = PreprocessingWrapper(
            steps=[("scaler", None), ("encoder", None)],
            base_models_dir=temp_dir,
            experiment_name="test_exp",
            step_filename_template="{name}.pkl",
        )
        wrapper2.load()

        assert wrapper2.is_fitted["scaler"] is True
        assert wrapper2.is_fitted["encoder"] is True

    def test_load_fails_with_wrong_template(self, temp_dir, sample_data):
        """Test load fails if using wrong step_filename_template."""
        X, y = sample_data
        transformer = DummyTransformer()

        # Save with .pkl
        wrapper1 = PreprocessingWrapper(
            steps=[("scaler", transformer)],
            base_models_dir=temp_dir,
            experiment_name="test_exp",
            step_filename_template="{name}.pkl",
        )
        wrapper1.partial_fit(X, y)
        wrapper1.save()

        # Try to load with .bin (wrong template)
        wrapper2 = PreprocessingWrapper(
            steps=[("scaler", None)],
            base_models_dir=temp_dir,
            experiment_name="test_exp",
            step_filename_template="{name}.bin",  # Wrong!
        )

        with pytest.raises(FileNotFoundError):
            wrapper2.load()

    def test_save_and_load_roundtrip_with_custom_params(
        self, temp_dir, sample_data
    ):
        """Integration test: save and load with custom base_models_dir and template."""
        X, y = sample_data
        transformer1 = DummyTransformer()
        transformer2 = DummyTransformer()

        # Save
        wrapper1 = PreprocessingWrapper(
            steps=[("step1", transformer1), ("step2", transformer2)],
            experiment_name="roundtrip_test",
            base_models_dir=temp_dir,
            step_filename_template="{name}.custom",
        )
        wrapper1.partial_fit(X, y)
        wrapper1.save()
        result1 = wrapper1.transform(X)

        # Load
        wrapper2 = PreprocessingWrapper(
            steps=[("step1", None), ("step2", None)],
            experiment_name="roundtrip_test",
            base_models_dir=temp_dir,
            step_filename_template="{name}.custom",
        )
        wrapper2.load()
        result2 = wrapper2.transform(X)

        np.testing.assert_array_equal(result1, result2)
        assert (
            Path(temp_dir)
            / "roundtrip_test"
            / "preprocessing"
            / "step1.custom"
        ).exists()

    def test_partial_fit_raises_error_if_transformer_is_none(
        self, sample_data
    ):
        """Test partial_fit raises AttributeError if transformer is None."""
        X, y = sample_data
        wrapper = PreprocessingWrapper(steps=[("bad_step", None)])

        with pytest.raises(AttributeError):
            wrapper.partial_fit(X, y)
