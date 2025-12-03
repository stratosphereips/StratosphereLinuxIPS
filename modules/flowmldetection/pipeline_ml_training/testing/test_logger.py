import pytest
import tempfile
import numpy as np
from pathlib import Path
from pipeline_ml_training.logger import Logger
from pipeline_ml_training.commons import BENIGN, MALICIOUS, BACKGROUND


class TestLogger:
    """Comprehensive test suite for Logger class."""

    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for test logs."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    # ========== Initialization and Directory Creation Tests ==========
    def test_initialization_creates_directories_and_logfile(self, temp_dir):
        """Test Logger initializes and creates necessary directories and logfile."""
        logger = Logger(
            experiment_name="test_exp",
            path_to_logging_dir=temp_dir,
            path_to_logfile="test.log",
            overwrite=False,
        )

        # Check directories were created
        exp_dir = Path(temp_dir) / "test_exp"
        assert exp_dir.exists()

        # Check logfile was created
        logfile = exp_dir / "test.log"
        assert logfile.exists()
        assert logfile.read_text() == ""  # Empty on creation

        # Check attributes set correctly
        assert logger.name == "test_exp"
        assert logger.path_to_logging_dir == temp_dir
        assert logger.path_to_logfile == "test.log"
        assert logger.relevant_labels == [MALICIOUS, BENIGN]

    def test_initialization_with_defaults(self, temp_dir):
        """Test Logger uses default values correctly."""
        logger = Logger(path_to_logging_dir=temp_dir)

        assert logger.name == "default_experiment"
        assert logger.path_to_logfile == "training.log"
        exp_dir = Path(temp_dir) / "default_experiment"
        assert (exp_dir / "training.log").exists()

    def test_initialization_existing_file_without_overwrite_raises_error(
        self, temp_dir
    ):
        """Test that existing logfile without overwrite raises FileExistsError."""
        # Create first logger
        Logger(
            experiment_name="test_exp",
            path_to_logging_dir=temp_dir,
            path_to_logfile="test.log",
            overwrite=False,
        )

        # Try to create another with same path and overwrite=False
        with pytest.raises(FileExistsError):
            Logger(
                experiment_name="test_exp",
                path_to_logging_dir=temp_dir,
                path_to_logfile="test.log",
                overwrite=False,
            )

    def test_initialization_existing_file_with_overwrite_succeeds(
        self, temp_dir
    ):
        """Test that overwrite=True allows overwriting existing logfile."""
        # Create first logger and write something
        logger1 = Logger(
            experiment_name="test_exp",
            path_to_logging_dir=temp_dir,
            path_to_logfile="test.log",
            overwrite=False,
        )
        logger1.write_to_log("original content")

        # Create second logger with overwrite=True
        logger2 = Logger(
            experiment_name="test_exp",
            path_to_logging_dir=temp_dir,
            path_to_logfile="test.log",
            overwrite=True,
        )

        # File should exist and be empty (overwritten)
        logfile = Path(temp_dir) / "test_exp" / "test.log"
        assert logfile.exists()
        assert logfile.read_text() == ""
        assert logger1.full_logfile_path == logger2.full_logfile_path

    def test_nested_directory_creation(self, temp_dir):
        """Test that nested directory structure is created correctly."""
        logger = Logger(
            experiment_name="nested/exp/name",
            path_to_logging_dir=temp_dir,
            path_to_logfile="log.txt",
            overwrite=False,
        )

        expected_path = Path(temp_dir) / "nested/exp/name" / "log.txt"
        assert logger.full_logfile_path == str(expected_path)
        assert expected_path.exists()
        # Also check that intermediate directories are created
        assert (Path(temp_dir) / "nested").exists()
        assert (Path(temp_dir) / "nested" / "exp").exists()
        assert (Path(temp_dir) / "nested" / "exp" / "name").exists()

    # ========== Write and Log Tests ==========
    def test_write_to_log_appends_message(self, temp_dir):
        """Test write_to_log appends messages to logfile."""
        logger = Logger(
            experiment_name="test_exp",
            path_to_logging_dir=temp_dir,
            path_to_logfile="test.log",
            overwrite=False,
        )

        logger.write_to_log("First message")
        logger.write_to_log("Second message")

        logfile = Path(temp_dir) / "test_exp" / "test.log"
        content = logfile.read_text()

        assert "First message" in content
        assert "Second message" in content
        assert content.count("\n") == 2  # Two newlines

    def test_log_prints_to_stdout(self, temp_dir, capsys):
        """Test log method prints to stdout with experiment name prefix."""
        logger = Logger(
            experiment_name="test_exp",
            path_to_logging_dir=temp_dir,
            overwrite=False,
        )

        logger.log("test message")
        captured = capsys.readouterr()

        assert "[test_exp] test message" in captured.out

    # ========== Metrics Computation Tests ==========
    def test_compute_metrics_basic(self, temp_dir):
        """Test compute_metrics with basic TP/FP/TN/FN calculation."""
        logger = Logger(path_to_logging_dir=temp_dir, overwrite=False)

        y_true = np.array(
            [MALICIOUS, MALICIOUS, BENIGN, BENIGN, MALICIOUS, BENIGN]
        )
        y_pred = np.array(
            [MALICIOUS, BENIGN, MALICIOUS, BENIGN, MALICIOUS, BENIGN]
        )

        metrics, seen_labels, predicted_labels = logger.compute_metrics(
            y_true, y_pred
        )

        # TP: pred=MAL, true=MAL -> 2 (indices 0, 4)
        # FP: pred=MAL, true=BEN -> 1 (index 2)
        # FN: pred=BEN, true=MAL -> 1 (index 1)
        # TN: pred=BEN, true=BEN -> 2 (indices 3, 5)
        assert metrics["TP"] == 2
        assert metrics["FP"] == 1
        assert metrics["FN"] == 1
        assert metrics["TN"] == 2

        # Check label counts
        assert seen_labels[MALICIOUS] == 3
        assert seen_labels[BENIGN] == 3
        assert predicted_labels[MALICIOUS] == 3
        assert predicted_labels[BENIGN] == 3

    def test_compute_metrics_all_correct(self, temp_dir):
        """Test compute_metrics with perfect predictions."""
        logger = Logger(path_to_logging_dir=temp_dir, overwrite=False)

        y_true = np.array([MALICIOUS, MALICIOUS, BENIGN, BENIGN])
        y_pred = np.array([MALICIOUS, MALICIOUS, BENIGN, BENIGN])

        metrics, _, _ = logger.compute_metrics(y_true, y_pred)

        assert metrics["TP"] == 2
        assert metrics["FP"] == 0
        assert metrics["FN"] == 0
        assert metrics["TN"] == 2

    def test_compute_metrics_all_wrong(self, temp_dir):
        """Test compute_metrics with completely wrong predictions."""
        logger = Logger(path_to_logging_dir=temp_dir, overwrite=False)

        y_true = np.array([MALICIOUS, MALICIOUS, BENIGN, BENIGN])
        y_pred = np.array([BENIGN, BENIGN, MALICIOUS, MALICIOUS])

        metrics, _, _ = logger.compute_metrics(y_true, y_pred)

        assert metrics["TP"] == 0
        assert metrics["FP"] == 2
        assert metrics["FN"] == 2
        assert metrics["TN"] == 0

    # ========== Filter Labels Tests ==========
    def test_filter_labels_removes_background(self, temp_dir):
        """Test _filter_labels removes BACKGROUND labels."""
        logger = Logger(path_to_logging_dir=temp_dir, overwrite=False)

        y_true = np.array([MALICIOUS, BACKGROUND, BENIGN, MALICIOUS])
        y_pred = np.array([MALICIOUS, MALICIOUS, BENIGN, BENIGN])

        y_true_filt, y_pred_filt = logger._filter_labels(y_true, y_pred)

        assert len(y_true_filt) == 3
        assert len(y_pred_filt) == 3
        assert BACKGROUND not in y_true_filt
        assert BACKGROUND not in y_pred_filt

    def test_filter_labels_preserves_order(self, temp_dir):
        """Test _filter_labels preserves order of remaining labels."""
        logger = Logger(path_to_logging_dir=temp_dir, overwrite=False)

        y_true = np.array([MALICIOUS, BACKGROUND, BENIGN, MALICIOUS])
        y_pred = np.array([MALICIOUS, BENIGN, BENIGN, MALICIOUS])

        y_true_filt, y_pred_filt = logger._filter_labels(y_true, y_pred)

        # Should keep indices 0, 2, 3
        assert list(y_true_filt) == [MALICIOUS, BENIGN, MALICIOUS]
        assert list(y_pred_filt) == [MALICIOUS, BENIGN, MALICIOUS]

    # ========== Save Training Results Tests ==========
    def test_save_training_results_with_separate_train_val(self, temp_dir):
        """Test save_training_results with separate training and validation sets."""
        logger = Logger(
            experiment_name="test_exp",
            path_to_logging_dir=temp_dir,
            overwrite=False,
        )

        y_gt_train = np.array([MALICIOUS, MALICIOUS, BENIGN])
        y_pred_train = np.array([MALICIOUS, BENIGN, BENIGN])
        y_gt_val = np.array([MALICIOUS, BENIGN, BENIGN])
        y_pred_val = np.array([MALICIOUS, MALICIOUS, BENIGN])

        logger.save_training_results(
            y_pred_train,
            y_gt_train,
            y_pred_val,
            y_gt_val,
            sum_labeled_flows=100,
        )

        logfile = Path(temp_dir) / "test_exp" / "training.log"
        content = logfile.read_text()

        # Check that both training and validation metrics appear
        assert "Training size:" in content
        assert "Validation size:" in content
        assert "Training metrics:" in content
        assert "Validation metrics:" in content
        assert "Total labels: 100" in content

    def test_save_training_results_same_train_val(self, temp_dir):
        """Test save_training_results when training and validation are same."""
        logger = Logger(
            experiment_name="test_exp",
            path_to_logging_dir=temp_dir,
            overwrite=False,
        )

        y_data = np.array([MALICIOUS, BENIGN, MALICIOUS, BENIGN])
        y_pred = np.array([MALICIOUS, BENIGN, BENIGN, BENIGN])

        logger.save_training_results(
            y_pred, y_data, None, None, sum_labeled_flows=50
        )

        logfile = Path(temp_dir) / "test_exp" / "training.log"
        content = logfile.read_text()

        # Should only have training metrics
        assert "Training size:" in content
        assert "Validation size:" not in content
        assert "Total labels: 50" in content

    def test_save_training_results_with_background_filtering(self, temp_dir):
        """Test save_training_results filters BACKGROUND labels correctly."""
        logger = Logger(
            experiment_name="test_exp",
            path_to_logging_dir=temp_dir,
            overwrite=False,
        )

        y_gt_train = np.array([MALICIOUS, BACKGROUND, BENIGN])
        y_pred_train = np.array([MALICIOUS, MALICIOUS, BENIGN])

        logger.save_training_results(
            y_pred_train, y_gt_train, None, None, sum_labeled_flows=100
        )

        logfile = Path(temp_dir) / "test_exp" / "training.log"
        content = logfile.read_text()

        # Training size should be 2 (BACKGROUND filtered out)
        assert "Training size: 2" in content

    # ========== Save Test Results Tests ==========
    def test_save_test_results_accumulates_metrics(self, temp_dir):
        """Test save_test_results accumulates metrics across multiple calls."""
        logger = Logger(
            experiment_name="test_exp",
            path_to_logging_dir=temp_dir,
            overwrite=False,
        )

        # First batch
        original_1 = np.array([MALICIOUS, MALICIOUS, BENIGN])
        predicted_1 = np.array([MALICIOUS, BENIGN, BENIGN])
        logger.save_test_results(original_1, predicted_1)

        # Second batch
        original_2 = np.array([MALICIOUS, BENIGN])
        predicted_2 = np.array([MALICIOUS, MALICIOUS])
        logger.save_test_results(original_2, predicted_2)

        # Check accumulated metrics
        assert (
            logger.malware_metrics["TP"] == 2
        )  # (0,0) from batch1 + (0,0) from batch2
        assert logger.malware_metrics["FP"] == 1  # (2,0) from batch2
        assert logger.malware_metrics["FN"] == 1  # (1,1) from batch1
        assert logger.malware_metrics["TN"] == 1  # (2,2) from batch1

        assert logger.seen_labels[MALICIOUS] == 3
        assert logger.seen_labels[BENIGN] == 2
        assert logger.predicted_labels[MALICIOUS] == 3
        assert logger.predicted_labels[BENIGN] == 2

    def test_save_test_results_filters_background(self, temp_dir):
        """Test save_test_results filters out BACKGROUND labels."""
        logger = Logger(
            experiment_name="test_exp",
            path_to_logging_dir=temp_dir,
            overwrite=False,
        )

        original = np.array([MALICIOUS, BACKGROUND, BENIGN, BACKGROUND])
        predicted = np.array([MALICIOUS, MALICIOUS, BENIGN, BENIGN])

        logger.save_test_results(original, predicted)

        # Only 2 flows counted (BACKGROUND filtered)
        assert logger.seen_labels[MALICIOUS] == 1
        assert logger.seen_labels[BENIGN] == 1
        assert sum(logger.malware_metrics.values()) == 2

    def test_save_test_results_writes_to_log(self, temp_dir):
        """Test save_test_results writes formatted output to logfile."""
        logger = Logger(
            experiment_name="test_exp",
            path_to_logging_dir=temp_dir,
            overwrite=False,
        )

        original = np.array([MALICIOUS, BENIGN, MALICIOUS])
        predicted = np.array([MALICIOUS, BENIGN, BENIGN])

        logger.save_test_results(original, predicted)

        logfile = Path(temp_dir) / "test_exp" / "training.log"
        content = logfile.read_text()

        assert "Total flows:" in content
        assert "Seen labels:" in content
        assert "Predicted labels:" in content
        assert "Malware metrics" in content

    def test_save_test_results_handles_empty_predictions(self, temp_dir):
        """Test save_test_results handles empty arrays."""
        logger = Logger(
            experiment_name="test_exp",
            path_to_logging_dir=temp_dir,
            overwrite=False,
        )

        original = np.array([], dtype=object)
        predicted = np.array([], dtype=object)

        logger.save_test_results(original, predicted)

        # Should initialize with zeros
        assert logger.malware_metrics["TP"] == 0
        assert logger.malware_metrics["FP"] == 0
        assert logger.seen_labels[MALICIOUS] == 0
        assert logger.seen_labels[BENIGN] == 0

    # ========== Integration Tests ==========
    def test_integration_full_workflow(self, temp_dir):
        """Integration test: full logging workflow."""
        logger = Logger(
            experiment_name="full_test",
            path_to_logging_dir=temp_dir,
            path_to_logfile="results.log",
            overwrite=False,
        )

        # Write initial message
        logger.write_to_log("Starting experiment...")

        # Training phase
        y_train = np.array([MALICIOUS, BENIGN, MALICIOUS, BENIGN])
        y_pred_train = np.array([MALICIOUS, BENIGN, BENIGN, BENIGN])

        logger.save_training_results(y_pred_train, y_train, None, None, 100)

        # Test phase
        y_test = np.array([MALICIOUS, BENIGN, MALICIOUS, BENIGN])
        y_pred_test = np.array([MALICIOUS, MALICIOUS, BENIGN, BENIGN])

        logger.save_test_results(y_test, y_pred_test)

        logfile = Path(temp_dir) / "full_test" / "results.log"
        content = logfile.read_text()

        # Check all components are present
        assert "Starting experiment..." in content
        assert "Training size:" in content
        assert "Total flows:" in content
