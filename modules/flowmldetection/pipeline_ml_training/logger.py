from commons import BENIGN, MALICIOUS, BACKGROUND
import numpy
import os


class Logger:
    def __init__(
        self,
        experiment_name: str = "default_experiment",
        path_to_logging_dir: str = "logs",
        path_to_logfile: str = "training.log",
        overwrite: bool = False,
    ):
        self.path_to_logfile = path_to_logfile
        self.path_to_logging_dir = path_to_logging_dir
        self.name = experiment_name

        os.makedirs(self.path_to_logging_dir, exist_ok=True)
        os.makedirs(
            os.path.join(self.path_to_logging_dir, self.name),
            exist_ok=True,
        )
        self.full_logfile_path = os.path.join(
            self.path_to_logging_dir, self.name, self.path_to_logfile
        )

        if os.path.exists(self.full_logfile_path) and not overwrite:
            print(
                f"Logfile '{self.full_logfile_path}' already exists! Aborting to avoid overwrite."
            )
            raise FileExistsError(
                f"Logfile '{self.full_logfile_path}' already exists."
            )
        with open(self.full_logfile_path, "w") as f:
            f.write("")

        # Only consider MALICIOUS and BENIGN labels for metrics
        self.relevant_labels = [MALICIOUS, BENIGN]

    def write_to_log(self, message: str):
        with open(self.full_logfile_path, "a") as f:
            f.write(message + "\n")
        # print(f"[{self.name}] {message}")

    def compute_metrics(
        self, y_true, y_pred, relevant_labels=[MALICIOUS, BENIGN]
    ):
        metrics = {
            "TP": numpy.sum((y_pred == MALICIOUS) & (y_true == MALICIOUS)),
            "FP": numpy.sum((y_pred == MALICIOUS) & (y_true == BENIGN)),
            "FN": numpy.sum((y_pred == BENIGN) & (y_true == MALICIOUS)),
            "TN": numpy.sum((y_pred == BENIGN) & (y_true == BENIGN)),
        }
        seen_labels = {
            label: numpy.sum(y_true == label) for label in relevant_labels
        }
        predicted_labels = {
            label: numpy.sum(y_pred == label) for label in relevant_labels
        }
        return metrics, seen_labels, predicted_labels

    def log(self, message: str):
        print(f"[{self.name}] {message}")

    def _filter_labels(
        self, y_true, y_pred, relevant_labels=[MALICIOUS, BENIGN]
    ):
        mask = numpy.isin(y_true, relevant_labels)
        return y_true[mask], y_pred[mask]

    def save_training_results(
        self, y_pred_train, y_gt_train, y_pred_val, y_gt_val, sum_labeled_flows
    ):

        relevant_labels = self.relevant_labels

        # Validation metrics if validation set is present and different from training set
        if (
            y_pred_val is not None
            and y_gt_val is not None
            and y_pred_train is not None
            and y_gt_train is not None
            and not numpy.array_equal(y_gt_train, y_gt_val)
        ):
            y_gt_val_filt, y_pred_val_filt = self._filter_labels(
                y_gt_val, y_pred_val, relevant_labels
            )
            y_gt_train_filt, y_pred_train_filt = self._filter_labels(
                y_gt_train, y_pred_train, relevant_labels
            )

            metrics_val, seen_labels_val, predicted_labels_val = (
                self.compute_metrics(
                    y_gt_val_filt, y_pred_val_filt, relevant_labels
                )
            )
            metrics_train, seen_labels_train, predicted_labels_train = (
                self.compute_metrics(
                    y_gt_train_filt, y_pred_train_filt, relevant_labels
                )
            )

            self.write_to_log(
                f"Total labels: {sum_labeled_flows}, "
                f"Validation size: {len(y_pred_val_filt)}, "
                f"Validation seen labels: {seen_labels_val}, "
                f"Validation predicted labels: {predicted_labels_val}, "
                f"Validation metrics: {metrics_val}, "
                f"Training size: {len(y_gt_train_filt)}, "
                f"Training seen labels: {seen_labels_train}, "
                f"Training predicted labels: {predicted_labels_train}, "
                f"Training metrics: {metrics_train}"
            )
        else:
            # Only one set (train == val), calculate metrics once
            y_gt_val_filt, y_pred_val_filt = self._filter_labels(
                y_gt_val, y_pred_val, relevant_labels
            )
            metrics, seen_labels, predicted_labels = self.compute_metrics(
                y_gt_val_filt, y_pred_val_filt, relevant_labels
            )

            self.write_to_log(
                f"Total labels: {sum_labeled_flows}, "
                f"Training size: {len(y_pred_val_filt)}, "
                f"Training seen labels: {seen_labels}, "
                f"Training predicted labels: {predicted_labels}, "
                f"Training metrics: {metrics}"
            )

    def save_test_results(self, original_labels, predicted_labels):
        # Convert to numpy arrays if not already
        original_labels = numpy.array(original_labels)
        predicted_labels = numpy.array(predicted_labels)

        # Discard rows where either label is BACKGROUND
        mask = (original_labels != BACKGROUND) & (
            predicted_labels != BACKGROUND
        )
        filtered_orig = original_labels[mask]
        filtered_pred = predicted_labels[mask]

        # Initialize metrics if not already done
        if not hasattr(self, "malware_metrics"):
            self.malware_metrics = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
        if not hasattr(self, "seen_labels"):
            self.seen_labels = {MALICIOUS: 0, BENIGN: 0}
        if not hasattr(self, "predicted_labels"):
            self.predicted_labels = {MALICIOUS: 0, BENIGN: 0}

        # Update counters for true and predicted labels
        for label in [MALICIOUS, BENIGN]:
            self.seen_labels[label] += numpy.sum(filtered_orig == label)
            self.predicted_labels[label] += numpy.sum(filtered_pred == label)

        # Calculate TP, FP, TN, FN from malware perspective
        self.malware_metrics["TP"] += numpy.sum(
            (filtered_orig == MALICIOUS) & (filtered_pred == MALICIOUS)
        )
        self.malware_metrics["FP"] += numpy.sum(
            (filtered_orig == BENIGN) & (filtered_pred == MALICIOUS)
        )
        self.malware_metrics["FN"] += numpy.sum(
            (filtered_orig == MALICIOUS) & (filtered_pred == BENIGN)
        )
        self.malware_metrics["TN"] += numpy.sum(
            (filtered_orig == BENIGN) & (filtered_pred == BENIGN)
        )

        total_flows = sum(self.seen_labels.values())
        log_str = (
            f"Total flows: {total_flows}; "
            f"Seen labels: {self.seen_labels}; "
            f"Predicted labels: {self.predicted_labels}; "
            f"Malware metrics (TP/FP/TN/FN): {self.malware_metrics}; "
        )
        self.write_to_log(log_str)
