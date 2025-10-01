# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
import json
import os
import pickle
import traceback
import warnings
from typing import Optional

# SPDX-License-Identifier: GPL-2.0-only
import numpy
import pandas as pd
from sklearn.linear_model import SGDClassifier
from sklearn.preprocessing import StandardScaler

from slips_files.common.abstracts.imodule import IModule
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from slips_files.core.structures.evidence import (
    Attacker,
    Direction,
    Evidence,
    EvidenceType,
    IoCType,
    Method,
    ProfileID,
    ThreatLevel,
    TimeWindow,
    Victim,
)
from slips_files.core.structures.labels import Label


# This horrible hack is only to stop sklearn from printing those warnings
def warn(*args, **kwargs):
    pass


warnings.warn = warn

BACKGROUND = Label.BACKGROUND.value
BENIGN = Label.BENIGN.value
MALICIOUS = Label.MALICIOUS.value


class FlowMLDetection(IModule):
    # Name: short name of the module. Do not use spaces
    name = "Flow ML Detection"
    description = (
        "Train or test a Machine Learning model to detect malicious flows"
    )
    authors = ["Sebastian Garcia, Jan Svoboda"]

    def init(self):
        # Subscribe to the channel
        self.c1 = self.db.subscribe("new_flow")
        self.c2 = self.db.subscribe("tw_closed")
        self.channels = {"new_flow": self.c1, "tw_closed": self.c2}
        self.fieldseparator = self.db.get_field_separator()
        # Set the output queue of our database instance
        # Read the configuration
        self.read_configuration()
        self.percentage_validation = (
            0.1  # 10% of the training data for validation
        )
        # The number of flows when last trained. Used internally only to know
        # when to retrain
        self.last_number_of_flows_when_trained = 0
        # The scaler trained during training and to use during testing

        self.model_path = "./modules/flowmldetection/model.bin"
        self.scaler_path = "./modules/flowmldetection/scaler.bin"
        self.all_classes = [MALICIOUS, BENIGN]

        self.classifier_initialized = False

        self.init_log_file()
        self.add_dummy_flows()
        self.labeled_counter = 0
        self.training_flows = []

        # Set the random seed for reproducibility
        numpy.random.seed(1111)

    def init_log_file(self):
        """
        Init the log file for training or testing
        """
        if not self.enable_logs:
            return

        if self.mode == "train":
            # Initialize the training log file
            self.log_path = os.path.join(self.output_dir, "training.log")
        elif self.mode == "test":
            # Initialize the testing log file
            self.log_path = os.path.join(self.output_dir, "testing.log")
        self.log_file = open(self.log_path, "w")

        self.print(
            f"Flow ML Detection module initialized in {self.mode} mode. "
            f"Minimum labels to start training: "
            f"{self.minimum_labels_to_start_train}, "
            f"minimum labels to retrain: {self.minimum_labels_to_retrain}, "
            f"minimum labels to finalize training: "
            f"{self.minimum_labels_to_finalize_train}.",
            1,
            1,
        )

    def add_dummy_flows(self):
        """
        Add dummy flows for each class to ensure the classifier can be trained
        even if the first batch does not contain all classes.
        """
        # Add dummy flows for each class to ensure classifier can be trained
        # even if the first batch does not contain all classes.

        # Dummy malicious flow (from previous code)
        self.dummy_malicious_flow = numpy.array(
            [
                1.9424750804901123,  # dur
                0.0,  # proto (tcp)
                49733.0,  # sport
                443.0,  # dport
                17.0,  # spkts
                27.0,  # dpkts (44 - 17)
                25517.0,  # sbytes
                17247.0,  # dbytes (42764 - 25517)
                1.0,  # state (Established)
                42764.0,  # bytes (sbytes + dbytes)
                44.0,  # pkts (spkts + dpkts)
            ]
        ).reshape(1, -1)

        # Dummy benign flow (from previous code)
        self.dummy_benign_flow = numpy.array(
            [
                10.896695,  # dur
                0.0,  # proto (tcp)
                47956.0,  # sport
                80.0,  # dport
                1.0,  # spkts
                0.0,  # dpkts (dummy value)
                100.0,  # sbytes
                67596.0,  # dbytes (67696 - 100)
                1.0,  # state (Established)
                67696.0,  # bytes (sbytes + dbytes)
                1.0,  # pkts (spkts + dpkts)
            ]
        ).reshape(1, -1)

    def read_configuration(self):
        conf = ConfigParser()
        self.mode = conf.get_ml_mode()
        # This is the global label in the configuration,
        # in case the flows do not have a label themselves
        self.ground_truth_config_label = conf.label()
        self.enable_logs: bool = conf.create_performance_metrics_log_files()

        self.batch_size: int = conf.flow_ml_detection_training_batch_size()
        # Minum amount of new labels needed to start the train (first train)
        self.minimum_labels_to_start_train = self.batch_size
        # Minum amount of new labels needed to retrain
        self.minimum_labels_to_retrain = self.batch_size

        # if I end and have more than this flows, I triger the final training
        # to not lose those.
        self.minimum_labels_to_finalize_train = int(self.batch_size / 4)

        self.validate_on_train = conf.validate_on_train()

    def write_to_log(self, message: str):
        """
        Write a message to the local log file if
        create_performance_metrics_log_files is enabled in slips.yaml
        """
        if not self.enable_logs:
            return

        try:
            self.log_file.write(message + "\n")
        except Exception as e:
            self.print(f"Error writing to log: {e}", 0, 1)

    def store_training_results(
        self,
        y_pred_train,
        y_gt_train,
        y_pred_val,
        y_gt_val,
        sum_labeled_flows,
    ):

        # Only consider MALICIOUS and BENIGN labels for metrics
        relevant_labels = [MALICIOUS, BENIGN]

        def compute_metrics(y_true, y_pred):
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

        # Filter out BACKGROUND from both ground truth and predictions
        def filter_labels(y_true, y_pred):
            mask = numpy.isin(y_true, relevant_labels)
            return y_true[mask], y_pred[mask]

        # Validation metrics if validation set is present and different from training set
        if (
            y_pred_val is not None
            and y_gt_val is not None
            and y_pred_train is not None
            and y_gt_train is not None
            and not numpy.array_equal(y_gt_train, y_gt_val)
        ):
            y_gt_val_filt, y_pred_val_filt = filter_labels(
                y_gt_val, y_pred_val
            )
            y_gt_train_filt, y_pred_train_filt = filter_labels(
                y_gt_train, y_pred_train
            )

            metrics_val, seen_labels_val, predicted_labels_val = (
                compute_metrics(y_gt_val_filt, y_pred_val_filt)
            )
            metrics_train, seen_labels_train, predicted_labels_train = (
                compute_metrics(y_gt_train_filt, y_pred_train_filt)
            )

            self.store_model()

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
            y_gt_val_filt, y_pred_val_filt = filter_labels(
                y_gt_val, y_pred_val
            )
            metrics, seen_labels, predicted_labels = compute_metrics(
                y_gt_val_filt, y_pred_val_filt
            )

            self.store_model()

            self.write_to_log(
                f"Total labels: {sum_labeled_flows}, "
                f"Training size: {len(y_pred_val_filt)}, "
                f"Training seen labels: {seen_labels}, "
                f"Training predicted labels: {predicted_labels}, "
                f"Training metrics: {metrics}"
            )

    def store_testing_results(self, original_label, predicted_label):
        # Only consider BENIGN and MALICIOUS, ignore BACKGROUND
        if original_label == BACKGROUND:
            return  # Ignore flows with BACKGROUND label, here for redundancy

        # Initialize metrics if not already done
        if not hasattr(self, "malware_metrics"):
            self.malware_metrics = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
        if not hasattr(self, "seen_labels"):
            self.seen_labels = {MALICIOUS: 0, BENIGN: 0}
        if not hasattr(self, "predicted_labels"):
            self.predicted_labels = {MALICIOUS: 0, BENIGN: 0}

        # Update counters for true and predicted labels
        if original_label in self.seen_labels:
            self.seen_labels[original_label] += 1
        else:
            self.seen_labels[original_label] = 1

        if predicted_label in self.predicted_labels:
            self.predicted_labels[predicted_label] += 1
        else:
            self.predicted_labels[predicted_label] = 1

        # Calculate TP, FP, TN, FN from malware perspective
        if original_label == MALICIOUS and predicted_label == MALICIOUS:
            self.malware_metrics["TP"] += 1
        elif original_label == BENIGN and predicted_label == MALICIOUS:
            self.malware_metrics["FP"] += 1
        elif original_label == MALICIOUS and predicted_label == BENIGN:
            self.malware_metrics["FN"] += 1
        elif original_label == BENIGN and predicted_label == BENIGN:
            self.malware_metrics["TN"] += 1

        total_flows = sum(self.seen_labels.values())
        log_str = (
            f"Total flows: {total_flows}; "
            f"Seen labels: {self.seen_labels}; "
            f"Predicted labels: {self.predicted_labels}; "
            f"Malware metrics (TP/FP/TN/FN): {self.malware_metrics}; "
        )
        self.write_to_log(log_str)

    def drop_labels(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Drop the labels from the DataFrame.
        This is used to prepare the DataFrame for training or testing.
        """
        # Drop the ground truth label and detailed label
        df = df.drop(
            [
                "ground_truth_label",
                "detailed_ground_truth_label",
                "label",
                "module_labels",
            ],
            axis=1,
            errors="ignore",
        )
        return df

    def train(self, sum_labeled_flows, last_number_of_flows_when_trained):
        """
        Train a model based on the flows we receive and the labels
        """
        if self.flows is None or self.flows.empty:
            self.print("No flows to train on. Skipping training.", 0, 1)
            return
        try:
            # Create y_gt_train with the label
            if hasattr(self.flows, "ground_truth_label"):
                gt = self.flows.ground_truth_label
                if hasattr(gt, "iloc"):  # a Series-like column
                    # if the column contains per-row labels, prefer the array of values
                    try:
                        y_gt_train = numpy.asarray(
                            self.flows["ground_truth_label"]
                        )
                    except Exception:
                        y_gt_train = numpy.full(
                            self.flows.shape[0], gt.iloc[0]
                        )
                else:
                    y_gt_train = numpy.full(self.flows.shape[0], gt)
            else:
                # fallback to global config label
                y_gt_train = numpy.full(
                    self.flows.shape[0], self.ground_truth_config_label
                )

            # Create X_train with the current flows minus the label
            X_train = self.flows.copy()
            X_train = self.drop_labels(X_train)

            X_val = X_train  # default - validate on all training data
            y_gt_val = y_gt_train

            # Take random 10% of data for validation if validating while training!
            if self.validate_on_train:
                validation_indices = numpy.random.choice(
                    X_train.shape[0],
                    size=int(self.percentage_validation * X_train.shape[0]),
                    replace=False,
                )
                train_indices = numpy.array(  # the rest is training
                    list(
                        set(range(X_train.shape[0])) - set(validation_indices)
                    )
                )

                # Split into train and validation sets
                X_val = X_train.iloc[validation_indices]
                y_gt_val = y_gt_train[validation_indices]
                X_train = X_train.iloc[train_indices]
                y_gt_train = y_gt_train[train_indices]

            try:  # when not fitted, the scaler.mean_ is None, try fitting it
                if (
                    not hasattr(self.scaler, "mean_")
                    or self.scaler.mean_ is None
                ):
                    # fit on the first batch of data
                    self.print(
                        "First fitting the scaler to the training data.", 0, 2
                    )
                    self.scaler.fit(X_train)
                else:
                    self.print(
                        "updating the scaler with the training data.", 0, 2
                    )
                    self.scaler.partial_fit(X_train)

                X_train = self.scaler.transform(X_train)

            except Exception as e:
                self.print(
                    f"Error in train() while scaling the training data: {e}",
                    1,
                    1,
                )

            # Train

            try:
                unique_labels = numpy.unique(y_gt_train)
                label_counts = {
                    label: (y_gt_train == label).sum()
                    for label in unique_labels
                }
                self.print(f"Training label counts: {label_counts}", 0, 1)

                if not self.classifier_initialized:  # init the classifier
                    self.print(
                        "labels in the training set: " + str(unique_labels),
                        0,
                        1,
                    )
                    # Ensure at least one flow from each class in the first batch
                    missing_labels = [
                        label
                        for label in [MALICIOUS, BENIGN]
                        if label not in unique_labels
                    ]
                    if missing_labels:
                        for label in missing_labels:
                            if label == MALICIOUS and hasattr(
                                self, "dummy_malicious_flow"
                            ):
                                X_train = numpy.vstack(
                                    [X_train, self.dummy_malicious_flow]
                                )
                                y_gt_train = numpy.append(
                                    y_gt_train, [MALICIOUS]
                                )
                            elif label == BENIGN and hasattr(
                                self, "dummy_benign_flow"
                            ):
                                X_train = numpy.vstack(
                                    [X_train, self.dummy_benign_flow]
                                )
                                y_gt_train = numpy.append(y_gt_train, [BENIGN])
                    # print("before training: ", X_train.shape)
                    self.clf.partial_fit(
                        X_train,
                        y_gt_train,
                        classes=[MALICIOUS, BENIGN],
                    )
                    self.classifier_initialized = True
                else:
                    self.clf.partial_fit(X_train, y_gt_train)
            except Exception:
                self.print("Error while calling clf.train()")
                self.print(traceback.format_exc(), 1, 1)

            # Predict on the training data
            y_pred_train = self.clf.predict(X_train)

            if self.validate_on_train:  # validation part
                if X_val.shape[0] == 0:
                    self.print(
                        "Validation set is empty after split. "
                        "Skipping validation.",
                        0,
                        1,
                    )
                    y_pred_val = numpy.array([])
                else:
                    X_val = self.scaler.transform(X_val)
                    y_pred_val = self.clf.predict(X_val)
            else:
                y_pred_val = y_pred_train

            # Store the training results (housekeeping..: logs, calculationg metrics)
            # y_gt_val already defined, either for val set or same as training set
            self.store_training_results(
                y_pred_train=y_pred_train,  # depends on X_train, depends on validation (yes/no,%,random split?), calculated every time
                y_gt_train=y_gt_train,  #  handled above while splitting data
                y_pred_val=y_pred_val,  # same as pred_train or predicted on val set, handled here
                y_gt_val=y_gt_val,  #  handled above while splitting data
                sum_labeled_flows=sum_labeled_flows,
            )

        except Exception:
            self.print("Error in train().", 0, 1)
            self.print(traceback.format_exc(), 0, 1)
            self.write_to_log("Error occurred during training.")

        self.last_number_of_flows_when_trained = self.labeled_counter
        self.labeled_counter = 0
        self.training_flows = []

    def process_features(self, dataset):
        """
        Discards some features of the dataset and can create new.
        Clean the dataset
        """
        try:
            # numeric conversions
            cols = [
                "proto",
                "dport",
                "sport",
                "dur",
                "pkts",
                "spkts",
                "bytes",
                "sbytes",
                "state",
            ]
            for col in cols:
                if col in dataset.columns:
                    try:
                        dataset[col] = dataset[col].astype("float64")
                    except (ValueError, AttributeError):
                        pass

            # Discard some type of flows that dont have ports
            to_discard = ["arp", "ARP", "icmp", "igmp", "ipv6-icmp", ""]
            for proto in to_discard:
                dataset = dataset[dataset.proto != proto]

            # If te proto is in the list to delete and there is only one flow,
            # then the dataset will be empty
            if dataset.empty:
                # DataFrame is empty now, so return empty
                return dataset

            # For now, discard these
            to_drop = [
                "appproto",
                "daddr",
                "saddr",
                "starttime",
                "type_",
                "smac",
                "dmac",
                "history",
                "uid",
                "dir_",
                "endtime",
                "flow_source",
            ]
            for field in to_drop:
                try:
                    dataset = dataset.drop(field, axis=1)
                except (ValueError, KeyError):
                    pass

            # When flows are read from Slips sqlite,
            # the state is not transformed to 'Established' or
            # 'Not Established', it is still 'S0' and others
            # So transform here
            dataset["state"] = dataset.apply(
                lambda row: self.db.get_final_state_from_flags(
                    row["state"], (row["spkts"] + row["dpkts"])
                ),
                axis=1,
            )

            # Convert state to categorical
            dataset.state = dataset.state.str.replace(
                r"(^.*Not Established.*$)", "0", regex=True
            )
            dataset.state = dataset.state.str.replace(
                r"(^.*Established.*$)", "1", regex=True
            )

            # Convert categories to floats
            dataset.state = dataset.state.astype("float64")

            # Convert proto to categorical. For now we only have few states, so we can hardcode...
            # We dont use the data to create categories because in testing mode
            # we dont see all the protocols
            # Also we dont store the Categorizer because the user can retrain
            # with its own data.
            dataset.proto = dataset.proto.str.lower()
            dataset.proto = dataset.proto.str.replace(
                r"(^.*tcp.*$)", "0", regex=True
            )
            dataset.proto = dataset.proto.str.replace(
                r"(^.*udp.*$)", "1", regex=True
            )
            dataset.proto = dataset.proto.str.replace(
                r"(^.*icmp.*$)", "2", regex=True
            )
            dataset.proto = dataset.proto.str.replace(
                r"(^.*icmp-ipv6.*$)", "3", regex=True
            )
            dataset.proto = dataset.proto.str.replace(
                r"(^.*arp.*$)", "4", regex=True
            )

            dataset["bytes"] = dataset["sbytes"] + dataset["dbytes"]
            dataset["pkts"] = dataset["spkts"] + dataset["dpkts"]

            fields_to_convert_to_float = [
                dataset.proto,
                dataset.dport,
                dataset.sport,
                dataset.dur,
                dataset.pkts,
                dataset.spkts,
                dataset.bytes,
                dataset.sbytes,
                dataset.state,
            ]
            for field in fields_to_convert_to_float:
                try:
                    field = field.astype("float64")
                except (ValueError, AttributeError):
                    pass

            return dataset
        except Exception:
            # Stop the timer
            self.print("Error in process_features()")
            self.print(traceback.format_exc(), 0, 1)

    def process_training_flows(self, last_number_of_flows_when_trained):
        """
        Process only the new flows in the DB since the last training.
        Store the pandas df in self.flows
        """
        try:
            # Ensure the index is an integer
            if last_number_of_flows_when_trained is None:
                last_number_of_flows_when_trained = 0
            else:
                last_number_of_flows_when_trained = int(
                    last_number_of_flows_when_trained
                )

            # We get all the flows so far
            new_flows = self.training_flows
            # Only process new flows since last training (slice the last batch of flows (contains the batch size of benign, malicious))
            if len(new_flows) > self.batch_size:
                self.print(
                    f"Expected {self.batch_size} new flows, "
                    f"but got {len(new_flows)}. "
                    "Skipping training.",
                    0,
                    1,
                )
                return None

            # Convert to pandas df
            df_flows = pd.DataFrame(new_flows)
            self.print(
                f"Processing {len(df_flows)} new flows for training.", 1, 1
            )
            # Process features
            df_flows = self.process_features(df_flows)
            self.print(
                f"Processed {len(df_flows)} new flows for training.", 1, 1
            )
            # Update the flow to the processed version
            self.flows = df_flows
        except Exception:
            self.print("Error in process_flows()")
            self.print(traceback.format_exc(), 0, 1)

    def process_flow(self, flow_to_process: dict):
        """
        Process one flow. Only used during detection in testing
        returns the pandas df with the processed flow
        """
        try:
            # Convert the flow to a pandas dataframe
            raw_flow = pd.DataFrame(flow_to_process, index=[0])
            dflow = self.process_features(raw_flow)
            if dflow.empty:
                return None
            # Update the flow to the processed version
            return dflow
        except Exception:
            # Stop the timer
            self.print("Error in process_flow()")
            self.print(traceback.format_exc(), 0, 1)

    def detect(self, x_flow) -> Optional[numpy.ndarray]:
        """
        Detects the given flow with the current model stored
        and returns the predection array
        at this point clean flown only!
        """

        # Scale the flow, then predict. not learning here!
        if (
            not self.classifier_initialized
            or not hasattr(self.scaler, "mean_")
            or self.scaler.mean_ is None
        ):
            self.print(
                "Classifier/scaler is not initialized. "
                "Please train the model before detecting.",
                0,
                1,
            )
            return None
        try:
            x_flow: numpy.ndarray = self.scaler.transform(x_flow)
            pred: numpy.ndarray = self.clf.predict(x_flow)
        except Exception as e:
            self.print(
                f"Error in detect() while scaling or predicting the flow: {e}",
                0,
                1,
            )
            self.print(traceback.format_exc(), 0, 1)

        return pred

    def store_model(self):
        """
        Store the trained model on disk
        """
        self.print("Storing the trained model and scaler on disk.", 0, 2)
        with open(self.model_path, "wb") as f:
            data = pickle.dumps(self.clf)
            f.write(data)
        with open(self.scaler_path, "wb") as g:
            data = pickle.dumps(self.scaler)
            g.write(data)

    def read_model(self):
        """
        Read the trained model from disk
        """
        try:
            self.print("Reading the trained model from disk.", 0, 2)
            with open(self.model_path, "rb") as f:
                self.clf = pickle.load(f)
            self.classifier_initialized = True
        except Exception as e:
            # If there is no model, create one empty
            if isinstance(e, FileNotFoundError):
                # If the file does not exist, create a new model
                self.print(
                    "There was no model. " "Creating a new empty model.", 0, 2
                )
            elif isinstance(e, EOFError):
                self.print(
                    "Error reading model from disk. "
                    "Creating a new empty model.",
                    0,
                    2,
                )
            self.clf = SGDClassifier(
                warm_start=True,  # warm start not needed, setting new model up?
                loss="hinge",
                penalty="l2",
                # experiments:
                # penalty, L1,L2,elastic,
                # class weights,
                # losses? kvadratic? huber?
            )
            self.classifier_initialized = (
                False  # needs training from this point on
            )

        # Read the scaler or create it anew
        try:
            self.print("Reading the trained scaler from disk.", 0, 2)
            with open(self.scaler_path, "rb") as g:
                self.scaler = pickle.load(g)
        except Exception as e:
            if isinstance(e, FileNotFoundError):
                self.print(
                    "There was no scaler. " "Creating a new empty scaler.",
                    0,
                    2,
                )
            elif isinstance(e, EOFError):
                self.print(
                    "Error reading scaler from disk. "
                    "Creating a new empty scaler.",
                    0,
                    2,
                )
            self.scaler = StandardScaler()

    def set_evidence_malicious_flow(self, flow: dict, twid: str):
        confidence: float = 0.1
        description = (
            f"Flow with malicious characteristics by ML. Src IP"
            f" {flow['saddr']}:{flow['sport']} to "
            f"{flow['daddr']}:{flow['dport']}"
        )
        twid_number = int(twid.replace("timewindow", ""))
        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.MALICIOUS_FLOW,
            attacker=Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value=flow["saddr"],
            ),
            victim=Victim(
                direction=Direction.DST,
                ioc_type=IoCType.IP,
                value=flow["daddr"],
            ),
            threat_level=ThreatLevel.LOW,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=flow["saddr"]),
            timewindow=TimeWindow(twid_number),
            uid=[flow["uid"]],
            timestamp=flow["starttime"],
            method=Method.AI,
            src_port=flow["sport"],
            dst_port=flow["dport"],
        )

        self.db.set_evidence(evidence)

    def shutdown_gracefully(self):
        # Confirm that the module is done processing
        if self.mode == "train":
            self.store_model()  # model AND scaler
            self.last_training_in_window()
        self.log_file.flush()

    def last_training_in_window(self):
        # Train on the last bunch of flows before new window/end of capture
        if not self.classifier_initialized:
            self.print(
                "Classifier is not initialized. " "No training will be done.",
                0,
                1,
            )
            return
        flows_left = self.labeled_counter

        self.print(f"Flows left to train on: {flows_left}", 0, 1)
        if flows_left >= self.minimum_labels_to_finalize_train:
            self.print(
                f"Training on the last {flows_left} flows in the window",
                0,
                1,
            )
            self.process_training_flows(self.last_number_of_flows_when_trained)
            self.print(
                f"Size of the last training batch: {len(self.flows)}",
                0,
                1,
            )
            self.train(
                self.labeled_counter,
                self.last_number_of_flows_when_trained,
            )
        else:
            self.print(
                f"Not enough flows to finalize training. "
                f"Need at least {self.minimum_labels_to_finalize_train}, "
                f"but got {flows_left}.",
                0,
                1,
            )
            self.labeled_counter = 0
            self.training_flows = []

    def pre_main(self):
        utils.drop_root_privs_permanently()
        # Load the model
        self.read_model()

    def main(self):
        """if (
            msg := self.get_msg("tw_closed")
        ):
            if self.mode == "train":
                self.last_training_in_window()  # train on flows from the end of the capture/window
            self.print("Time window closed. "+str(msg) , 1, 1)"""

        if msg := self.get_msg("new_flow"):
            # When a new flow arrives
            msg = json.loads(msg["data"])
            self.twid = msg["twid"]
            self.profileid = msg["profileid"]
            self.flow = msg["flow"]

            # These following extra fields are expected in testing.
            # update the original flow dict to have them
            self.flow.update(
                {
                    "state": msg["interpreted_state"],
                    "label": msg["label"],
                    "module_labels": msg["module_labels"],
                }
            )

            # print("unchanged_flow: ", self.flow)

            if (not self.flow.get("ground_truth_label")) or (
                self.flow.get("ground_truth_label") == ""
            ):
                self.flow["ground_truth_label"] = (
                    self.ground_truth_config_label
                )

            if self.flow["ground_truth_label"] in [
                BACKGROUND
            ]:  # skip detecting background, we dont care about it. still detect empty, for detection purposes!
                return

            if self.mode == "train":
                # We are training

                # Is the amount in the DB of labels enough to retrain?
                # Use labeled flows
                if self.flow["ground_truth_label"] in [MALICIOUS, BENIGN]:
                    self.labeled_counter += 1
                    self.training_flows += [self.flow]

                # The min labels to retrain is the min number of flows
                # we should have seen so far in this capture to start training
                # This is so we dont _start_ training with only 1 flow

                # Once we are over the start minimum, the second condition is
                # to force to retrain every a minimum_labels_to_retrain number
                # of flows. So we dont retrain every 1 flow.)

                if self.labeled_counter < self.minimum_labels_to_retrain:
                    return

                # So for example we retrain every 50 labels and only when
                # we have at least 50 labels

                # Process all flows in the DB and make them ready
                # for pandas

                self.process_training_flows(
                    self.last_number_of_flows_when_trained
                )

                # Train a model
                self.train(
                    self.labeled_counter,
                    self.last_number_of_flows_when_trained,
                )

            elif self.mode == "test":

                # We are testing, -> using the scaler and model to detect
                processed_flow = self.process_flow(self.flow)
                # After processing the flow, it may happen that we
                # delete icmp/arp/etc so the dataframe can be empty !!
                if processed_flow is not None and not processed_flow.empty:
                    try:
                        # print("processed: ", processed_flow.shape, processed_flow.columns)
                        original_label = processed_flow[
                            "ground_truth_label"
                        ].iloc[0]
                    except KeyError:
                        # If there are no labels in the flows, the default
                        # label should be the one in the config file.
                        original_label = self.ground_truth_config_label

                    # Predict, normalize flows before
                    processed_flow = self.drop_labels(processed_flow)
                    pred: numpy.ndarray = self.detect(processed_flow)

                    if pred is None or getattr(pred, "size", 0) == 0:
                        # an error occurred or empty prediction
                        return

                    if pred[0] == MALICIOUS:
                        # Generate an alert
                        self.set_evidence_malicious_flow(self.flow, self.twid)
                        self.print(
                            f"Prediction {pred[0]} for label {original_label}"
                            f' flow {self.flow["saddr"]}:'
                            f'{self.flow["sport"]} -> '
                            f'{self.flow["daddr"]}:'
                            f'{self.flow["dport"]}/'
                            f'{self.flow["proto"]}',
                            0,
                            2,
                        )

                    # So you can disable this code easily. Since it is used
                    # only for evaluating a testing
                    log_testing_data = True
                    if log_testing_data:
                        self.store_testing_results(
                            original_label,
                            pred[0],
                        )
