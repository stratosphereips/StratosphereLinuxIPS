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
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    precision_score,
    recall_score,
)
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
    authors = ["Sebastian Garcia"]

    def init(self):
        # Subscribe to the channel
        self.c1 = self.db.subscribe("new_flow")
        self.channels = {"new_flow": self.c1}
        self.fieldseparator = self.db.get_field_separator()
        # Set the output queue of our database instance
        # Read the configuration
        self.read_configuration()
        # Minum amount of new labels needed to start the train
        self.minimum_labels_to_start_train = 50
        # Minum amount of new labels needed to retrain
        self.minimum_labels_to_retrain = 50
        # The number of flows when last trained. Used internally only to know
        # when to retrain
        self.last_number_of_flows_when_trained = 0
        # The scaler trained during training and to use during testing
        self.scaler = StandardScaler()
        self.model_path = "./modules/flowmldetection/model.bin"
        self.scaler_path = "./modules/flowmldetection/scaler.bin"
        self.all_classes = [BACKGROUND, MALICIOUS, BENIGN]
        self.all_labels = ["background", "malicious", "benign"]

        self.classifier_initialized = False
        self.init_log_file()

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

    def read_configuration(self):
        conf = ConfigParser()
        self.mode = conf.get_ml_mode()
        # This is the global label in the configuration,
        # in case the flows do not have a label themselves
        self.ground_truth_config_label = conf.label()
        self.enable_logs: bool = conf.create_performance_metrics_log_files()

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
        y_flow,
        y_pred,
        sum_labeled_flows,
        epoch_label_counts,
    ):
        # For metrics, let's focus on Malicious vs Benign (ignore Background)
        mask = (y_flow == MALICIOUS) | (y_flow == BENIGN)
        y_true_bin = y_flow[mask]
        y_pred_bin = y_pred[mask]

        # Map to binary: Malicious=1, Benign=0
        y_true_bin = numpy.where(y_true_bin == MALICIOUS, 1, 0)
        y_pred_bin = numpy.where(y_pred_bin == MALICIOUS, 1, 0)

        # Compute confusion matrix: tn, fp, fn, tp
        tn, fp, fn, tp = (
            confusion_matrix(y_true_bin, y_pred_bin, labels=[0, 1]).ravel()
            if len(set(y_true_bin)) > 1
            else (0, 0, 0, 0)
        )

        # Compute metrics
        FPR = fp / (fp + tn) if (fp + tn) > 0 else 0
        TNR = tn / (tn + fp) if (tn + fp) > 0 else 0
        TPR = tp / (tp + fn) if (tp + fn) > 0 else 0
        FNR = fn / (fn + tp) if (fn + tp) > 0 else 0
        F1 = f1_score(y_true_bin, y_pred_bin, zero_division=0)
        PREC = precision_score(y_true_bin, y_pred_bin, zero_division=0)
        ACCU = accuracy_score(y_true_bin, y_pred_bin)
        MCC = (
            matthews_corrcoef(y_true_bin, y_pred_bin)
            if len(set(y_true_bin)) > 1
            else 0
        )
        RECALL = recall_score(y_true_bin, y_pred_bin, zero_division=0)

        # Store the models on disk
        self.store_model()

        # Log training information
        self.write_to_log(
            f"Total labels: {sum_labeled_flows}, "
            f"Background: {epoch_label_counts['Background']}. "
            f"Benign: {epoch_label_counts['Benign']}. "
            f"Malicious: {epoch_label_counts[MALICIOUS]}. "
            f"Metrics: FPR={FPR:.4f}, TNR={TNR:.4f}, "
            f"TPR={TPR:.4f}, FNR={FNR:.4f}, "
            f"F1={F1:.4f}, Precision={PREC:.4f}, "
            f"Accuracy={ACCU:.4f}, MCC={MCC:.4f}, Recall={RECALL:.4f}."
        )

    def train(self, sum_labeled_flows, last_number_of_flows_when_trained):
        """
        Train a model based on the flows we receive and the labels
        """
        try:
            # Create y_flow with the label
            y_flow = numpy.full(
                self.flows.shape[0], self.flows.ground_truth_label
            )
            # Create X_flow with the current flows minus the label
            X_flow = self.flows.copy()
            X_flow = X_flow.drop("ground_truth_label", axis=1)
            # Drop the detailed labels
            X_flow = X_flow.drop("detailed_ground_truth_label", axis=1)
            # Drop the module_labels
            X_flow = X_flow.drop("module_labels", axis=1)

            try:  # when not fitted, the scaler.mean_ is None, try fitting it
                if (
                    not hasattr(self.scaler, "mean_")
                    or self.scaler.mean_ is None
                ):
                    # fit on the first batch of data
                    self.print(
                        "First fitting the scaler to the training data.", 0, 2
                    )
                    self.scaler.fit(X_flow)
                else:
                    self.print(
                        "updating the scaler with the training data.", 0, 2
                    )
                    self.scaler.partial_fit(X_flow)  # update for now
                X_flow = self.scaler.transform(X_flow)
            except Exception as e:
                self.print(
                    f"Error in train() while scaling the training data: {e}",
                    1,
                    1,
                )
                self.print("Flow to scale:", 2, 1)
                self.print(X_flow, 2, 1)

            # Count the number of labels of each type in this epoch
            epoch_label_counts = {
                BACKGROUND: (y_flow == BACKGROUND).sum(),
                MALICIOUS: (y_flow == MALICIOUS).sum(),
                BENIGN: (y_flow == BENIGN).sum(),
            }

            # Train
            try:
                unique_labels = numpy.unique(y_flow)
                label_counts = {
                    label: (y_flow == label).sum() for label in unique_labels
                }
                self.print(f"Label counts: {label_counts}", 0, 1)

                if not self.classifier_initialized:  # init the classifier
                    self.print(
                        "labels in the training set: " + str(unique_labels),
                        0,
                        1,
                    )
                    self.clf.partial_fit(
                        X_flow, y_flow, classes=[BACKGROUND, MALICIOUS, BENIGN]
                    )
                    self.classifier_initialized = True
                else:
                    self.clf.partial_fit(X_flow, y_flow)
            except Exception:
                self.print("Error while calling clf.train()")
                self.print(traceback.format_exc(), 1, 1)

            # Predict on the training data
            y_pred = self.clf.predict(X_flow)

            # Store the training results (housekeeping..: logs, calculationg metrics)
            self.store_training_results(
                y_flow, y_pred, sum_labeled_flows, epoch_label_counts
            )

        except Exception:
            self.print("Error in train().", 0, 1)
            self.print(traceback.format_exc(), 0, 1)
            self.write_to_log("Error occurred during training.")

    def process_features(self, dataset):
        """
        Discards some features of the dataset and can create new.
        Clean the dataset
        """
        try:
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
            flows = self.db.get_all_flows()
            # Only process new flows since last training
            new_flows = flows[last_number_of_flows_when_trained:]

            # Check how many **different** labels are in the DB
            labels = self.db.get_labels()
            if len(labels) != len(self.all_classes):
                # Insert fake flows for both classes if needed

                # I dont like this hack. feels weird, may bias the model in some way??
                new_flows.insert(
                    1,
                    {
                        "starttime": 1594417039.029793,
                        "dur": "1.9424750804901123",
                        "saddr": "10.7.10.101",
                        "sport": "49733",
                        "daddr": "40.70.224.145",
                        "dport": "443",
                        "proto": "tcp",
                        "state": "SF",
                        "spkts": 17,
                        "dpkts": 27,
                        "sbytes": 25517,
                        "dbytes": 17247,
                        "appproto": "ssl",
                        "ground_truth_label": MALICIOUS,
                        "module_labels": {
                            "flowalerts-long-connection": MALICIOUS
                        },
                    },
                )
                new_flows.insert(
                    1,
                    {
                        "starttime": 1382355032.706468,
                        "dur": "10.896695",
                        "saddr": "147.32.83.52",
                        "sport": "47956",
                        "daddr": "80.242.138.72",
                        "dport": "80",
                        "proto": "tcp",
                        "state": "SF",
                        "spkts": 1,
                        "dpkts": 0,
                        "sbytes": 100,
                        "dbytes": 67596,
                        "appproto": "http",
                        "ground_truth_label": BENIGN,
                        "module_labels": {
                            "flowalerts-long-connection": BENIGN
                        },
                    },
                )
                new_flows.insert(
                    1,
                    {
                        "starttime": 310.391420,
                        "dur": "5.082519",
                        "saddr": "192.168.1.115",
                        "sport": "60041",
                        "daddr": "54.247.115.15",
                        "dport": "80",
                        "proto": "tcp",
                        "state": "RSTO",
                        "spkts": 7,
                        "dpkts": 5,
                        "sbytes": 2594,
                        "dbytes": 816,
                        "appproto": "http",
                        "ground_truth_label": BACKGROUND,
                        "module_labels": {
                            "flowalerts-long-connection": BACKGROUND
                        },
                    },
                )

            # Convert to pandas df
            df_flows = pd.DataFrame(new_flows)

            # Process features
            df_flows = self.process_features(df_flows)

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
        """
        try:
            # clean the flow
            fields_to_drop = [
                "label",
                "module_labels",
                "uid",
                "history",
                "dir_",
                "endtime",
                "flow_source",
                "ground_truth_label",
                "detailed_ground_truth_label",
            ]
            for field in fields_to_drop:
                try:
                    x_flow = x_flow.drop(field, axis=1)
                except (KeyError, ValueError):
                    pass

            # temp fix:
            if "bytes" in x_flow.columns:
                x_flow = x_flow.rename(columns={"bytes": "allbytes"})

            # Scale the flow
            try:
                x_flow: numpy.ndarray = self.scaler.transform(x_flow)
                pred: numpy.ndarray = self.clf.predict(x_flow)
            except Exception as e:
                self.print(
                    f"Error in detect() while scaling or predicting the flow: {e}",
                    0,
                    1,
                )
                self.print("Flow to predict:")
                self.print(x_flow, 0, 1)
                # self.print(traceback.format_exc(), 0, 1)
                # in develop: [dur, proto, sport, dport, spkts, dpkts, sbytes, state, ground_truth_label, detailed_ground_truth_label, allbytes, pkts, label, module_labels]
                # In my branch: dur proto  sport  dport  spkts  dpkts  sbytes  dbytes  state ground_truth_label detailed_ground_truth_label   label  module_labels  bytes  pkts

            return pred
        except Exception as e:
            self.print(
                f"Error in detect() while processing " f"\n{x_flow}\n{e}"
            )
            self.print(traceback.format_exc(), 0, 1)

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

    def store_scaler(self):
        """
        Store the trained scaler on disk
        """
        self.print("Storing the trained scaler on disk.", 0, 2)
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
            self.classifier_initialized
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
                # validation and such? (early stopping?)
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
            self.scaler = StandardScaler()  # RobustScaler()
            # TODO: use the same scaler as in training / can load and look? robust cannot do incremental learning

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
            # TODO: train on the last flows (below required amount of labels)
            labels = self.db.get_labels()
            sum_labeled_flows = sum(i[1] for i in labels)
            if sum_labeled_flows != self.last_number_of_flows_when_trained:
                self.print("Training on the last flows before shutdown.", 0, 2)
                self.process_training_flows(
                    self.last_number_of_flows_when_trained
                )
                self.train(
                    sum_labeled_flows,
                    self.last_number_of_flows_when_trained,
                )
                self.last_number_of_flows_when_trained = sum_labeled_flows

            self.store_model()
            self.store_scaler()
        self.log_file.flush()

    def pre_main(self):
        utils.drop_root_privs_permanently()
        # Load the model
        self.read_model()

    def main(self):
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

            if self.mode == "train":
                # We are training

                # Is the amount in the DB of labels enough to retrain?
                # Use labeled flows

                labels = self.db.get_labels()
                sum_labeled_flows = sum(i[1] for i in labels)

                # The min labels to retrain is the min number of flows
                # we should have seen so far in this capture to start training
                # This is so we dont _start_ training with only 1 flow

                # Once we are over the start minimum, the second condition is
                # to force to retrain every a minimum_labels_to_retrain number
                # of flows. So we dont retrain every 1 flow.)

                if sum_labeled_flows < self.minimum_labels_to_start_train:
                    return
                if (
                    sum_labeled_flows - self.last_number_of_flows_when_trained
                    < self.minimum_labels_to_retrain
                ):
                    return

                # So for example we retrain every 50 labels and only when
                # we have at least 50 labels

                # Process all flows in the DB and make them ready
                # for pandas
                self.process_training_flows(
                    self.last_number_of_flows_when_trained
                )

                # Train an algorithm
                self.train(
                    sum_labeled_flows,
                    self.last_number_of_flows_when_trained,
                )
                self.last_number_of_flows_when_trained = sum_labeled_flows

            elif self.mode == "test":
                # We are testing, which means using the model to detect
                processed_flow = self.process_flow(self.flow)
                # After processing the flow, it may happen that we
                # delete icmp/arp/etc so the dataframe can be empty
                if processed_flow is not None and not processed_flow.empty:
                    try:
                        original_label = processed_flow[
                            "ground_truth_label"
                        ].iloc[0]
                    except KeyError:
                        # If there are no labels in the flows, the default
                        # label should be the one in the config file.
                        original_label = self.ground_truth_config_label

                    # Predict
                    pred: numpy.ndarray = self.detect(processed_flow)
                    if not pred:
                        # an error occurred
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
                        # Initialize counters if not already done
                        if not hasattr(self, "tp"):
                            self.tp = 0
                        if not hasattr(self, "tn"):
                            self.tn = 0
                        if not hasattr(self, "fp"):
                            self.fp = 0
                        if not hasattr(self, "fn"):
                            self.fn = 0

                        # Update counters based on predictions and labels
                        if (
                            pred[0] == MALICIOUS
                            and original_label == MALICIOUS
                        ):
                            self.tp += 1
                        elif pred[0] == BENIGN and original_label == BENIGN:
                            self.tn += 1
                        elif pred[0] == MALICIOUS and original_label == BENIGN:
                            self.fp += 1
                            self.write_to_log(
                                f"False Positive Flow: {self.flow}"
                            )
                        elif pred[0] == BENIGN and original_label == MALICIOUS:
                            self.fn += 1
                            self.write_to_log(
                                f"False Negative Flow: {self.flow}"
                            )

                        self.print("logging testing performance metrics", 2, 0)
                        # Log the testing performance metrics
                        self.write_to_log(
                            f"TP: {self.tp}, TN: {self.tn},"
                            f" FP: {self.fp}, FN: {self.fn}"
                        )
