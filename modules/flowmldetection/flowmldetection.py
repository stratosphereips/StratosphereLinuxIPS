# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
from typing import Optional

# SPDX-License-Identifier: GPL-2.0-only
import numpy
from sklearn.linear_model import SGDClassifier
from sklearn.preprocessing import StandardScaler
import pickle
import pandas as pd
import json
import traceback
import warnings

from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from slips_files.common.abstracts.module import IModule
from slips_files.core.structures.evidence import (
    Evidence,
    ProfileID,
    TimeWindow,
    Attacker,
    ThreatLevel,
    EvidenceType,
    IoCType,
    Direction,
    Victim,
    Method,
)

# Only for debbuging
# from matplotlib import pyplot as plt


# This horrible hack is only to stop sklearn from printing those warnings
def warn(*args, **kwargs):
    pass


warnings.warn = warn


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
        # Minum amount of new lables needed to trigger the train
        self.minimum_lables_to_retrain = 50
        # To plot the scores of training
        # self.scores = []
        # The scaler trained during training and to use during testing
        self.scaler = StandardScaler()
        self.model_path = "./modules/flowmldetection/model.bin"
        self.scaler_path = "./modules/flowmldetection/scaler.bin"

    def read_configuration(self):
        conf = ConfigParser()
        self.mode = conf.get_ml_mode()

    def train(self):
        """
        Train a model based on the flows we receive and the labels
        """
        try:
            # Process the labels to have only Normal and Malware
            self.flows.label = self.flows.label.str.replace(
                r"(^.*ormal.*$)", "Normal", regex=True
            )
            self.flows.label = self.flows.label.str.replace(
                r"(^.*alware.*$)", "Malware", regex=True
            )
            self.flows.label = self.flows.label.str.replace(
                r"(^.*alicious.*$)", "Malware", regex=True
            )

            # Separate
            y_flow = self.flows["label"]
            X_flow = self.flows.drop("label", axis=1)
            X_flow = X_flow.drop("module_labels", axis=1)

            # Normalize this batch of data so far. This can get progressivle slow
            X_flow = self.scaler.fit_transform(X_flow)

            # Train
            try:
                self.clf.partial_fit(
                    X_flow, y_flow, classes=["Malware", "Normal"]
                )
            except Exception:
                self.print("Error while calling clf.train()")
                self.print(traceback.format_exc(), 0, 1)

            # See score so far in training
            score = self.clf.score(X_flow, y_flow)

            # To debug the training score
            # self.scores.append(score)

            self.print(f"	Training Score: {score}", 0, 1)
            # self.print(f'    Model Parameters: {self.clf.coef_}')

            # Debug code to store a plot in a png of the scores
            # plt.plot(self.scores)
            # plt.savefig('train-scores.png')

            # Store the models on disk
            self.store_model()

        except Exception:
            self.print("Error in train()", 0, 1)
            self.print(traceback.format_exc(), 0, 1)

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

            # For now, discard the ports
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
                "dbytes",
                "endtime",
                "bytes",
                "flow_source",
            ]
            for field in to_drop:
                try:
                    dataset = dataset.drop(field, axis=1)
                except (ValueError, KeyError):
                    pass

            # Convert state to categorical
            dataset.state = dataset.state.str.replace(
                r"(^.*NotEstablished.*$)", "0", regex=True
            )
            dataset.state = dataset.state.str.replace(
                r"(^.*Established.*$)", "1", regex=True
            )
            # Convert proto to categorical. For now we only have few states,
            # so we can hardcode...
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
            fields_to_convert_to_flow = [
                dataset.proto,
                dataset.dport,
                dataset.sport,
                dataset.dur,
                dataset.pkts,
                dataset.spkts,
                dataset.allbytes,
                dataset.sbytes,
                dataset.state,
            ]
            for field in fields_to_convert_to_flow:
                try:
                    field = field.astype("float64")
                except ValueError:
                    pass

            return dataset
        except Exception:
            # Stop the timer
            self.print("Error in process_features()")
            self.print(traceback.format_exc(), 0, 1)

    def process_flows(self):
        """
        Process all the flwos in the DB
        Store the pandas df in self.flows
        """
        try:
            # We get all the flows so far
            # because this retraining happens in batches
            flows = self.db.get_all_flows()
            # Check how many different labels are in the DB
            # We need both normal and malware
            labels = self.db.get_labels()
            if len(labels) == 1:
                # Only 1 label has flows
                # There are not enough different labels, so insert two flows
                # that are fake but representative of a normal and malware flow
                # they are only for the training process
                # At least 1 flow of each label is required
                # self.print(f'Amount of labeled flows: {labels}', 0, 1)
                flows.append(
                    {
                        "ts": 1594417039.029793,
                        "dur": "1.9424750804901123",
                        "saddr": "10.7.10.101",
                        "sport": "49733",
                        "daddr": "40.70.224.145",
                        "dport": "443",
                        "proto": "tcp",
                        "state": "Established",
                        "allbytes": 42764,
                        "spkts": 37,
                        "sbytes": 25517,
                        "appproto": "ssl",
                        "label": "Malware",
                        "module_labels": {
                            "flowalerts-long-connection": "Malware"
                        },
                    }
                )
                flows.append(
                    {
                        "ts": 1382355032.706468,
                        "dur": "10.896695",
                        "saddr": "147.32.83.52",
                        "sport": "47956",
                        "daddr": "80.242.138.72",
                        "dport": "80",
                        "proto": "tcp",
                        "state": "Established",
                        "allbytes": 67696,
                        "spkts": 1,
                        "sbytes": 100,
                        "appproto": "http",
                        "label": "Normal",
                        "module_labels": {
                            "flowalerts-long-connection": "Normal"
                        },
                    }
                )
                # If there are enough flows, we dont insert them anymore

            # Convert to pandas df
            df_flows = pd.DataFrame(flows)

            # Process features
            df_flows = self.process_features(df_flows)

            # Update the flow to the processed version
            self.flows = df_flows
        except Exception:
            # Stop the timer
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
            given_x_flow = x_flow
            # clean the flow
            fields_to_drop = [
                "label",
                "module_labels",
                "uid",
                "history",
                "dir_",
                "dbytes",
                "dpkts",
                "endtime",
                "bytes",
                "flow_source",
                "ground_truth_label",  # todo now we can use them
                "detailed_ground_truth_label",
            ]
            for field in fields_to_drop:
                try:
                    x_flow = x_flow.drop(field, axis=1)
                except (KeyError, ValueError):
                    pass
            # Scale the flow
            x_flow: numpy.ndarray = self.scaler.transform(x_flow)
            pred: numpy.ndarray = self.clf.predict(x_flow)
            return pred
        except Exception as e:
            self.print(
                f"Error in detect() while processing " f"\n{given_x_flow}\n{e}"
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

    def read_model(self):
        """
        Read the trained model from disk
        """
        try:
            self.print("Reading the trained model from disk.", 0, 2)
            with open(self.model_path, "rb") as f:
                self.clf = pickle.load(f)
            self.print("Reading the trained scaler from disk.", 0, 2)
            with open(self.scaler_path, "rb") as g:
                self.scaler = pickle.load(g)
        except FileNotFoundError:
            # If there is no model, create one empty
            self.print(
                "There was no model. " "Creating a new empty model.", 0, 2
            )
            self.clf = SGDClassifier(
                warm_start=True, loss="hinge", penalty="l1"
            )
        except EOFError:
            self.print(
                "Error reading model from disk. "
                "Creating a new empty model.",
                0,
                2,
            )
            self.clf = SGDClassifier(
                warm_start=True, loss="hinge", penalty="l1"
            )

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
            self.store_model()

    def pre_main(self):
        utils.drop_root_privs()
        # Load the model
        self.read_model()

    def main(self):
        if msg := self.get_msg("new_flow"):
            msg = json.loads(msg["data"])
            twid = msg["twid"]
            self.flow = msg["flow"]
            # these fields are expected in testing. update the original
            # flow dict to have them
            self.flow.update(
                {
                    "allbytes": (self.flow["sbytes"] + self.flow["dbytes"]),
                    # the flow["state"] is the origstate, we dont need that here
                    # we need the interpreted state
                    "state": msg["interpreted_state"],
                    "pkts": self.flow["spkts"] + self.flow["dpkts"],
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
                if (
                    sum_labeled_flows >= self.minimum_lables_to_retrain
                    and sum_labeled_flows % self.minimum_lables_to_retrain == 1
                ):
                    # We get here every 'self.minimum_lables_to_retrain'
                    # amount of labels
                    # So for example we retrain every 100 labels and only when
                    # we have at least 100 labels
                    self.print(
                        f"Training the model with the last group of "
                        f"flows and labels. Total flows: {sum_labeled_flows}."
                    )
                    # Process all flows in the DB and make them ready
                    # for pandas
                    self.process_flows()
                    # Train an algorithm
                    self.train()
            elif self.mode == "test":
                # We are testing, which means using the model to detect
                processed_flow = self.process_flow(self.flow)

                # After processing the flow, it may happen that we
                # delete icmp/arp/etc so the dataframe can be empty
                if processed_flow is not None and not processed_flow.empty:
                    # Predict
                    pred: numpy.ndarray = self.detect(processed_flow)
                    if not pred:
                        # an error occurred
                        return

                    label = self.flow["label"]
                    if label and label != "unknown" and label != pred[0]:
                        # If the user specified a label in test mode,
                        # and the label is diff from the prediction,
                        # print in debug mode
                        self.print(
                            f"Report Prediction {pred[0]} for label"
                            f' {label} flow {self.flow["saddr"]}:'
                            f'{self.flow["sport"]} ->'
                            f' {self.flow["daddr"]}:'
                            f'{self.flow["dport"]}/'
                            f'{self.flow["proto"]}',
                            0,
                            3,
                        )
                    if pred[0] == "Malware":
                        # Generate an alert
                        self.set_evidence_malicious_flow(self.flow, twid)
                        self.print(
                            f"Prediction {pred[0]} for label {label}"
                            f' flow {self.flow["saddr"]}:'
                            f'{self.flow["sport"]} -> '
                            f'{self.flow["daddr"]}:'
                            f'{self.flow["dport"]}/'
                            f'{self.flow["proto"]}',
                            0,
                            2,
                        )
