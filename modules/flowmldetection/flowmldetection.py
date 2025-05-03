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
        # Minum amount of new labels needed to start the train
        self.minimum_labels_to_start_train = 50
        # Minum amount of new labels needed to retrain
        self.minimum_labels_to_retrain = 50
        # The number of flows when last trained
        self.last_number_of_flows_when_trained = 0
        # To plot the scores of training
        # self.scores = []
        # The scaler trained during training and to use during testing
        self.scaler = StandardScaler()
        self.model_path = "./modules/flowmldetection/model.bin"
        self.scaler_path = "./modules/flowmldetection/scaler.bin"

        # Initialize the training log file
        self.training_log_path = "./modules/flowmldetection/training.log"
        with open(self.training_log_path, "w") as log_file:
            log_file.write("Training Log Initialized\n")

    def read_configuration(self):
        conf = ConfigParser()
        self.mode = conf.get_ml_mode()
        # This is the global label in the configuration,
        # in case the flows do not have a label themselves
        self.label = conf.label()

    def write_to_training_log(self, message: str):
        """
        Write a message to the training log file.
        """
        try:
            with open(self.training_log_path, "a") as log_file:
                log_file.write(message + "\n")
        except Exception as e:
            self.print(f"Error writing to training log: {e}", 0, 1)

    def train(self, sum_labeled_flows):
        """
        Train a model based on the flows we receive and the labels
        """
        try:
            # Get the flows from the DB
            # self.flows = self.db.get_all_flows_in_profileid_twid(self.profileid, self.twid)
            # Convert to pandas df
            # self.flows = pd.DataFrame(self.flows)
            # Process the features
            # X_flow = self.process_features(self.flows)

            # Create X_flow with the current flows minus the label
            X_flow = self.flows.drop("label", axis=1)
            # Create y_flow with the label
            y_flow = numpy.full(X_flow.shape[0], self.label)
            # Drop the module_labels
            X_flow = X_flow.drop("module_labels", axis=1)

            # Normalize this batch of data so far. This can get progressivle slow
            X_flow = self.scaler.fit_transform(X_flow)

            # Train
            try:
                self.clf.partial_fit(
                    X_flow, y_flow, classes=["Malicious", "Benign"]
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
            self.print("Error in train().", 0, 1)
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

            # If te proto is in the list to delete and there is only one flow, then the dataset will be empty
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

            dataset["allbytes"] = dataset["sbytes"] + dataset["dbytes"]
            dataset["pkts"] = dataset["spkts"] + dataset["dpkts"]

            fields_to_convert_to_float = [
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

    def process_training_flows(self):
        """
        Process all the flows in the DB
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

                # These flows should be in the same format as the ones in the DB.
                # Which means the satate is still SF, S0, etc.
                flows.append(
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
                        "label": "Malicious",
                        "module_labels": {
                            "flowalerts-long-connection": "Malicious"
                        },
                    }
                )
                flows.append(
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
                        "label": "Benign",
                        "module_labels": {
                            "flowalerts-long-connection": "Benign"
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
            ]
            # For argus binetflows this fails because ther is a field calle bytes that was not in other flows. It should be called allbytes.
            # Error
            ''' [Flow ML Detection] Error in detect() while processing                                                                                                                                                                                                                         
            dur proto  sport dport  state  pkts  spkts  dpkts  bytes  sbytes  dbytes  allbytes                                                                                                                                                                                    
            0  63.822830     0  56119   981    0.0    15     15      0   8764    1887       0      1887                                                                                                                                                                                    
            The feature names should match those that were passed during fit.                                                                                                                                                                                                              
            Feature names unseen at fit time:                                                                                                                                                                                                                                              
            - bytes     
            '''

            # IF we delete here the filed bytes the error is
            # [Flow ML Detection] Error in detect() while processing 
            # dur proto sport dport  state  pkts  spkts  dpkts  sbytes  dbytes allbytes                                                                                                                                                             
            # 0  63.822830     0  56120   980    0.0    15     15      0    1887       0      1887                                                                                                                                                             
            # The feature names should match those that were passed during fit.                                                                                                                                                                                
            # Feature names must be in the same order as they were in fit.                                                                                                                                                                                     
                                                                                                                                                                                                                                                 
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
            # When a new flow arrives
            msg = json.loads(msg["data"])
            self.twid = msg["twid"]
            self.profileid = msg["profileid"]
            self.flow = msg["flow"]
            # These following extra fields are expected in testing. update the original
            # flow dict to have them
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
                # of flows. So we dont retrain every 1 flow.
                if (
                    sum_labeled_flows >= self.minimum_labels_to_start_train
                ):
                    if (sum_labeled_flows - self.last_number_of_flows_when_trained >= self.minimum_labels_to_retrain):
                        # So for example we retrain every 50 labels and only when
                        # we have at least 50 labels
                        self.print(
                            f"Training the model with the last group of "
                            f"flows and labels. Total flows: {sum_labeled_flows}."
                        )
                        # Process all flows in the DB and make them ready
                        # for pandas
                        self.process_training_flows()
                        # Train an algorithm
                        self.train()
                        self.last_number_of_flows_when_trained = sum_labeled_flows

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
                            f"Predicted {pred[0]} for ground-truth label"
                            f' {label}. Flow {self.flow["saddr"]}:'
                            f'{self.flow["sport"]} ->'
                            f' {self.flow["daddr"]}:'
                            f'{self.flow["dport"]}/'
                            f'{self.flow["proto"]}',
                            0,
                            3,
                        )
                    if pred[0] == "Malicious":
                        # Generate an alert
                        self.set_evidence_malicious_flow(self.flow, self.twid)
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
