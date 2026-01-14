# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
from typing import Optional

# SPDX-License-Identifier: GPL-2.0-only
import json
import os
import pickle
import traceback
import warnings

import numpy
import pandas as pd
from sklearn.linear_model import SGDClassifier
from sklearn.exceptions import NotFittedError
from sklearn.preprocessing import StandardScaler

from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from slips_files.common.abstracts.imodule import IModule
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
        self.model_load_path = None
        self.scaler_load_path = None
        self.model_family = "legacy"
        self.model_family_override = None
        self.malicious_labels = {"Malware", "Malicious"}
        self.benign_labels = {"Normal", "Benign"}
        # Read the configuration
        self.read_configuration()
        # Minum amount of new lables needed to trigger the train
        self.minimum_lables_to_retrain = 50
        # To plot the scores of training
        # self.scores = []
        # The scaler trained during training and to use during testing
        self.scaler = StandardScaler()

    def read_configuration(self):
        conf = ConfigParser()
        self.mode = conf.get_ml_mode()
        model_load_path = conf.read_configuration(
            "flowmldetection", "model_load_path", None
        )
        scaler_load_path = conf.read_configuration(
            "flowmldetection", "scaler_load_path", None
        )
        if model_load_path:
            self.model_load_path = model_load_path
        if scaler_load_path:
            self.scaler_load_path = scaler_load_path
        if self.model_load_path and not self.scaler_load_path:
            guessed_scaler_path = self.model_load_path
            guessed_scaler_path = guessed_scaler_path.replace(
                "/classifiers/", "/scalers/"
            )
            guessed_scaler_path = guessed_scaler_path.replace(
                "_model.bin", "_scaler.bin"
            )
            if os.path.exists(guessed_scaler_path):
                self.scaler_load_path = guessed_scaler_path
            else:
                base_name = os.path.basename(guessed_scaler_path)
                if base_name.startswith("model_"):
                    alt_scaler_path = os.path.join(
                        os.path.dirname(guessed_scaler_path),
                        f"scaler_{base_name[len('model_'):]}"
                    )
                    if os.path.exists(alt_scaler_path):
                        self.scaler_load_path = alt_scaler_path
        model_family_override = conf.read_configuration(
            "flowmldetection", "model_family", None
        )
        if model_family_override:
            self.model_family_override = str(model_family_override).lower()

    def _infer_model_family(self) -> str:
        if self.model_family_override:
            return self.model_family_override
        if hasattr(self.clf, "predict_one") or hasattr(self.clf, "learn_one"):
            return "river"
        if self.model_load_path and "river_models" in self.model_load_path:
            return "river"
        return "legacy"

    def _canonical_label(self, label: Optional[str]) -> Optional[str]:
        if label in self.malicious_labels:
            return "Malicious"
        if label in self.benign_labels:
            return "Benign"
        return label

    def _is_malicious_label(self, label: Optional[str]) -> bool:
        return label in self.malicious_labels

    def drop_labels(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Drop label fields from the DataFrame to prepare for prediction.
        """
        if df is None:
            return df
        return df.drop(
            [
                "ground_truth_label",
                "detailed_ground_truth_label",
                "label",
                "module_labels",
            ],
            axis=1,
            errors="ignore",
        )

    def _align_features_for_scaler(
        self, df: pd.DataFrame, scaler
    ) -> Optional[pd.DataFrame]:
        feature_names = getattr(scaler, "feature_names_in_", None)
        if feature_names is None:
            return df
        feature_names = list(feature_names)
        missing = [name for name in feature_names if name not in df.columns]
        extra = [name for name in df.columns if name not in feature_names]
        if missing or extra:
            message = (
                "Scaler feature set mismatch. "
                f"missing={missing} extra={extra} "
                f"expected={feature_names} actual={list(df.columns)}"
            )
            raise ValueError(message)
        return df.loc[:, feature_names]

    def train(self):
        """
        Train a model based on the flows we receive and the labels
        """
        if self.model_family == "river":
            self.print(
                "Training is not supported for river models in this module.",
                0,
                1,
            )
            return
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
        if self.model_family == "river":
            return self._process_features_river(dataset)
        return self._process_features_legacy(dataset)

    def _process_features_legacy(self, dataset):
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
                "interface",
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

    def _process_features_river(self, dataset):
        """
        Process features to match the river model training pipeline.
        """
        try:
            cols = [
                "proto",
                "dport",
                "sport",
                "dur",
                "pkts",
                "spkts",
                "dpkts",
                "bytes",
                "sbytes",
                "dbytes",
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
                if "proto" in dataset.columns:
                    dataset = dataset[dataset.proto != proto]

            # If the proto is in the list to delete and there is only one flow,
            # then the dataset will be empty
            if dataset.empty:
                return dataset

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
                "interface",
                "allbytes",
            ]
            for field in to_drop:
                try:
                    dataset = dataset.drop(field, axis=1)
                except (ValueError, KeyError):
                    pass

            if {
                "state",
                "spkts",
                "dpkts",
            }.issubset(dataset.columns):
                dataset["state"] = dataset.apply(
                    lambda row: self.db.get_final_state_from_flags(
                        row["state"], (row["spkts"] + row["dpkts"])
                    ),
                    axis=1,
                )

            if (
                "state" in dataset.columns
                and pd.api.types.is_string_dtype(dataset["state"])
            ):
                dataset.state = dataset.state.str.replace(
                    r"(^.*Not ?Established.*$)", "0", regex=True
                )
                dataset.state = dataset.state.str.replace(
                    r"(^.*Established.*$)", "1", regex=True
                )
                try:
                    dataset.state = dataset.state.astype("float64")
                except (ValueError, AttributeError):
                    pass

            if (
                "proto" in dataset.columns
                and pd.api.types.is_string_dtype(dataset["proto"])
            ):
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

            if {"sbytes", "dbytes"}.issubset(dataset.columns):
                dataset["bytes"] = dataset["sbytes"] + dataset["dbytes"]
            if {"spkts", "dpkts"}.issubset(dataset.columns):
                dataset["pkts"] = dataset["spkts"] + dataset["dpkts"]

            fields_to_convert_to_float = [
                "proto",
                "dport",
                "sport",
                "dur",
                "pkts",
                "spkts",
                "dpkts",
                "bytes",
                "sbytes",
                "dbytes",
                "state",
            ]
            for field in fields_to_convert_to_float:
                if field in dataset.columns:
                    try:
                        dataset[field] = dataset[field].astype("float64")
                    except (ValueError, AttributeError):
                        pass

            return dataset
        except Exception:
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
            if dflow is not None and dflow.empty:
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
            given_x_flow = x_flow
            if x_flow is None or getattr(x_flow, "empty", False):
                return None
            if self.clf is None:
                self.print("No model loaded. Skipping detection.", 0, 1)
                return None
            x_flow = self.drop_labels(x_flow)
            if self.model_family == "river":
                return self._detect_river(x_flow)
            if self.scaler is None:
                self.print("No scaler loaded. Skipping detection.", 0, 1)
                return None
            x_flow = self._align_features_for_scaler(x_flow, self.scaler)
            if x_flow is None:
                return None
            try:
                x_flow: numpy.ndarray = self.scaler.transform(x_flow)
            except NotFittedError as exc:
                raise RuntimeError(
                    "Scaler is not fitted. Load a trained scaler or retrain."
                ) from exc
            try:
                pred: numpy.ndarray = self.clf.predict(x_flow)
            except NotFittedError as exc:
                raise RuntimeError(
                    "Model is not fitted. Load a trained model or retrain."
                ) from exc
            return pred
        except Exception as e:
            self.print(
                f"Error in detect() while processing " f"\n{given_x_flow}\n{e}"
            )
            self.print(traceback.format_exc(), 0, 1)

    def _detect_river(self, x_flow: pd.DataFrame) -> Optional[numpy.ndarray]:
        record = None
        if self.scaler is not None:
            if hasattr(self.scaler, "transform_one"):
                record = self.scaler.transform_one(x_flow.iloc[0].to_dict())
            elif hasattr(self.scaler, "transform"):
                aligned_flow = self._align_features_for_scaler(
                    x_flow, self.scaler
                )
                if aligned_flow is None:
                    return None
                x_flow = aligned_flow
                scaled = self.scaler.transform(x_flow)
                if isinstance(scaled, pd.DataFrame):
                    record = scaled.iloc[0].to_dict()
                else:
                    record = dict(zip(x_flow.columns, scaled[0]))
        if record is None:
            record = x_flow.iloc[0].to_dict()

        if hasattr(self.clf, "predict_one"):
            pred = self.clf.predict_one(record)
            return numpy.asarray([pred])
        if hasattr(self.clf, "predict"):
            return self.clf.predict(x_flow)

        self.print("Loaded model does not support prediction.", 0, 1)
        return None

    def store_model(self):
        """
        Store the trained model on disk
        """
        if not self.model_load_path or not self.scaler_load_path:
            raise RuntimeError(
                "Model/scaler paths are not configured. "
                "Set flowmldetection.model_load_path and "
                "flowmldetection.scaler_load_path."
            )
        self.print("Storing the trained model and scaler on disk.", 0, 2)
        with open(self.model_load_path, "wb") as f:
            data = pickle.dumps(self.clf)
            f.write(data)
        with open(self.scaler_load_path, "wb") as g:
            data = pickle.dumps(self.scaler)
            g.write(data)

    def read_model(self):
        """
        Read the trained model from disk
        """
        try:
            if not self.model_load_path:
                raise RuntimeError(
                    "Model load path is not configured. "
                    "Set flowmldetection.model_load_path."
                )
            self.print("Reading the trained model from disk.", 0, 2)
            with open(self.model_load_path, "rb") as f:
                self.clf = pickle.load(f)
            self.model_family = self._infer_model_family()
        except ModuleNotFoundError as e:
            self.print(
                f"Failed to read model. Missing dependency: {e}", 0, 1
            )
            self.model_family = self._infer_model_family()
            self.clf = None
            return
        except FileNotFoundError:
            if self.mode == "test":
                raise
            # If there is no model, create one empty
            self.print(
                "There was no model. " "Creating a new empty model.", 0, 2
            )
            self.clf = SGDClassifier(
                warm_start=True, loss="hinge", penalty="l1"
            )
            self.model_family = "legacy"
        except EOFError:
            if self.mode == "test":
                raise
            self.print(
                "Error reading model from disk. "
                "Creating a new empty model.",
                0,
                2,
            )
            self.clf = SGDClassifier(
                warm_start=True, loss="hinge", penalty="l1"
            )
            self.model_family = "legacy"
        except Exception:
            self.print("Error reading model from disk.", 0, 1)
            self.print(traceback.format_exc(), 0, 1)
            self.model_family = self._infer_model_family()
            self.clf = None
            return

        try:
            if not self.scaler_load_path:
                raise RuntimeError(
                    "Scaler load path is not configured. "
                    "Set flowmldetection.scaler_load_path."
                )
            self.print("Reading the trained scaler from disk.", 0, 2)
            with open(self.scaler_load_path, "rb") as g:
                self.scaler = pickle.load(g)
        except ModuleNotFoundError as e:
            self.print(
                f"Failed to read scaler. Missing dependency: {e}", 0, 1
            )
            self.scaler = None
        except FileNotFoundError:
            if self.mode == "test":
                raise
            if self.model_family == "river":
                self.print("There was no scaler. Continuing without it.", 0, 2)
                self.scaler = None
            else:
                self.print(
                    "There was no scaler. Creating a new empty scaler.",
                    0,
                    2,
                )
                self.scaler = StandardScaler()
        except EOFError:
            if self.mode == "test":
                raise
            if self.model_family == "river":
                self.print(
                    "Error reading scaler from disk. Continuing without it.",
                    0,
                    2,
                )
                self.scaler = None
            else:
                self.print(
                    "Error reading scaler from disk. "
                    "Creating a new empty scaler.",
                    0,
                    2,
                )
                self.scaler = StandardScaler()
        except Exception:
            self.print("Error reading scaler from disk.", 0, 1)
            self.print(traceback.format_exc(), 0, 1)
            self.scaler = None

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
        if self.mode == "train" and self.model_family != "river":
            self.store_model()

    def pre_main(self):
        utils.drop_root_privs_permanently()
        # Load the model
        self.read_model()

    def main(self):
        if msg := self.get_msg("new_flow"):
            msg = json.loads(msg["data"])
            twid = msg["twid"]
            self.flow = msg["flow"]
            # these fields are expected in testing. update the original
            # flow dict to have them
            flow_update = {
                # the flow["state"] is the origstate, we dont need that here
                # we need the interpreted state
                "state": msg["interpreted_state"],
                "label": msg["label"],
                "module_labels": msg["module_labels"],
            }
            if self.model_family != "river":
                flow_update.update(
                    {
                        "allbytes": (
                            self.flow["sbytes"] + self.flow["dbytes"]
                        ),
                        "pkts": self.flow["spkts"] + self.flow["dpkts"],
                    }
                )
            self.flow.update(flow_update)

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
                    if pred is None or getattr(pred, "size", 0) == 0:
                        # an error occurred
                        return

                    label = self.flow.get("label")
                    canonical_label = self._canonical_label(label)
                    canonical_pred = self._canonical_label(pred[0])
                    if (
                        label
                        and label != "unknown"
                        and canonical_label != canonical_pred
                    ):
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
                    if self._is_malicious_label(pred[0]):
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
