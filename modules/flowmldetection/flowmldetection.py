from sklearn.linear_model import SGDClassifier
from sklearn.preprocessing import StandardScaler
import pickle
import pandas as pd
import json
import datetime
import traceback
import warnings


from slips_files.common.state_handler import get_final_state_from_flags
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from slips_files.common.abstracts.module import IModule
from slips_files.core.evidence_structure.evidence import (
    Evidence,
    ProfileID,
    TimeWindow,
    Attacker,
    ThreatLevel,
    EvidenceType,
    IoCType,
    Direction,
    IDEACategory,
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
            to_discard = ["arp", "ARP", "icmp", "igmp", "ipv6-icmp"]
            for proto in to_discard:
                dataset = dataset[dataset.proto != proto]

            # For now, discard these
            to_drop = [
                "appproto",
                "daddr",
                "saddr",
                "ts",
                "origstate",
                "type_",
                "dir_",
                "history",
                "dbytes",
                "dpkts",
                "smac",
                "dmac",
            ]
            for field in to_drop:
                try:
                    dataset = dataset.drop(field, axis=1)
                except ValueError:
                    pass

            # When flows are read from Slips sqlite,
            # the state is not transformed to 'Established' or
            # 'Not Established', it is still 'S0' and others
            # So transform here
            dataset["state"] = dataset.apply(
                lambda row: get_final_state_from_flags(
                    row["state"], row["pkts"]
                ),
                axis=1,
            )
            # dataset.state = new_state_column

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
            dataset.proto = dataset.proto.astype("float64")
            try:
                # Convert dport to float
                dataset.dport = dataset.dport.astype("float")
            except ValueError:
                pass
            try:
                # Convert sport to float
                dataset.sport = dataset.sport.astype("float")
            except ValueError:
                pass
            try:
                # Convert Dur to float
                dataset.dur = dataset.dur.astype("float")
            except ValueError:
                pass
            try:
                # Convert TotPkts to float
                dataset.pkts = dataset.pkts.astype("float")
            except ValueError:
                pass
            try:
                # Convert SrcPkts to float
                dataset.spkts = dataset.spkts.astype("float")
            except ValueError:
                pass
            try:
                # Convert TotBytes to float
                dataset.allbytes = dataset.allbytes.astype("float")
            except ValueError:
                pass
            try:
                # Convert SrcBytes to float
                dataset.sbytes = dataset.sbytes.astype("float")
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
            flows: list = self.db.get_all_flows()

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
                        "origstate": "SRPA_SPA",
                        "state": "Established",
                        "pkts": 84,
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
                        "origstate": "SRPA_SPA",
                        "state": "Established",
                        "pkts": 67,
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

    def process_flow(self):
        """
        Process one flow. Only used during detection in testing
        Store the pandas df in self.flow
        """
        try:
            # Convert the flow to a pandas dataframe
            raw_flow = pd.DataFrame(self.flow_dict, index=[0])
            # Process features
            dflow = self.process_features(raw_flow)
            # Update the flow to the processed version
            self.flow = dflow
        except Exception:
            # Stop the timer
            self.print("Error in process_flow()")
            self.print(traceback.format_exc(), 0, 1)

    def detect(self):
        """
        Detect this flow with the current model stored
        """
        try:
            # Store the real label if there is one
            # y_flow = self.flow["label"]
            # remove the real label column
            self.flow = self.flow.drop("label", axis=1)
            # remove the label predictions column of the other modules
            X_flow = self.flow.drop("module_labels", axis=1)
            # Scale the flow
            X_flow = self.scaler.transform(X_flow)
            pred = self.clf.predict(X_flow)
            return pred
        except Exception:
            # Stop the timer
            self.print("Error in detect() X_flow:")
            self.print(X_flow)
            self.print(traceback.format_exc(), 0, 1)

    def store_model(self):
        """
        Store the trained model on disk
        """
        self.print("Storing the trained model and scaler on disk.", 0, 2)
        with open("./modules/flowmldetection/model.bin", "wb") as f:
            data = pickle.dumps(self.clf)
            f.write(data)
        with open("./modules/flowmldetection/scaler.bin", "wb") as g:
            data = pickle.dumps(self.scaler)
            g.write(data)

    def read_model(self):
        """
        Read the trained model from disk
        """
        try:
            self.print("Reading the trained model from disk.", 0, 2)
            with open("./modules/flowmldetection/model.bin", "rb") as f:
                self.clf = pickle.load(f)
            self.print("Reading the trained scaler from disk.", 0, 2)
            with open("./modules/flowmldetection/scaler.bin", "rb") as g:
                self.scaler = pickle.load(g)
        except FileNotFoundError:
            # If there is no model, create one empty
            self.print("There was no model. Creating a new empty model.", 0, 2)
            self.clf = SGDClassifier(
                warm_start=True, loss="hinge", penalty="l1"
            )
        except EOFError:
            self.print(
                "Error reading model from disk. Creating a new empty model.",
                0,
                2,
            )
            self.clf = SGDClassifier(
                warm_start=True, loss="hinge", penalty="l1"
            )

    def set_evidence_malicious_flow(
        self,
        saddr: str,
        sport: str,
        daddr: str,
        dport: str,
        twid: str,
        uid: str,
    ):
        confidence: float = 0.1
        ip_identification = self.db.get_ip_identification(daddr)
        description = (
            f"Malicious flow by ML. Src IP {saddr}:{sport} to "
            f"{daddr}:{dport} {ip_identification}"
        )

        timestamp = utils.convert_format(
            datetime.datetime.now(), utils.alerts_format
        )

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.MALICIOUS_FLOW,
            attacker=Attacker(
                direction=Direction.SRC, attacker_type=IoCType.IP, value=saddr
            ),
            threat_level=ThreatLevel.LOW,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=int(twid.replace("timewindow", ""))),
            uid=[uid],
            timestamp=timestamp,
            category=IDEACategory.ANOMALY_TRAFFIC,
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
            data = msg["data"]
            data = json.loads(data)
            # profileid = data["profileid"]
            twid = data["twid"]
            flow = data["flow"]
            flow = json.loads(flow)
            # Convert the common fields to something that can
            # be interpreted
            # Get the uid which is the key
            uid = next(iter(flow))
            self.flow_dict = json.loads(flow[uid])

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
                    # We get here every 'self.minimum_lables_to_retrain' amount of labels
                    # So for example we retrain every 100 labels and only when we have at least 100 labels
                    self.print(
                        f"Training the model with the last group of flows and labels. Total flows: {sum_labeled_flows}."
                    )
                    # Process all flows in the DB and make them ready for pandas
                    self.process_flows()
                    # Train an algorithm
                    self.train()
            elif self.mode == "test":
                # We are testing, which means using the model to detect
                self.process_flow()

                # After processing the flow, it may happen that we delete icmp/arp/etc
                # so the dataframe can be empty
                if self.flow is not None and not self.flow.empty:
                    # Predict
                    pred = self.detect()
                    label = self.flow_dict["label"]

                    # Report
                    if label and label != "unknown" and label != pred[0]:
                        # If the user specified a label in test mode, and the label
                        # is diff from the prediction, print in debug mode
                        self.print(
                            f'Report Prediction {pred[0]} for label {label} flow {self.flow_dict["saddr"]}:'
                            f'{self.flow_dict["sport"]} -> {self.flow_dict["daddr"]}:'
                            f'{self.flow_dict["dport"]}/{self.flow_dict["proto"]}',
                            0,
                            3,
                        )
                    if pred[0] == "Malware":
                        # Generate an alert
                        self.set_evidence_malicious_flow(
                            self.flow_dict["saddr"],
                            self.flow_dict["sport"],
                            self.flow_dict["daddr"],
                            self.flow_dict["dport"],
                            twid,
                            uid,
                        )
                        self.print(
                            f'Prediction {pred[0]} for label {label} flow {self.flow_dict["saddr"]}:'
                            f'{self.flow_dict["sport"]} -> {self.flow_dict["daddr"]}:'
                            f'{self.flow_dict["dport"]}/{self.flow_dict["proto"]}',
                            0,
                            2,
                        )
