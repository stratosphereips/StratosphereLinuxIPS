import pickle
from pathlib import Path
from commons import BENIGN, MALICIOUS
from typing import Union
import numpy


# Author: Jan Svoboda
# functionality: Wrapper for classifiers to provide a common interface for training and prediction
# functions: save/load, fit/predict, init new classifier
#
class ClassifierWrapper:
    def __init__(self, classifier):
        self.classifier = classifier
        self.is_trained = False
        self.classes = [BENIGN, MALICIOUS]
        self.dummy_flows = {}
        self.fill_dummy()

    def fill_dummy(self):
        dummy_malicious_flow = numpy.array(
            [
                0.0,  # proto (tcp)
                443.0,  # dport
                49733.0,  # sport
                1.9424750804901123,  # dur
                44.0,  # pkts (spkts + dpkts)
                17.0,  # spkts
                42764.0,  # bytes (sbytes + dbytes)
                25517.0,  # sbytes
                1.0,  # state (Established)
            ]
        ).reshape(1, -1)

        # Dummy benign flow (from previous code)
        dummy_benign_flow = numpy.array(
            [
                0.0,  # proto (tcp)
                80.0,  # dport
                47956.0,  # sport
                10.896695,  # dur
                1.0,  # pkts (spkts + dpkts)
                1.0,  # spkts
                67696.0,  # bytes (sbytes + dbytes)
                100.0,  # sbytes
                1.0,  # state (Established)
            ]
        ).reshape(1, -1)

        self.dummy_flows[BENIGN] = (dummy_benign_flow, BENIGN)
        self.dummy_flows[MALICIOUS] = (dummy_malicious_flow, MALICIOUS)

    def load_classifier(
        self, path: Union[str, Path], name: str = "classifier.pkl"
    ):
        path = Path(path)
        if not path.exists() or not path.is_dir():
            raise FileNotFoundError(f"Directory {path} does not exist")
        model_path = path / name
        if not model_path.exists():
            pkl_files = list(path.glob("*.pkl"))
            available = [f.name for f in pkl_files]
            print(
                f"Classifier file {model_path} does not exist. Available .pkl files: {available}"
            )
            raise FileNotFoundError(
                f"Classifier file {model_path} does not exist"
            )
        with open(model_path, "rb") as f:
            self.classifier = pickle.load(f)
        self.is_trained = True

    def fit(self, X, y):
        if not hasattr(self.classifier, "partial_fit"):
            raise NotImplementedError(
                "The underlying classifier does not support partial_fit."
            )

        if not self.is_trained:
            # first fit, check for class coverage (at least one??)
            missing_classes = [
                cls for cls in self.classes if cls not in set(y)
            ]
            if missing_classes:
                print(
                    f"Warning: The initial training data does not contain samples for all classes. Missing classes: {missing_classes}"
                )
            for cls in missing_classes:
                if (
                    not hasattr(self, "dummy_flows")
                    or cls not in self.dummy_flows
                ):
                    raise ValueError(
                        f"No dummy sample provided for missing class {cls} in self.dummy_flows."
                    )
                X = X.append(self.dummy_flows[cls][0])
                y = y.append(self.dummy_flows[cls][1])

            self.classifier.partial_fit(X, y, classes=self.classes)
        else:
            self.classifier.partial_fit(X, y)

    def predict(self, X):
        return self.classifier.predict(X)

    def getClassifier(self):
        return self.classifier

    def save_classifier(
        self,
        path: Union[str, Path] = "./models/",
        name: str = "classifier.pkl",
    ):
        path = Path(path)
        if not path.exists():
            path.mkdir(parents=True, exist_ok=True)
        model_path = path / name
        with open(model_path, "wb") as f:
            pickle.dump(self.classifier, f)


class SKLearnClassifierWrapper(ClassifierWrapper):
    def __init__(self, classifier):
        super().__init__(classifier)


# wrappers for other libraries? torch, xgboost, lightgbm
