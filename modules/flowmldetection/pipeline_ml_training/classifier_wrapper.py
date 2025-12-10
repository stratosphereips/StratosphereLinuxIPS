import pickle
from pathlib import Path
from .commons import BENIGN, MALICIOUS
from typing import Union
import numpy


# Author: Jan Svoboda
# functionality: Wrapper for classifiers to provide a common interface for training and prediction
# functions: save/load, fit/predict, init new classifier
#
class ClassifierWrapper:
    def __init__(self, classifier, preprocessing_handler, classes=None):

        self.classifier = classifier
        self.is_trained = False
        self.classes = classes if classes is not None else [BENIGN, MALICIOUS]
        self.dummy_flows = {}
        self.fill_dummy()
        self.preprocessing_handler = preprocessing_handler
        assert len(self.classes) >= 2, "At least two classes must be specified"

    def fill_dummy(self):
        # these dummy flows are taken from slips itself
        dummy_malicious_flow = numpy.array(
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

        # Dummy benign flow
        dummy_benign_flow = numpy.array(
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

        dummy_default_flow = numpy.array(
            [
                10.0,  # dur
                0.0,  # proto (tcp)
                0.0,  # sport
                0.0,  # dport
                1.0,  # spkts
                1.0,  # dpkts
                1.0,  # sbytes
                1.0,  # dbytes
                1.0,  # state (Established)
                2.0,  # bytes (sbytes + dbytes)
                2.0,  # pkts (spkts + dpkts)
            ]
        ).reshape(1, -1)

        self.dummy_flows[BENIGN] = (dummy_benign_flow, BENIGN)
        self.dummy_flows[MALICIOUS] = (dummy_malicious_flow, MALICIOUS)
        self.dummy_flows["default"] = (dummy_default_flow, "default")

    def load_classifier(
        self, path: Union[str, Path], name: str = "classifier.bin"
    ):
        path = Path(path)
        if not path.exists() or not path.is_dir():
            raise FileNotFoundError(f"Directory {path} does not exist")
        model_path = path / name
        if not model_path.exists():
            pkl_files = list(path.glob("*.bin"))
            available = [f.name for f in pkl_files]
            print(
                f"Classifier file {model_path} does not exist. Available .bin files: {available}"
            )
            raise FileNotFoundError(
                f"Classifier file {model_path} does not exist"
            )

        with open(model_path, "rb") as f:
            self.classifier = pickle.load(f)
        self.is_trained = True

    def process_flows(self, X, y):
        # first fit, check for class coverage (at least one??)
        missing_classes = [cls for cls in self.classes if cls not in set(y)]
        if missing_classes:
            print(
                f"Warning: The initial training data does not contain samples for all classes. Missing classes: {missing_classes}"
            )
        for cls in missing_classes:
            if not hasattr(self, "dummy_flows"):
                raise AttributeError(
                    "No dummy samples provided for missing classes."
                )
            # print("class ", cls, " is missing, adding dummy flow for initial training")
            dummy_flow, _ = self.dummy_flows.get(
                cls, self.dummy_flows["default"]
            )
            processed_dummy = self.preprocessing_handler.transform(dummy_flow)
            X = numpy.concatenate([X, processed_dummy], axis=0)
            y = numpy.concatenate([y, numpy.array([cls])], axis=0)
        self.is_trained = True
        return X, y

    def native_fitting_function(self, X, y, *args, **kwargs):
        pass

    def partial_fit(self, X, y):
        try:
            if not self.is_trained:
                X, y = self.process_flows(X, y)
                self.native_fitting_function(X, y, classes=self.classes)
            else:
                self.native_fitting_function(X, y)
        except Exception as e:
            print(f"[ERROR] Classifier partial_fit failed: {e}")
            raise

    def predict(self, X):
        return self.classifier.predict(X)

    def getClassifier(self):
        return self.classifier

    def save_classifier(
        self,
        path: Union[str, Path] = "./models/",
        name: str = "classifier.bin",
    ):
        path = Path(path)
        if not path.exists():
            path.mkdir(parents=True, exist_ok=True)
        model_path = path / name
        with open(model_path, "wb") as f:
            pickle.dump(self.classifier, f)


class SKLearnClassifierWrapper(ClassifierWrapper):
    def __init__(self, classifier, preprocessing_handler=None, classes=None):
        super().__init__(
            classifier,
            preprocessing_handler=preprocessing_handler,
            classes=classes,
        )

    def native_fitting_function(self, X, y, *args, **kwargs):
        self.classifier.partial_fit(X, y, *args, **kwargs)


# wrappers for other libraries? torch, xgboost, lightgbm
class RiverClassifierWrapper(ClassifierWrapper):
    def __init__(self, classifier, preprocessing_handler=None, classes=None):
        super().__init__(
            classifier,
            preprocessing_handler=preprocessing_handler,
            classes=classes,
        )

    def native_fitting_function(self, X, y, *args, **kwargs):
        # Prefer batch update if the river estimator supports learn_many
        if hasattr(self.classifier, "learn_many"):
            try:
                # River expects a mapping feature_name -> array/series for batch updates.
                if isinstance(X, numpy.ndarray):
                    X_batch = {i: X[:, i] for i in range(X.shape[1])}
                else:
                    X_batch = X
                self.classifier.learn_many(X_batch, y)
                return
            except Exception:
                # if conversion fails, fall back to per-sample learning
                pass

        # fallback: per-sample learning
        for xi, yi in zip(X, y):
            self.classifier.learn_one(
                x=dict(enumerate(xi)), y=yi
            )  # ,w= weights[yi])

    def predict(self, X):
        # Prefer batch prediction if the river estimator supports predict_many
        if hasattr(self.classifier, "predict_many"):
            try:
                if isinstance(X, numpy.ndarray):
                    X_batch = {i: X[:, i] for i in range(X.shape[1])}
                else:
                    X_batch = X
                preds = self.classifier.predict_many(X_batch)
                return numpy.array(list(preds))
            except Exception:
                # fall through to per-sample prediction on failure
                pass

        # Fallback: per-sample prediction using predict_one (always present in River)
        preds = []
        for xi in X:
            preds.append(self.classifier.predict_one(dict(enumerate(xi))))

        return numpy.array(preds)
