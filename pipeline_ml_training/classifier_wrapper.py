import pickle
from pathlib import Path
from commons import BENIGN, MALICIOUS
from typing import Union


# Author: Jan Svoboda
# functionality: Wrapper for classifiers to provide a common interface for training and prediction
# functions: save/load, fit/predict, init new classifier
#
class ClassifierWrapper:
    def __init__(self, classifier):
        self.classifier = classifier
        self.is_trained = False
        self.classes = [BENIGN, MALICIOUS]

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
                raise ValueError(
                    f"First batch must contain at least one sample of each class. Missing: {missing_classes}"
                )

            self.classifier.partial_fit(X, y, classes=self.classes)
        else:
            self.classifier.partial_fit(X, y)

    def predict(self, X):
        return self.classifier.predict(X)

    def getClassifier(self):
        return self.classifier

    def save_classifier(
        self, path: Union[str, Path], name: str = "classifier.pkl"
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
