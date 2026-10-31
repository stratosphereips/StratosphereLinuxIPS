"""Train letters with explicit C2 labels and separate capture groups per split."""

import argparse
import csv
import hashlib
import json
from pathlib import Path
from typing import Any

import numpy as np

from modules.rnn_cc_detection.preprocessing import VOCABULARY, encode_letters


def load_splits(path: Path) -> dict[str, tuple[np.ndarray, np.ndarray]]:
    """Read reviewed TSV labels and reject overlapping captures or encoded inputs.

    Parameters:
        path: TSV with group, split, label (benign/c2), state columns.

    Returns:
        Independent train, validation and test arrays using padding schema 2.
    """
    groups: dict[str, str] = {}
    inputs: dict[bytes, tuple[str, str]] = {}
    splits: dict[str, list[tuple[np.ndarray, int]]] = {
        s: [] for s in ("train", "validation", "test")
    }
    with path.open() as source:
        reader = csv.DictReader(source, delimiter="\t")
        if not {"group", "split", "label", "state"}.issubset(
            reader.fieldnames or []
        ):
            raise ValueError(
                "Training requires group, split, label, state TSV columns; broad Botnet/Malware labels are not C2 labels"
            )
        for row in reader:
            group, split, label = row["group"], row["split"], row["label"]
            if (
                not group
                or split not in splits
                or label not in {"benign", "c2"}
            ):
                raise ValueError(
                    "Use a capture/session group, explicit split, and benign or c2 label"
                )
            if group in groups and groups[group] != split:
                raise ValueError("Capture group occurs in multiple splits")
            groups[group] = split
            encoded = encode_letters(row["state"], schema=2)[0]
            digest = hashlib.sha256(encoded.tobytes()).digest()
            if digest in inputs and inputs[digest] != (split, label):
                raise ValueError(
                    "Identical encoded input has conflicting labels or occurs in multiple splits"
                )
            inputs[digest] = (split, label)
            splits[split].append((encoded, int(label == "c2")))
    if any(
        {label for _, label in values} != {0, 1} for values in splits.values()
    ):
        raise ValueError(
            "Each independent split requires benign and confirmed C2 examples"
        )
    return {
        split: (
            np.asarray([x for x, _ in values]),
            np.asarray([y for _, y in values]),
        )
        for split, values in splits.items()
    }


def build_model(
    embed_dim: int, units: int, dropout: float, learning_rate: float
) -> Any:
    """Build an RNN with a real padding token and matching input shape.

    Parameters:
        embed_dim: Embedding width.
        units: Bidirectional GRU width.
        dropout: Regularization fraction.
        learning_rate: Adam learning rate.

    Returns:
        Compiled Keras binary classifier.
    """
    import tensorflow as tf

    layers = tf.keras.layers
    model = tf.keras.Sequential(
        [
            layers.Input(shape=(500, 1), dtype="int32"),
            layers.Reshape((500,)),
            layers.Embedding(len(VOCABULARY) + 1, embed_dim, mask_zero=True),
            layers.Bidirectional(layers.GRU(units)),
            layers.Dense(24, activation="relu"),
            layers.Dropout(dropout),
            layers.Dense(1, activation="sigmoid"),
        ]
    )
    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate),
        loss="binary_crossentropy",
        metrics=["accuracy"],
    )
    return model


def main() -> None:
    """Tune on validation only and evaluate the untouched test split once."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-D", "--dataset-file", type=Path, required=True)
    parser.add_argument("-S", "--model-file", type=Path, required=True)
    parser.add_argument("--epochs", type=int, default=30)
    parser.add_argument(
        "--trials",
        type=int,
        default=0,
        help="Optional Optuna trials; test data is excluded",
    )
    args = parser.parse_args()
    splits = load_splits(args.dataset_file)
    train_x, train_y = splits["train"]
    val_x, val_y = splits["validation"]
    parameters = {
        "embed_dim": 32,
        "units": 16,
        "dropout": 0.3,
        "learning_rate": 0.001,
    }
    if args.trials:
        import optuna
        import tensorflow as tf

        def objective(trial: Any) -> float:
            """Evaluate one model on validation captures only.

            Parameters:
                trial: Optuna trial suggesting model parameters.

            Returns:
                Validation loss to minimize.
            """
            tf.keras.backend.clear_session()
            params = {
                "embed_dim": trial.suggest_categorical(
                    "embed_dim", [16, 32, 64]
                ),
                "units": trial.suggest_categorical("units", [8, 16, 32]),
                "dropout": trial.suggest_float("dropout", 0.1, 0.5),
                "learning_rate": trial.suggest_float(
                    "learning_rate", 0.0001, 0.01, log=True
                ),
            }
            model = build_model(**params)
            model.fit(
                train_x,
                train_y,
                validation_data=(val_x, val_y),
                epochs=args.epochs,
                batch_size=100,
                verbose=0,
            )
            return float(model.evaluate(val_x, val_y, verbose=0)[0])

        study = optuna.create_study(direction="minimize")
        study.optimize(objective, n_trials=args.trials)
        parameters = study.best_params
    model = build_model(**parameters)
    model.fit(
        train_x,
        train_y,
        validation_data=(val_x, val_y),
        epochs=args.epochs,
        batch_size=100,
        verbose=1,
    )
    test = model.evaluate(*splits["test"], verbose=0)
    model.save(args.model_file)
    args.model_file.with_suffix(args.model_file.suffix + ".json").write_text(
        json.dumps(
            {
                "encoding_schema": 2,
                "test_loss": float(test[0]),
                "test_accuracy": float(test[1]),
                "parameters": parameters,
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
