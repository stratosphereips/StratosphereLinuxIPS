"""Shared training/runtime letter encoding with explicit padding compatibility."""

import numpy as np

VOCABULARY = "abcdefghiABCDEFGHIrstuvwxyzRSTUVWXYZ1234567890,.+*"


def encode_letters(
    sequence: str, length: int = 500, schema: int = 1
) -> np.ndarray:
    """Encode the latest letters with numeric zero padding.

    Parameters:
        sequence: Behavioral letters, including time separators.
        length: Fixed sequence length expected by the model.
        schema: 1 preserves the shipped legacy token map; 2 reserves zero for padding.

    Returns:
        Integer input of shape (1, length, 1), matching training.
    """
    if schema not in (1, 2) or length < 1:
        raise ValueError("Unsupported letter encoding schema or length")
    mapping = {
        letter: index + (schema == 2)
        for index, letter in enumerate(VOCABULARY)
    }
    result = np.zeros((1, length, 1), dtype=np.int32)
    result[0, : min(length, len(sequence)), 0] = [
        mapping[letter] for letter in sequence[-length:]
    ]
    return result


def connection_count(sequence: str) -> int:
    """Count flow symbols without counting time separators or long-gap zeroes.

    Parameters:
        sequence: Behavioral letters.

    Returns:
        Number of represented connections.
    """
    return sum(
        letter in VOCABULARY and letter not in "0,.+*" for letter in sequence
    )


def is_established(state: str) -> bool:
    """Match complete state names and Zeek established TCP outcomes.

    Parameters:
        state: Raw Zeek or normalized Slips connection state.

    Returns:
        True for established sessions, including SF, excluding NotEstablished.
    """
    return str(state).replace(" ", "").lower() in {
        "sf",
        "s1",
        "s2",
        "s3",
        "rsto",
        "rstr",
        "established",
    }
