# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import re


def measure_regex_specificity(regex_text: str) -> dict:
    literal_chars = 0
    meta_tokens = 0
    wildcard_points = 0.0
    idx = 0
    while idx < len(regex_text):
        char = regex_text[idx]
        next_char = regex_text[idx + 1] if idx + 1 < len(regex_text) else ""

        if char == "\\":
            token = regex_text[idx : idx + 2]
            meta_tokens += 1
            if len(token) == 2 and token[1] in ".^$*+?{}[]()|\\":
                literal_chars += 1
            else:
                wildcard_points += 1.0
            idx += 2 if next_char else 1
            continue

        if char.isalnum() or char in "-_/:,@=":
            literal_chars += 1
            idx += 1
            continue

        meta_tokens += 1
        if char == "." and next_char in {"*", "+"}:
            wildcard_points += 2.5
        elif char == ".":
            wildcard_points += 1.5
        elif char == "[":
            wildcard_points += 1.2
        elif char in {"*", "+", "?"}:
            wildcard_points += 1.0
        idx += 1

    effective_length = max(1, literal_chars + meta_tokens)
    specificity_ratio = min(1.0, literal_chars / effective_length)
    wildcard_penalty = min(1.0, wildcard_points / max(1.0, effective_length / 2))
    return {
        "specificity_ratio": specificity_ratio,
        "wildcard_penalty": wildcard_penalty,
    }


def compute_match_strength(
    compiled_regex: re.Pattern,
    value: str,
    regex_features: dict | None = None,
) -> float:
    value = str(value or "")
    if not value:
        return 0.0

    if regex_features is None:
        regex_features = measure_regex_specificity(compiled_regex.pattern)

    best_score = 0.0
    value_len = max(1, len(value))
    for match in compiled_regex.finditer(value):
        start, end = match.span()
        span_len = max(0, end - start)
        if span_len <= 0:
            continue

        span_ratio = min(1.0, span_len / value_len)
        start_bonus = 1.0 if start == 0 else 0.0
        end_bonus = 1.0 if end == len(value) else 0.0
        full_bonus = 1.0 if start == 0 and end == len(value) else 0.0
        score = (
            40.0 * span_ratio
            + 12.0 * start_bonus
            + 12.0 * end_bonus
            + 16.0 * full_bonus
            + 30.0 * regex_features["specificity_ratio"]
            - 18.0 * regex_features["wildcard_penalty"]
        )
        best_score = max(best_score, max(0.0, min(100.0, score)))
    return best_score
