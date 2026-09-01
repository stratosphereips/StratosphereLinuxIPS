import re

import pytest

from modules.regex_generator.match_strength import (
    compute_match_strength,
    measure_regex_specificity,
)
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "regex_text, expected_key",
    [
        (r"evil\.example\.com", "specificity_ratio"),
        (r".*example.*", "wildcard_penalty"),
    ],
)
def test_measure_regex_specificity_returns_feature_scores(
    regex_text: str, expected_key: str
) -> None:
    """Verify regex specificity metrics include normalized feature scores.

    Parameters:
        regex_text: Regex text to inspect.
        expected_key: Expected feature key in the metrics.

    Return value:
        None.
    """
    module_factory = ModuleFactory()

    features = measure_regex_specificity(regex_text)

    assert module_factory
    assert expected_key in features
    assert 0.0 <= features[expected_key] <= 1.0


def test_compute_match_strength_scores_full_match_above_partial() -> None:
    """Verify full regex matches score higher than partial matches.

    Return value:
        None.
    """
    module_factory = ModuleFactory()
    compiled_regex = re.compile(r"evil\.example\.com")

    full_score = compute_match_strength(compiled_regex, "evil.example.com")
    partial_score = compute_match_strength(
        compiled_regex, "prefix-evil.example.com"
    )

    assert module_factory
    assert full_score > partial_score
