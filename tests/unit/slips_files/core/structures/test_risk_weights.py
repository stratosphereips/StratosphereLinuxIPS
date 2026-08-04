# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import pytest

from slips_files.core.structures.risk_weights import (
    HIGH_RISK_WEIGHT,
    LOW_RISK_WEIGHT,
    MEDIUM_RISK_WEIGHT,
    RATL_THRESHOLD,
    RiskWeight,
    convert_weight_to_risk_weight_enum_member,
    get_risk_weight_for_accumulated_threat_level,
    increase_risk_weight,
)
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "risk_weight, expected_bucket",
    [
        (LOW_RISK_WEIGHT, RiskWeight.LOW),
        (MEDIUM_RISK_WEIGHT, RiskWeight.MEDIUM),
        (HIGH_RISK_WEIGHT, RiskWeight.HIGH),
    ],
)
def test_get_risk_weight_from_weight(
    risk_weight: float, expected_bucket: RiskWeight
) -> None:
    ModuleFactory().create_evidence_handler_worker_obj()

    assert (
        convert_weight_to_risk_weight_enum_member(risk_weight)
        == expected_bucket
    )


@pytest.mark.parametrize(
    "risk_weight, expected_bucket",
    [
        (RiskWeight.LOW, RiskWeight.MEDIUM),
        (RiskWeight.MEDIUM, RiskWeight.HIGH),
        (RiskWeight.HIGH, RiskWeight.HIGH),
    ],
)
def test_increase_risk_weight(
    risk_weight: RiskWeight, expected_bucket: RiskWeight
) -> None:
    ModuleFactory().create_evidence_handler_worker_obj()

    assert increase_risk_weight(risk_weight) == expected_bucket


@pytest.mark.parametrize(
    "accumulated_threat_level, expected_bucket",
    [
        (0.0, RiskWeight.LOW),
        (5.0, RiskWeight.LOW),
        (25.0, RiskWeight.LOW),
        (100.0, RiskWeight.LOW),
        (1_000.0, RiskWeight.LOW),
    ],
)
def test_get_risk_weight_for_accumulated_threat_level(
    accumulated_threat_level: float, expected_bucket: RiskWeight
) -> None:
    ModuleFactory().create_evidence_handler_worker_obj()

    assert (
        get_risk_weight_for_accumulated_threat_level(accumulated_threat_level)
        == expected_bucket
    )


def test_risk_weights_are_configured_multipliers() -> None:
    ModuleFactory().create_evidence_handler_worker_obj()

    assert RiskWeight.LOW.weight == LOW_RISK_WEIGHT
    assert RiskWeight.MEDIUM.weight == MEDIUM_RISK_WEIGHT
    assert RiskWeight.HIGH.weight == HIGH_RISK_WEIGHT
    assert RATL_THRESHOLD > 0
