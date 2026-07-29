# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import pytest

from slips_files.core.structures.risk_weights import (
    HIGH_RISK_WEIGHT,
    LOW_RISK_WEIGHT,
    MEDIUM_RISK_WEIGHT,
    RATL_THRESHOLD,
    RiskWeight,
    convert_float_to_risk_weight,
    get_risk_weight_for_accumulated_threat_level,
)
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "risk_weight, expected_bucket",
    [
        (0.0, RiskWeight.LOW),
        (LOW_RISK_WEIGHT, RiskWeight.LOW),
        (MEDIUM_RISK_WEIGHT, RiskWeight.MEDIUM),
        (HIGH_RISK_WEIGHT, RiskWeight.HIGH),
    ],
)
def test_convert_risk_weight_to_bucket(
    risk_weight: float, expected_bucket: RiskWeight
) -> None:
    ModuleFactory().create_evidence_handler_worker_obj()

    assert convert_float_to_risk_weight(risk_weight) == expected_bucket


@pytest.mark.parametrize(
    "accumulated_threat_level, expected_bucket",
    [
        (0.0, RiskWeight.HIGH),
        (RiskWeight.HIGH.maximum_atl / 2, RiskWeight.HIGH),
        (RiskWeight.MEDIUM.minimum_atl, RiskWeight.MEDIUM),
        (
            (RiskWeight.MEDIUM.minimum_atl + RiskWeight.MEDIUM.maximum_atl)
            / 2,
            RiskWeight.MEDIUM,
        ),
        (RiskWeight.LOW.minimum_atl, RiskWeight.LOW),
        (RiskWeight.LOW.minimum_atl + 1.0, RiskWeight.LOW),
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


@pytest.mark.parametrize(
    "risk_weight_bucket",
    [RiskWeight.HIGH, RiskWeight.MEDIUM, RiskWeight.LOW],
)
def test_each_risk_weight_bucket_contains_alertable_atl(
    risk_weight_bucket: RiskWeight,
) -> None:
    ModuleFactory().create_evidence_handler_worker_obj()

    assert (
        risk_weight_bucket.minimum_atl
        <= risk_weight_bucket.alertable_atl_boundary
        < risk_weight_bucket.maximum_atl
    )
    assert (
        pytest.approx(
            risk_weight_bucket.alertable_atl_boundary
            * risk_weight_bucket.risk_weight
        )
        == RATL_THRESHOLD
    )
