# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import pytest

from slips_files.core.structures.risk_weights import (
    HIGH_SENSITIVITY_WEIGHT,
    LOW_SENSITIVITY_WEIGHT,
    MEDIUM_SENSITIVITY_WEIGHT,
    RATL_THRESHOLD,
    Sensitivity,
    convert_sensitivity_weight_to_risk_weight,
    get_sensitivity_for_accumulated_threat_level,
)
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "sensitivity_weight, expected_bucket",
    [
        (0.0, Sensitivity.LOW),
        (LOW_SENSITIVITY_WEIGHT, Sensitivity.LOW),
        (MEDIUM_SENSITIVITY_WEIGHT, Sensitivity.MEDIUM),
        (HIGH_SENSITIVITY_WEIGHT, Sensitivity.HIGH),
    ],
)
def test_convert_sensitivity_weight_to_risk_weight(
    sensitivity_weight: float, expected_bucket: Sensitivity
) -> None:
    ModuleFactory().create_evidence_handler_worker_obj()

    assert (
        convert_sensitivity_weight_to_risk_weight(sensitivity_weight)
        == expected_bucket
    )


@pytest.mark.parametrize(
    "accumulated_threat_level, expected_bucket",
    [
        (0.0, Sensitivity.HIGH),
        (Sensitivity.HIGH.maximum_atl / 2, Sensitivity.HIGH),
        (Sensitivity.MEDIUM.minimum_atl, Sensitivity.MEDIUM),
        (
            (Sensitivity.MEDIUM.minimum_atl + Sensitivity.MEDIUM.maximum_atl)
            / 2,
            Sensitivity.MEDIUM,
        ),
        (Sensitivity.LOW.minimum_atl, Sensitivity.LOW),
        (Sensitivity.LOW.minimum_atl + 1.0, Sensitivity.LOW),
    ],
)
def test_get_sensitivity_for_accumulated_threat_level(
    accumulated_threat_level: float, expected_bucket: Sensitivity
) -> None:
    ModuleFactory().create_evidence_handler_worker_obj()

    assert (
        get_sensitivity_for_accumulated_threat_level(accumulated_threat_level)
        == expected_bucket
    )


@pytest.mark.parametrize(
    "sensitivity",
    [Sensitivity.HIGH, Sensitivity.MEDIUM, Sensitivity.LOW],
)
def test_each_risk_weight_bucket_contains_alertable_atl(
    sensitivity: Sensitivity,
) -> None:
    ModuleFactory().create_evidence_handler_worker_obj()

    assert (
        sensitivity.minimum_atl
        <= sensitivity.alertable_atl_boundary
        < sensitivity.maximum_atl
    )
    assert (
        pytest.approx(
            sensitivity.alertable_atl_boundary * sensitivity.sensitivity_weight
        )
        == RATL_THRESHOLD
    )
