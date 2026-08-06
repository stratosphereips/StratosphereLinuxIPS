# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import pytest

from slips_files.core.helpers.risk_weights_config_parser import (
    RiskWeightsConfig,
    _validate_risk_weights_config,
    read_risk_weights_config,
)
from tests.module_factory import ModuleFactory


def test_read_risk_weights_config() -> None:
    ModuleFactory().create_evidence_handler_worker_obj()

    config = read_risk_weights_config()

    assert config.low_risk_weight > 0
    assert (
        config.low_risk_weight
        < config.medium_risk_weight
        < config.high_risk_weight
    )
    assert config.ratl_threshold > 0


@pytest.mark.parametrize(
    "config",
    [
        RiskWeightsConfig(1.0, 1.0, 1.72, 15.0),
        RiskWeightsConfig(1.0, 0.5, 1.72, 15.0),
        RiskWeightsConfig(0.32, 1.0, 1.0, 15.0),
    ],
)
def test_validate_risk_weights_config_rejects_invalid_weight_order(
    config: RiskWeightsConfig,
) -> None:
    ModuleFactory().create_evidence_handler_worker_obj()

    with pytest.raises(ValueError):
        _validate_risk_weights_config(config)


def test_validate_risk_weights_config_rejects_non_positive_ratl_threshold() -> (
    None
):
    ModuleFactory().create_evidence_handler_worker_obj()

    config = RiskWeightsConfig(0.32, 1.0, 1.72, 0.0)

    with pytest.raises(ValueError):
        _validate_risk_weights_config(config)
