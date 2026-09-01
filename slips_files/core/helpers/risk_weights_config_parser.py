# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from dataclasses import dataclass

from slips_files.common.parsers.config_parser import ConfigParser


@dataclass(frozen=True)
class RiskWeightsConfig:
    low_risk_weight: float
    medium_risk_weight: float
    high_risk_weight: float
    ratl_threshold: float


def _read_configured_risk_weight(
    risk_weight: float | None, config_name: str
) -> float:
    """
    Read a configured risk weight from slips.yaml.

    Parameters:
        risk_weight: Parsed risk weight value.
        config_name: Detection configuration key to read.

    Return value:
        Configured risk weight as a float.
    """
    if risk_weight is None:
        raise ValueError(f"Missing detection.{config_name} in slips.yaml.")

    if risk_weight <= 0:
        raise ValueError(
            f"detection.{config_name} must be greater than 0 in slips.yaml."
        )

    return risk_weight


def _read_ratl_threshold(config_parser: ConfigParser) -> float:
    """
    Read the live RATL alert threshold from slips.yaml.

    Parameters:
        config_parser: Configuration parser instance.

    Return value:
        Configured RATL threshold as a float.
    """
    ratl_threshold = config_parser.risk_accumulated_threat_level()
    if ratl_threshold <= 0:
        raise ValueError(
            "detection.risk_accumulated_threat_level must be greater than 0 "
            "in slips.yaml."
        )

    return ratl_threshold


def _validate_risk_weights_config(
    config: RiskWeightsConfig,
) -> RiskWeightsConfig:
    """
    Validate the configured risk weights and RATL threshold.

    Parameters:
        config: Parsed risk-weight configuration.

    Return value:
        The validated configuration.
    """
    if not (
        config.low_risk_weight
        < config.medium_risk_weight
        < config.high_risk_weight
    ):
        raise ValueError(
            "Configured risk weights must satisfy "
            "low_risk_weight < medium_risk_weight < high_risk_weight."
        )

    if config.ratl_threshold <= 0:
        raise ValueError(
            "detection.risk_accumulated_threat_level must be greater than 0 "
            "in slips.yaml."
        )

    return config


def read_risk_weights_config() -> RiskWeightsConfig:
    """
    Read and validate the live risk-weight configuration from slips.yaml.

    Return value:
        Validated risk-weight configuration.
    """
    config_parser = ConfigParser()
    config = RiskWeightsConfig(
        low_risk_weight=_read_configured_risk_weight(
            config_parser.low_risk_weight(),
            "low_risk_weight",
        ),
        medium_risk_weight=_read_configured_risk_weight(
            config_parser.medium_risk_weight(),
            "medium_risk_weight",
        ),
        high_risk_weight=_read_configured_risk_weight(
            config_parser.high_risk_weight(),
            "high_risk_weight",
        ),
        ratl_threshold=_read_ratl_threshold(config_parser),
    )
    return _validate_risk_weights_config(config)
