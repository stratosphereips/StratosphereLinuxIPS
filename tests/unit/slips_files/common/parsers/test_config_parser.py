# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import Mock

import pytest

from slips_files.common.parsers.config_parser import ConfigParser
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    ("method_name", "config_name"),
    [
        ("low_risk_weight", "low_risk_weight"),
        ("medium_risk_weight", "medium_risk_weight"),
        ("high_risk_weight", "high_risk_weight"),
    ],
)
def test_risk_weight_methods_read_detection_values(
    method_name: str, config_name: str
) -> None:
    ModuleFactory().create_notify_obj()

    config_parser = object.__new__(ConfigParser)
    config_parser.read_configuration = Mock(return_value="1.5")

    assert getattr(config_parser, method_name)() == 1.5
    config_parser.read_configuration.assert_called_once_with(
        "detection", config_name, None
    )


@pytest.mark.parametrize("configured_value", [None, "invalid"])
def test_risk_weight_methods_return_none_for_invalid_values(
    configured_value: str | None,
) -> None:
    ModuleFactory().create_notify_obj()

    config_parser = object.__new__(ConfigParser)
    config_parser.read_configuration = Mock(return_value=configured_value)

    assert config_parser.low_risk_weight() is None
