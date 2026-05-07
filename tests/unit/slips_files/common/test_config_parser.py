# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit tests for selected ConfigParser helpers."""

import pytest

from slips_files.common.parsers.config_parser import ConfigParser
from tests.module_factory import ModuleFactory


def _parser_with_config(config):
    """
    Create a ConfigParser instance without reading files.

    Parameters:
        config: Configuration dictionary.

    Returns:
        ConfigParser instance with injected config data.
    """
    parser = ConfigParser.__new__(ConfigParser)
    parser.config = config
    return parser


@pytest.mark.parametrize(
    "raw_value, expected",
    [
        (True, True),
        (False, False),
        ("true", True),
        ("yes", True),
        ("1", True),
        ("false", False),
        ("no", False),
        ("0", False),
    ],
)
def test_graph_structure_enabled_parses_boolean_values(raw_value, expected):
    """graph_structure.enabled should accept boolean-like values."""
    module_factory = ModuleFactory()
    assert module_factory is not None

    parser = _parser_with_config({"graph_structure": {"enabled": raw_value}})

    assert parser.graph_structure_enabled() is expected


def test_graph_structure_enabled_defaults_to_false_when_missing():
    """graph_structure.enabled should be disabled when the section is absent."""
    module_factory = ModuleFactory()
    assert module_factory is not None

    parser = _parser_with_config({})

    assert parser.graph_structure_enabled() is False
