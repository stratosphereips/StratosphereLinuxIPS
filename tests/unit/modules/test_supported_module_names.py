# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit tests for modules/supported_module_names.py."""

import pytest

from modules.supported_module_names import (
    Modules,
    SUPPORTED_MODULE_NAME_BY_FILE,
)
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "member_name, expected_value",
    [
        ("ALERT_SUMMARY", "alert_summary"),
        ("ARP_POISONER", "arp_poisoner"),
        ("BLOCKING", "blocking"),
        ("EVIDENCE_HANDLER", "evidence_handler"),
        ("EXPORTING_ALERTS", "exporting_alerts"),
        ("INPUT", "input"),
        ("LLM_PROXY", "llm_proxy"),
        ("ML_LINEAR_MODEL", "ml_linear_model"),
        ("ML_ONLINE_MODEL", "ml_online_model"),
        ("PROFILER", "profiler"),
        ("REGEX_GENERATOR", "regex_generator"),
        ("T_CELL", "t_cell"),
    ],
)
def test_supported_module_name_members_match_runtime_names(
    member_name: str, expected_value: str
) -> None:
    """Test enum members expose the runtime module names."""
    module_factory = ModuleFactory()
    assert module_factory is not None

    assert Modules[member_name] == expected_value


def test_supported_module_name_uses_python_file_name_as_enum_member() -> None:
    """Test enum members can be resolved by the module file name name."""
    module_factory = ModuleFactory()
    assert module_factory is not None

    assert Modules.HTTP_ANALYZER == "http_analyzer"


def test_supported_module_name_mapping_uses_file_name_keys() -> None:
    """Test the shared mapping keeps module file names as dictionary keys."""
    module_factory = ModuleFactory()
    assert module_factory is not None

    assert (
        SUPPORTED_MODULE_NAME_BY_FILE["http_analyzer"] == Modules.HTTP_ANALYZER
    )
