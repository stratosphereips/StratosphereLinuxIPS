# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import ast
from unittest.mock import Mock, patch

import pytest

from managers.process_manager.reporting_mixin import ReportingMixin
from modules.supported_module_names import Modules
from tests.module_factory import ModuleFactory


def test_process_manager_includes_reporting_mixin() -> None:
    process_manager = ModuleFactory().create_process_manager_obj()

    assert isinstance(process_manager, ReportingMixin)


def test_print_disabled_modules():
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.user_disabled_modules = {Modules.TEMPLATE, Modules.FIDES}
    process_manager.slips_disabled_modules = set()
    with patch.object(process_manager.main, "print") as mock_print:
        process_manager.print_disabled_modules()
        printed_modules = ast.literal_eval(
            mock_print.call_args.args[0].removeprefix("Disabled Modules: ")
        )

        assert set(printed_modules) == {"template", "fides"}
        mock_print.assert_called_once()


@pytest.mark.parametrize(
    "mode, expected_print_function",
    [  # Test case 1: Daemonized mode
        ("daemonized", "main.daemon.print"),
        # Test case 2: Normal mode
        ("interactive", "main.print"),
    ],
)
def test_get_print_function(mode, expected_print_function):
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.main.mode = mode

    process_manager.main.daemon = Mock()
    process_manager.main.daemon.print = Mock()
    process_manager.main.print = Mock()

    print_function = process_manager.get_print_function()

    expected_function = eval(f"process_manager.{expected_print_function}")

    assert print_function == expected_function

    print_function()
    expected_function.assert_called_once()


def test_print_stopped_module():
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.children = [Mock(), Mock()]
    process_manager.stopped_modules = []

    with patch(
        "managers.process_manager.reporting_mixin.green",
        side_effect=["green_module_name", "green_count"],
    ), patch.object(process_manager.main, "print") as mock_print:
        process_manager.print_stopped_module("TestModule")

        assert "TestModule" in process_manager.stopped_modules
        mock_print.assert_called_once()

        printed_str = mock_print.call_args[0][0]
        assert "green_module_name" in printed_str
        assert "Stopped" in printed_str
        assert "green_count left" in printed_str

        process_manager.print_stopped_module("testmodule")

        assert mock_print.call_count == 1


def test_print_started_module():
    process_manager = ModuleFactory().create_process_manager_obj()
    with patch(
        "managers.process_manager.reporting_mixin.green",
        return_value="green_module_name",
    ), patch.object(process_manager.main, "print") as mock_print:
        process_manager.print_started_module(
            Modules.CESNET, 12345, "Test description"
        )

        mock_print.assert_called_once_with(
            "\t\tStarting green_module_name module "
            "(Test description) [PID green_module_name]",
            1,
            0,
        )
