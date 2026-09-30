# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import Mock, patch

import pytest

from managers.process_manager.web_interface_shutdown_mixin import (
    WebInterfaceShutdownMixin,
)
from modules.supported_module_names import Modules
from tests.module_factory import ModuleFactory


def test_process_manager_includes_web_interface_shutdown_mixin() -> None:
    process_manager = ModuleFactory().create_process_manager_obj()

    assert isinstance(process_manager, WebInterfaceShutdownMixin)


def test_wait_defers_web_stopped_message_while_server_is_running() -> None:
    """Do not report the launcher exit as an HTTP server shutdown."""
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.main.args.webinterface = True
    process_manager.main.conf.web_interface_port = 55000
    process_manager.web_interface_shutdown = False
    web_launcher = Mock()
    web_launcher.name = Modules.WEB_INTERFACE.value
    web_launcher.is_alive.return_value = False

    with (
        patch(
            "managers.process_manager.web_interface_shutdown_mixin."
            "WebInterface.is_verified_server_running",
            return_value=True,
        ),
        patch.object(process_manager, "print_stopped_module") as print_stopped,
    ):
        alive_processes = process_manager.wait_for_processes_to_finish(
            [web_launcher]
        )

    assert alive_processes == []
    assert process_manager.deferred_stopped_modules == {
        Modules.WEB_INTERFACE.value
    }
    print_stopped.assert_not_called()


def test_kill_skips_web_launcher_with_deferred_status() -> None:
    """Do not revisit the launcher while its stopped status is deferred."""
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.main.args.webinterface = True
    process_manager.main.conf.web_interface_port = 55000
    process_manager.web_interface_shutdown = False
    web_launcher = Mock(pid=1234)
    process_manager.children = [web_launcher]
    process_manager.deferred_stopped_modules = {Modules.WEB_INTERFACE.value}
    process_manager.main.db.get_name_of_module_at.return_value = (
        Modules.WEB_INTERFACE.value
    )

    with (
        patch.object(process_manager, "kill_process_tree") as kill_process,
        patch.object(process_manager, "print_stopped_module") as print_stopped,
    ):
        process_manager.kill_all_children()

    kill_process.assert_not_called()
    print_stopped.assert_not_called()


@pytest.mark.parametrize(
    "response, expected_stop",
    [
        ("y\n", True),
        ("yes\n", True),
        ("n\n", False),
        ("\n", False),
    ],
)
def test_ask_user_to_stop_web_interface(
    response: str, expected_stop: bool
) -> None:
    """
    Test the completed-analysis web interface prompt.

    Parameters:
        response: Console response to the prompt.
        expected_stop: Whether the response requests server shutdown.
    """
    process_manager = ModuleFactory().create_process_manager_obj()
    stdin = Mock()
    stdin.isatty.return_value = True
    stdin.readline.return_value = response
    process_manager.shutdown_signal_received = False

    with (
        patch(
            "managers.process_manager.web_interface_shutdown_mixin.sys.stdin",
            stdin,
        ),
        patch(
            "managers.process_manager.web_interface_shutdown_mixin.select.select",
            return_value=([stdin], [], []),
        ),
    ):
        result = process_manager._ask_user_to_stop_web_interface()

    assert result is expected_stop


def test_stop_web_interface_reports_status_after_server_stops() -> None:
    """Mark the web interface stopped after terminating its HTTP server."""
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.children = [Mock()]
    process_manager.web_interface_shutdown = False

    with patch(
        "managers.process_manager.web_interface_shutdown_mixin."
        "WebInterface.stop_verified_server",
        return_value=True,
    ) as stop_server:
        process_manager._stop_web_interface(55000)

    stop_server.assert_called_once_with(55000)
    assert process_manager.web_interface_shutdown is True
    assert process_manager.stopped_modules == [Modules.WEB_INTERFACE.value]


def test_forced_shutdown_stops_web_interface_without_prompt() -> None:
    """Test signal-driven shutdown immediately stops the verified server."""
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.main.args.webinterface = True
    process_manager.main.conf.web_interface_port = 55000
    process_manager.web_interface_shutdown = False
    process_manager.force_shutdown_requested = True

    with (
        patch(
            "managers.process_manager.web_interface_shutdown_mixin."
            "WebInterface.is_verified_server_running",
            return_value=True,
        ),
        patch(
            "managers.process_manager.web_interface_shutdown_mixin.WebInterface.stop_verified_server",
            return_value=True,
        ) as stop_server,
        patch.object(
            process_manager, "_ask_user_to_stop_web_interface"
        ) as prompt,
    ):
        process_manager._handle_web_interface_after_analysis(False)

    prompt.assert_not_called()
    stop_server.assert_called_once_with(55000)
    assert process_manager.web_interface_shutdown is True


def test_first_ctrl_c_prompts_before_stopping_web_interface() -> None:
    """Keep the web interface available after the first Ctrl-C."""
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.main.args.webinterface = True
    process_manager.main.conf.web_interface_port = 55000
    process_manager.shutdown_signal_received = True
    process_manager.keyboard_interrupt_received = True
    process_manager.web_interface_shutdown = False

    with (
        patch(
            "managers.process_manager.web_interface_shutdown_mixin."
            "WebInterface.is_verified_server_running",
            return_value=True,
        ),
        patch(
            "managers.process_manager.web_interface_shutdown_mixin.WebInterface.stop_verified_server",
            return_value=True,
        ) as stop_server,
        patch.object(
            process_manager,
            "_ask_user_to_stop_web_interface",
            return_value=False,
        ) as prompt,
        patch(
            "managers.process_manager.web_interface_shutdown_mixin.time.sleep",
            side_effect=KeyboardInterrupt,
        ) as mock_sleep,
    ):
        process_manager._handle_web_interface_after_analysis(False)

    prompt.assert_called_once_with()
    mock_sleep.assert_called_once_with(0.5)
    stop_server.assert_called_once_with(55000)
    assert process_manager.shutdown_signal_received is True
    assert process_manager.web_interface_shutdown is True


def test_normal_shutdown_keeps_web_until_ctrl_c() -> None:
    """Test a completed run stays available until the user interrupts it."""
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.main.args.webinterface = True
    process_manager.main.conf.web_interface_port = 55000
    process_manager.shutdown_signal_received = False
    process_manager.web_interface_shutdown = False

    with (
        patch(
            "managers.process_manager.web_interface_shutdown_mixin."
            "WebInterface.is_verified_server_running",
            return_value=True,
        ),
        patch(
            "managers.process_manager.web_interface_shutdown_mixin.WebInterface.stop_verified_server",
            return_value=True,
        ) as stop_server,
        patch.object(
            process_manager,
            "_ask_user_to_stop_web_interface",
            return_value=False,
        ) as prompt,
        patch(
            "managers.process_manager.web_interface_shutdown_mixin.time.sleep",
            side_effect=KeyboardInterrupt,
        ),
    ):
        process_manager._handle_web_interface_after_analysis(True)

    prompt.assert_called_once_with()
    stop_server.assert_called_once_with(55000)
    assert process_manager.shutdown_signal_received is True
    assert process_manager.web_interface_shutdown is True


def test_shutdown_reports_interface_web_address() -> None:
    """Keep the externally reachable interface URL visible during shutdown."""
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.main.args.webinterface = True
    process_manager.main.args.interface = "eno1"
    process_manager.main.conf.web_interface_port = 55000
    process_manager.main.conf.web_interface_bind = "interface"
    process_manager.main.db.get_host_ip.return_value = "192.0.2.25"
    process_manager.shutdown_signal_received = False
    process_manager.web_interface_shutdown = False

    with (
        patch(
            "managers.process_manager.web_interface_shutdown_mixin."
            "WebInterface.is_verified_server_running",
            return_value=True,
        ),
        patch(
            "managers.process_manager.web_interface_shutdown_mixin."
            "WebInterface.stop_verified_server",
            return_value=True,
        ),
        patch.object(
            process_manager,
            "_ask_user_to_stop_web_interface",
            return_value=False,
        ),
        patch(
            "managers.process_manager.web_interface_shutdown_mixin.time.sleep",
            side_effect=KeyboardInterrupt,
        ),
    ):
        process_manager._handle_web_interface_after_analysis(True)

    messages = [
        str(call.args[0]) for call in process_manager.main.print.call_args_list
    ]
    assert any("http://192.0.2.25:55000/" in message for message in messages)
