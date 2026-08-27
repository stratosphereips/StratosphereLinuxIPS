# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
import signal
from unittest.mock import Mock, call, patch

import pytest

from managers.process_manager.shutdown_mixin import ShutdownMixin
from modules.supported_module_names import Modules
from slips_files.common.input_type import InputType
from slips_files.common.slips_utils import utils
from tests.module_factory import ModuleFactory


def test_process_manager_includes_shutdown_mixin() -> None:
    process_manager = ModuleFactory().create_process_manager_obj()

    assert isinstance(process_manager, ShutdownMixin)


def test_get_hitlist_in_order_uses_supported_module_name_values() -> None:
    """Test hitlist lookups use the shared supported module names enum."""
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.main.args.blocking = True
    process_manager.main.db.get_disabled_modules.return_value = []
    process_manager.main.db.get_pid_of.side_effect = lambda module_name: {
        "evidence_handler": 10,
        Modules.BLOCKING: 20,
        Modules.ARP_POISONER: 30,
        Modules.EXPORTING_ALERTS: 40,
    }.get(module_name)
    process_manager.children = [
        Mock(pid=10),
        Mock(pid=20),
        Mock(pid=30),
        Mock(pid=40),
        Mock(pid=50),
    ]

    to_kill_first, to_kill_last = process_manager.get_hitlist_in_order()

    assert [process.pid for process in to_kill_first] == [50]
    assert [process.pid for process in to_kill_last] == [10, 20, 30, 40]


@pytest.mark.parametrize(
    "pending_module_names, expected_print_calls",
    [
        # Test case 1: No pending modules, no additional print calls
        ([], 1),
        # Test case 2: Pending modules without feeds_update_manager, one additional print call
        (["Module1", "Module2"], 1),
        # Test case 3: Pending update manager prints the extra warning
        ([Modules.FEEDS_UPDATE_MANAGER], 2),
    ],
)
def test_warn_about_pending_modules(
    pending_module_names, expected_print_calls
):
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.warning_printed_once = False
    pending_modules = []
    for module_name in pending_module_names:
        pending_module = Mock()
        pending_module.name = module_name
        pending_modules.append(pending_module)

    with patch.object(process_manager.main, "print") as mock_print:
        process_manager.warn_about_pending_modules(pending_modules)

        assert mock_print.call_count == expected_print_calls
        expected_result = True
        assert process_manager.warning_printed_once == expected_result

    with patch.object(process_manager.main, "print") as mock_print:
        process_manager.warn_about_pending_modules(pending_modules)

        mock_print.assert_not_called()


@pytest.mark.parametrize(
    "blocking_enabled, exporting_alerts_disabled, "
    "expected_kill_first, expected_kill_last",
    [  # Testcase1: blocking enabled, exporting_alerts enabled
        (True, False, [1, 2, 6, 7], [3, 4, 5]),
        # Testcase2: blocking disabled, exporting_alerts enabled
        (False, False, [1, 2, 4, 6, 7], [3, 5]),
        # Testcase3: blocking enabled, exporting_alerts disabled
        (True, True, [1, 2, 5, 6, 7], [3, 4]),
        # Testcase4: blocking disabled, exporting_alerts disabled
        (False, True, [1, 2, 4, 5, 6, 7], [3]),
        # Testcase5: All enabled, some PIDs are None
        (True, False, [1, 2, 6, 7], [3, 4, 5]),
    ],
)
def test_get_hitlist_in_order(
    blocking_enabled,
    exporting_alerts_disabled,
    expected_kill_first,
    expected_kill_last,
):
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.children = [
        Mock(pid=1, name="Process1"),
        Mock(pid=2, name="Process2"),
        Mock(pid=3, name="evidence_handler"),
        Mock(pid=4, name="blocking"),
        Mock(pid=5, name="exporting_alerts"),
        Mock(pid=6, name="alert_summary"),
        Mock(pid=7, name="LLM"),
    ]

    process_manager.main.db.get_pid_of = lambda x: {
        "evidence_handler": 3,
        "blocking": 4,
        "exporting_alerts": 5,
        "alert_summary": 6,
        "LLM": 7,
    }.get(x)
    process_manager.main.args.blocking = blocking_enabled
    process_manager.main.db.get_disabled_modules = lambda: (
        ["exporting_alerts"] if exporting_alerts_disabled else []
    )

    to_kill_first, to_kill_last = process_manager.get_hitlist_in_order()

    assert [p.pid for p in to_kill_first] == expected_kill_first
    assert [p.pid for p in to_kill_last] == expected_kill_last


@pytest.mark.parametrize(
    "alive_statuses, expected_alive_count",
    [  # Testcase1: two processes still alive
        ([True, True, False], 2),
        # Testcase2: all processes finished
        ([False, False, False], 0),
        # Tetscase3: first and third processes alive
        ([True, False, True], 2),
    ],
)
def test_wait_for_processes_to_finish(alive_statuses, expected_alive_count):
    process_manager = ModuleFactory().create_process_manager_obj()

    # create mock process objects based on the `alive_statuses`
    mock_processes = [
        Mock(name=f"Process{i}") for i in range(len(alive_statuses))
    ]

    # set up the is_alive of each process
    for i, process in enumerate(mock_processes):
        process.is_alive.return_value = alive_statuses[i]

    with patch.object(
        process_manager, "print_stopped_module"
    ) as mock_print_stopped:
        alive_processes = process_manager.wait_for_processes_to_finish(
            mock_processes
        )

    # assertions
    # verify the number of alive processes matches the expected count
    assert len(alive_processes) == expected_alive_count, (
        f"Expected {expected_alive_count} alive processes, but got "
        f"{len(alive_processes)}"
    )

    # verify the `print_stopped_module` method is called for all stopped processes
    expected_stopped_count = len(alive_statuses) - expected_alive_count
    assert mock_print_stopped.call_count == expected_stopped_count, (
        f"Expected `print_stopped_module` to be called "
        f"{expected_stopped_count} times, "
        f"but it was called {mock_print_stopped.call_count} times"
    )


@pytest.mark.parametrize(
    "end_date_str, start_time_str, expected_analysis_time",
    [
        # Test case 1: Analysis time is 10 minutes
        (
            1680343800,
            1680343200,
            10.0,
        ),  # "2023-04-01 10:10:00", "2023-04-01 10:00:00"
        # Test case 2: Analysis time is 1 hour
        (
            1680346800,
            1680343200,
            60.0,
        ),  # "2023-04-01 11:00:00", "2023-04-01 10:00:00"
        # Test case 3: Analysis time is less than a minute
        (
            1680343230,
            1680343200,
            0.5,
        ),  # "2023-04-01 10:00:30", "2023-04-01 10:00:00"
    ],
)
def test_get_analysis_time(
    end_date_str, start_time_str, expected_analysis_time
):
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.main.db.get_slips_start_time.return_value = start_time_str

    with patch.object(utils, "convert_ts_format", return_value=end_date_str):
        analysis_time = process_manager.get_analysis_time()

    assert analysis_time == (expected_analysis_time, end_date_str)


@pytest.mark.parametrize(
    "message, msg_recvd_in_control_channel, expected_result",
    [
        # Test case 1: Message is None
        (None, True, False),
        # Test case 2: Message doesn't contain "stop_slips"
        ({"data": "some_other_message"}, True, False),
        # Test case 3: Wrapped plain-text messages should be decoded first
        (
            {
                "data": json.dumps(
                    {"text": "stop_slips", "version": "test-version"}
                )
            },
            True,
            True,
        ),
        # Test case 3: Message contains
        # "stop_slips" but not intended for control channel
        ({"data": "stop_slips"}, False, False),
        # Test case 4: Message contains
        # "stop_slips" and intended for control channel
        ({"data": "stop_slips"}, True, True),
    ],
)
def test_is_stop_msg_received(
    message, msg_recvd_in_control_channel, expected_result
):
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.main.c1.get_message.return_value = message

    with patch(
        "slips_files.common.slips_utils.utils.is_msg_intended_for"
    ) as mock_is_intended_for:
        mock_is_intended_for.return_value = msg_recvd_in_control_channel
        assert process_manager.is_stop_msg_received() == expected_result


@pytest.mark.parametrize(
    "mock_return_value, expected_result",
    [
        (None, False),
        (Mock(), True),
    ],
)
def test_is_debugger_active(
    mock_return_value: object, expected_result: bool
) -> None:
    process_manager = ModuleFactory().create_process_manager_obj()

    with patch("sys.gettrace", return_value=mock_return_value):
        assert process_manager.is_debugger_active() is expected_result


@pytest.mark.parametrize(
    "debugger_active, running_non_stop, expected",
    [
        (True, False, True),
        (False, True, True),
        (False, False, False),
    ],
)
def test_should_run_non_stop(
    debugger_active: bool, running_non_stop: bool, expected: bool
) -> None:
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.is_debugger_active = Mock(return_value=debugger_active)
    process_manager.main.db.is_running_non_stop.return_value = running_non_stop

    assert process_manager.should_run_non_stop() is expected


@pytest.mark.parametrize(
    "input_acquired, profiler_acquired, expected_result",
    [  # Test case 1: Both semaphores are not acquired
        (False, False, False),
        # Test case 2: Only input semaphore is acquired
        (True, False, False),
        # Testcase 3: Only profiler acquired
        (False, True, False),
        # Testcase 4: Both semaphores are acquired
        (True, True, True),
    ],
)
def test_is_done_receiving_new_flows(
    input_acquired, profiler_acquired, expected_result
):
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.can_acquire_semaphore = Mock(
        side_effect=[input_acquired, profiler_acquired]
    )
    assert process_manager.is_done_receiving_new_flows() == expected_result


def test_stop_llm_stack_if_llm_module_stopped_kills_dependents() -> None:
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.module_dependencies = {
        Modules.LLM_PROXY: (),
        Modules.REGEX_GENERATOR: (Modules.LLM_PROXY,),
        Modules.ALERT_SUMMARY: (Modules.LLM_PROXY,),
    }
    process_manager.main.db.get_pid_of.side_effect = lambda module_name: {
        Modules.LLM_PROXY: 100,
        Modules.REGEX_GENERATOR: 101,
        Modules.ALERT_SUMMARY: 102,
    }.get(module_name)

    with (
        patch(
            "managers.process_manager.shutdown_mixin.os.kill",
            side_effect=ProcessLookupError,
        ),
        patch.object(
            process_manager, "kill_process_tree"
        ) as mock_kill_process_tree,
        patch.object(process_manager.main, "print") as mock_print,
    ):
        process_manager._stop_llm_stack_if_llm_module_stopped()

    assert mock_kill_process_tree.call_args_list == [call(101), call(102)]
    assert process_manager.stopped_modules == [
        str(Modules.REGEX_GENERATOR),
        str(Modules.ALERT_SUMMARY),
        str(Modules.LLM_PROXY),
    ]
    mock_print.assert_called_once_with(
        "Stopping modules because llm_proxy stopped: "
        "['Modules.REGEX_GENERATOR', 'Modules.ALERT_SUMMARY']"
    )


@pytest.mark.parametrize(
    "llm_enabled, os_kill_side_effect, stopped_modules",
    [
        (False, None, []),
        (True, None, []),
        (True, ProcessLookupError, [str(Modules.REGEX_GENERATOR)]),
    ],
)
def test_stop_llm_stack_if_llm_module_stopped_skips_unneeded_shutdown(
    llm_enabled: bool,
    os_kill_side_effect: type[BaseException] | None,
    stopped_modules: list[str],
) -> None:
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.module_dependencies = {
        Modules.LLM_PROXY: (),
        Modules.REGEX_GENERATOR: (Modules.LLM_PROXY,),
    }
    process_manager.main.conf.llm_enabled.return_value = llm_enabled
    process_manager.main.db.get_pid_of.side_effect = lambda module_name: {
        Modules.LLM_PROXY: 100,
        Modules.REGEX_GENERATOR: 101,
    }.get(module_name)
    process_manager.stopped_modules = stopped_modules

    with (
        patch(
            "managers.process_manager.shutdown_mixin.os.kill",
            side_effect=os_kill_side_effect,
        ),
        patch.object(
            process_manager, "kill_process_tree"
        ) as mock_kill_process_tree,
        patch.object(process_manager.main, "print") as mock_print,
    ):
        process_manager._stop_llm_stack_if_llm_module_stopped()

    if llm_enabled and os_kill_side_effect is ProcessLookupError:
        mock_kill_process_tree.assert_called_once_with(101)
        mock_print.assert_called_once_with(
            "Stopping modules because llm_proxy stopped: ['Modules.REGEX_GENERATOR']"
        )
    else:
        mock_kill_process_tree.assert_not_called()
        mock_print.assert_not_called()


@pytest.mark.parametrize(
    "live_update, stop_received, done_receiving, expected_result, expected_cause",
    [
        (True, False, False, True, "live_update"),
        (False, True, False, True, "control"),
        (False, False, True, True, "natural"),
        (False, False, False, False, ""),
    ],
)
def test_should_stop_slips(
    live_update,
    stop_received,
    done_receiving,
    expected_result,
    expected_cause,
):
    """
    Test whether Slips should stop for live updates, stop messages, or done input.

    Parameters:
    live_update: Whether a live update is in progress.
    stop_received: Whether a stop message was received.
    done_receiving: Whether input and profiler finished processing.
    expected_result: Expected stop decision.
    expected_cause: Expected recorded shutdown cause.

    Return:
    None.
    """
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.is_slips_live_updating_event.is_set = Mock(
        return_value=live_update
    )
    process_manager.is_stop_msg_received = Mock(return_value=stop_received)
    process_manager.is_done_receiving_new_flows = Mock(
        return_value=done_receiving
    )
    process_manager._did_a_core_module_fail = Mock(return_value=False)
    process_manager.all_children_started = True

    assert process_manager.should_stop_slips() == expected_result
    assert process_manager.shutdown_cause == expected_cause


@pytest.mark.parametrize(
    "input_exitcode, profiler_exitcode, evidence_exitcode, expected_result",
    [
        (None, None, None, False),
        (0, None, None, False),
        (None, 1, None, True),
        (0, 1, None, False),
        (None, None, 0, True),
    ],
)
def test_did_a_core_module_fail_for_file_input(
    input_exitcode: int | None,
    profiler_exitcode: int | None,
    evidence_exitcode: int | None,
    expected_result: bool,
) -> None:
    """
    Test core module failure detection for finite file inputs.

    Parameters:
    input_exitcode: Input process exit code.
    profiler_exitcode: Profiler process exit code.
    evidence_exitcode: Evidence process exit code.
    expected_result: Expected failure detection result.

    Return:
    None.
    """
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.input_process = Mock()
    process_manager.profiler_process = Mock()
    process_manager.evidence_process = Mock()
    process_manager.input_process.exitcode = input_exitcode
    process_manager.profiler_process.exitcode = profiler_exitcode
    process_manager.evidence_process.exitcode = evidence_exitcode
    process_manager.main.db.is_running_non_stop.return_value = False

    assert process_manager._did_a_core_module_fail() == expected_result


@pytest.mark.parametrize(
    "input_type",
    [
        InputType.INTERFACE,
        InputType.STDIN,
        InputType.CYST,
    ],
)
@pytest.mark.parametrize(
    "input_exitcode, profiler_exitcode, evidence_exitcode, expected_result",
    [
        (None, None, None, False),
        (0, None, None, True),
        (None, 1, None, True),
        (None, None, 0, True),
    ],
)
def test_did_a_core_module_fail_for_forever_growing_input(
    input_type: InputType,
    input_exitcode: int | None,
    profiler_exitcode: int | None,
    evidence_exitcode: int | None,
    expected_result: bool,
) -> None:
    """
    Test core module failure detection for forever-growing inputs.

    Parameters:
    input_exitcode: Input process exit code.
    profiler_exitcode: Profiler process exit code.
    evidence_exitcode: Evidence process exit code.
    expected_result: Expected failure detection result.

    Return:
    None.
    """
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.main.input_type = input_type
    process_manager.input_process = Mock()
    process_manager.profiler_process = Mock()
    process_manager.evidence_process = Mock()
    process_manager.input_process.exitcode = input_exitcode
    process_manager.profiler_process.exitcode = profiler_exitcode
    process_manager.evidence_process.exitcode = evidence_exitcode
    process_manager.main.db.is_running_non_stop.return_value = True

    assert process_manager._did_a_core_module_fail() == expected_result


def test_should_stop_slips_sets_core_module_failure() -> None:
    """
    Test should_stop_slips marks core module failures for shutdown handling.

    Return:
    None.
    """
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.is_slips_live_updating_event.is_set = Mock(
        return_value=False
    )
    process_manager._did_a_core_module_fail = Mock(return_value=True)
    process_manager.is_stop_msg_received = Mock()
    process_manager.is_done_receiving_new_flows = Mock()
    process_manager.all_children_started = True

    assert process_manager.should_stop_slips() is True
    assert process_manager.core_module_failure is True
    assert process_manager.shutdown_cause == "core_failure"
    process_manager.is_stop_msg_received.assert_not_called()
    process_manager.is_done_receiving_new_flows.assert_not_called()


def test_shutdown_gracefully_handles_core_module_failure() -> None:
    """
    Test shutdown avoids waiting for modules after a core module failure.

    Return:
    None.
    """
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.core_module_failure = True
    process_manager.main.args.stopdaemon = False
    process_manager.main.args.save = False
    process_manager.main.input_information = "test_input"
    process_manager.main.conf.wait_for_modules_to_finish.return_value = 1
    process_manager.main.conf.export_labeled_flows.return_value = False
    process_manager.main.db.get_flows_count.return_value = 42
    process_manager.main.db.check_tw_to_close = Mock()
    process_manager.main.db.close_all_dbs = Mock()
    process_manager.main.metadata_man = Mock()
    process_manager.main.profilers_manager = Mock()
    process_manager.main.store_zeek_dir_copy = Mock()
    process_manager.main.delete_zeek_files = Mock()
    process_manager.get_hitlist_in_order = Mock(return_value=([], []))
    process_manager.shutdown_interactive = Mock()
    process_manager.kill_all_children = Mock()
    process_manager.get_analysis_time = Mock(
        return_value=(1.23, "2026/05/21 12:00:00")
    )
    process_manager.is_slips_live_updating_event.is_set = Mock(
        return_value=False
    )

    with patch(
        "managers.process_manager.shutdown_mixin.multiprocessing.active_children",
        return_value=[],
    ):
        process_manager.shutdown_gracefully()

    process_manager.shutdown_interactive.assert_not_called()
    assert process_manager.kill_all_children.call_count == 2
    process_manager.main.print.assert_any_call(
        "[Process Manager] Slips didn't shutdown gracefully - Core module failure.\n",
        log_to_logfiles_only=True,
    )


def test_kill_daemon_children_excludes_thread_pids_from_logging_count():
    """Exclude stored thread PIDs from daemon-child shutdown log counts."""
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.main.db.get_pids.return_value = {
        "module_one": 123,
        "module_thread": 456,
        "module_two": 789,
    }

    with (
        patch.object(
            process_manager, "kill_process_tree"
        ) as mock_kill_process_tree,
        patch.object(
            process_manager, "print_stopped_module"
        ) as mock_print_stopped_module,
    ):
        process_manager.kill_daemon_children()

    assert mock_kill_process_tree.call_args_list == [call(123), call(789)]
    assert mock_print_stopped_module.call_args_list == [
        call("module_one", total_modules=2),
        call("module_two", total_modules=2),
    ]


def test_kill_process_tree_kills_descendants_before_parent():
    """Kill descendants before their parent can reparent them."""
    process_manager = ModuleFactory().create_process_manager_obj()
    parent_children = Mock()
    parent_children.read.return_value = "456\n"
    child_children = Mock()
    child_children.read.return_value = ""

    with (
        patch(
            "managers.process_manager.shutdown_mixin.os.popen",
            side_effect=[parent_children, child_children],
        ),
        patch("managers.process_manager.shutdown_mixin.os.kill") as mock_kill,
    ):
        process_manager.kill_process_tree(123)

    assert mock_kill.call_args_list == [
        call(456, signal.SIGKILL),
        call(123, signal.SIGKILL),
    ]


def test_shutdown_interactive_signals_evidence_handler_after_other_modules_stop():
    """Delay the evidence-handler shutdown signal until earlier modules stop."""
    process_manager = ModuleFactory().create_process_manager_obj()
    first_process = Mock()
    last_process = Mock()

    with (
        patch.object(
            process_manager,
            "wait_for_processes_to_finish",
            side_effect=[[], []],
        ) as mock_wait,
        patch.object(
            process_manager.evidence_handler_termination_event, "set"
        ) as mock_set,
    ):
        result = process_manager.shutdown_interactive(
            [first_process], [last_process]
        )

    assert result == (None, None)
    assert mock_wait.call_args_list == [
        call([first_process]),
        call([last_process]),
    ]
    mock_set.assert_called_once_with()


def test_shutdown_interactive_does_not_signal_evidence_handler_while_modules_are_pending():
    """Keep the evidence handler running while earlier modules are pending."""
    process_manager = ModuleFactory().create_process_manager_obj()
    pending_process = Mock()
    last_process = Mock()

    with (
        patch.object(
            process_manager,
            "wait_for_processes_to_finish",
            return_value=[pending_process],
        ) as mock_wait,
        patch.object(
            process_manager, "warn_about_pending_modules"
        ) as mock_warn,
        patch.object(
            process_manager.evidence_handler_termination_event, "set"
        ) as mock_set,
    ):
        result = process_manager.shutdown_interactive(
            [pending_process], [last_process]
        )

    assert result == ([pending_process], [last_process])
    mock_wait.assert_called_once_with([pending_process])
    mock_warn.assert_called_once_with([pending_process, last_process])
    mock_set.assert_not_called()


@pytest.mark.parametrize(
    "response, expected_stop",
    [
        ("y\n", True),
        ("yes\n", True),
        ("n\n", False),
        ("\n", False),
    ],
)
def test_ask_to_stop_web_interface(response: str, expected_stop: bool) -> None:
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
    process_manager.main.shutdown_signal_received = False

    with (
        patch("managers.process_manager.shutdown_mixin.sys.stdin", stdin),
        patch(
            "managers.process_manager.shutdown_mixin.select.select",
            return_value=([stdin], [], []),
        ),
    ):
        result = process_manager._ask_to_stop_web_interface()

    assert result is expected_stop


def test_forced_shutdown_stops_web_interface_without_prompt() -> None:
    """Test signal-driven shutdown immediately stops the verified server."""
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.main.args.webinterface = True
    process_manager.main.conf.web_interface_port = 55000
    process_manager.main.web_interface_shutdown = False
    process_manager.main.force_shutdown_requested = True

    with (
        patch(
            "managers.process_manager.shutdown_mixin."
            "WebInterface.is_verified_server_running",
            return_value=True,
        ),
        patch(
            "managers.process_manager.shutdown_mixin.WebInterface.stop_verified_server",
            return_value=True,
        ) as stop_server,
        patch.object(process_manager, "_ask_to_stop_web_interface") as prompt,
    ):
        process_manager._handle_web_interface_after_analysis(False)

    prompt.assert_not_called()
    stop_server.assert_called_once_with(55000)
    assert process_manager.main.web_interface_shutdown is True


def test_first_ctrl_c_prompts_before_stopping_web_interface() -> None:
    """Keep the web interface available after the first Ctrl-C."""
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.main.args.webinterface = True
    process_manager.main.conf.web_interface_port = 55000
    process_manager.main.shutdown_signal_received = True
    process_manager.main.keyboard_interrupt_received = True
    process_manager.main.web_interface_shutdown = False

    with (
        patch(
            "managers.process_manager.shutdown_mixin."
            "WebInterface.is_verified_server_running",
            return_value=True,
        ),
        patch(
            "managers.process_manager.shutdown_mixin.WebInterface.stop_verified_server",
            return_value=True,
        ) as stop_server,
        patch.object(
            process_manager,
            "_ask_to_stop_web_interface",
            return_value=False,
        ) as prompt,
        patch(
            "managers.process_manager.shutdown_mixin.time.sleep",
            side_effect=KeyboardInterrupt,
        ) as mock_sleep,
    ):
        process_manager._handle_web_interface_after_analysis(False)

    prompt.assert_called_once_with()
    mock_sleep.assert_called_once_with(0.5)
    stop_server.assert_called_once_with(55000)
    assert process_manager.main.shutdown_signal_received is True
    assert process_manager.main.web_interface_shutdown is True


def test_natural_shutdown_keeps_web_until_ctrl_c() -> None:
    """Test a completed run stays available until the user interrupts it."""
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.main.args.webinterface = True
    process_manager.main.conf.web_interface_port = 55000
    process_manager.main.shutdown_signal_received = False
    process_manager.main.web_interface_shutdown = False

    with (
        patch(
            "managers.process_manager.shutdown_mixin."
            "WebInterface.is_verified_server_running",
            return_value=True,
        ),
        patch(
            "managers.process_manager.shutdown_mixin.WebInterface.stop_verified_server",
            return_value=True,
        ) as stop_server,
        patch.object(
            process_manager,
            "_ask_to_stop_web_interface",
            return_value=False,
        ) as prompt,
        patch(
            "managers.process_manager.shutdown_mixin.time.sleep",
            side_effect=KeyboardInterrupt,
        ),
    ):
        process_manager._handle_web_interface_after_analysis(True)

    prompt.assert_called_once_with()
    stop_server.assert_called_once_with(55000)
    assert process_manager.main.shutdown_signal_received is True
    assert process_manager.main.web_interface_shutdown is True
