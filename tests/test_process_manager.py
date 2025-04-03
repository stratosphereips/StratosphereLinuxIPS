# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import pytest
from unittest.mock import Mock, patch, MagicMock
from managers.process_manager import ProcessManager
from tests.module_factory import ModuleFactory
from slips_files.common.slips_utils import utils


@pytest.mark.parametrize(
    "input_type, input_information, cli_packet_filter, "
    "zeek_or_bro, zeek_dir, line_type",
    [
        # Test case 1: pcap input
        ("pcap", "test.pcap", "tcp port 80", "zeek", "/opt/zeek", "conn"),
        # Test case 2: zeek input
        ("zeek", "test.log", "", "bro", "/opt/bro", "dns"),
        # Test case 3: stdin input
        ("stdin", "-", "", "zeek", "/opt/zeek", "http"),
    ],
)
def test_start_input_process(
    input_type,
    input_information,
    cli_packet_filter,
    zeek_or_bro,
    zeek_dir,
    line_type,
):
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.main.input_type = input_type
    process_manager.main.input_information = input_information
    process_manager.main.args.pcapfilter = cli_packet_filter
    process_manager.main.zeek_bro = zeek_or_bro
    process_manager.main.zeek_dir = zeek_dir
    process_manager.main.line_type = line_type

    with patch("managers.process_manager.Input") as mock_input:
        mock_input_process = Mock()
        mock_input.return_value = mock_input_process
        mock_input_process.pid = 54321

        result = process_manager.start_input_process()

        assert result == mock_input_process
        mock_input.assert_called_once_with(
            process_manager.main.logger,
            process_manager.main.args.output,
            process_manager.main.redis_port,
            process_manager.termination_event,
            is_input_done=process_manager.is_input_done,
            profiler_queue=process_manager.profiler_queue,
            input_type=input_type,
            input_information=input_information,
            cli_packet_filter=cli_packet_filter,
            zeek_or_bro=zeek_or_bro,
            zeek_dir=zeek_dir,
            line_type=line_type,
            is_profiler_done_event=process_manager.is_profiler_done_event,
        )
        mock_input_process.start.assert_called_once()
        process_manager.main.print.assert_called_once()
        process_manager.main.db.store_pid.assert_called_once_with(
            "Input", 54321
        )


@pytest.mark.parametrize(
    "module_name, modules_to_ignore, expected",
    [
        # Test case 1: Module name not in ignore list
        ("test_module", ["ignore_module"], False),
        # Test case 2: Exact match in ignore list
        ("ignore_module", ["ignore_module"], True),
        # Test case 3: Partial match in ignore list
        ("test_ignore_module", ["ignore_module"], True),
        # Test case 4: Module name with spaces, not in ignore list
        ("test module", ["ignore module"], False),
        # Test case 5: Module name with hyphens, not in ignore list
        ("test-module", ["ignore-module"], False),
    ],
)
def test_is_ignored_module(module_name, modules_to_ignore, expected):
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.modules_to_ignore = modules_to_ignore
    assert process_manager.is_ignored_module(module_name) == expected


def test_print_disabled_modules():
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.modules_to_ignore = ["Module1", "Module2"]
    with patch.object(process_manager.main, "print") as mock_print:
        process_manager.print_disabled_modules()
        mock_print.assert_called_once_with(
            "Disabled Modules: " "['Module1', 'Module2']", 1, 0
        )


@pytest.mark.parametrize(
    "pending_modules, expected_print_calls",
    [
        # Test case 1: No pending modules, no additional print calls
        ([], 1),
        # Test case 2: Pending modules without Update Manager, one additional print call
        ([Mock(name="Module1"), Mock(name="Module2")], 1),
    ],
)
def test_warn_about_pending_modules(pending_modules, expected_print_calls):
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.warning_printed_once = False

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
    [  # Testcase1: blocking enabled, Exporting Alerts enabled
        (True, False, [1, 2], [3, 4, 5]),
        # Testcase2: Blocking disabled, Exporting Alerts enabled
        (False, False, [1, 2, 4], [3, 5]),
        # Testcase3: Blocking enabled, Exporting Alerts disabled
        (True, True, [1, 2, 5], [3, 4]),
        # Testcase4: Blocking disabled, Exporting Alerts disabled
        (False, True, [1, 2, 4, 5], [3]),
        # Testcase5: All enabled, some PIDs are None
        (True, False, [1, 2], [3, 4, 5]),
    ],
)
def test_get_hitlist_in_order(
    blocking_enabled,
    exporting_alerts_disabled,
    expected_kill_first,
    expected_kill_last,
):
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.processes = [
        Mock(pid=1, name="Process1"),
        Mock(pid=2, name="Process2"),
        Mock(pid=3, name="EvidenceHandler"),
        Mock(pid=4, name="Blocking"),
        Mock(pid=5, name="Exporting Alerts"),
    ]

    process_manager.main.db.get_pid_of = lambda x: {
        "EvidenceHandler": 3,
        "Blocking": 4,
        "Exporting Alerts": 5,
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

    with patch("time.time", side_effect=[0, 3.1]):
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
    utils.convert_format = Mock(return_value=end_date_str)
    process_manager.main.db.get_slips_start_time.return_value = start_time_str

    analysis_time = process_manager.get_analysis_time()

    assert analysis_time == (expected_analysis_time, end_date_str)


@pytest.mark.parametrize(
    "message, msg_recvd_in_control_channel, expected_result",
    [
        # Test case 1: Message is None
        (None, True, False),
        # Test case 2: Message doesn't contain "stop_slips"
        ({"data": "some_other_message"}, True, False),
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
    [  # Testcase1: Debugger inactive
        (None, False),
        # Testcase2: Debugger active
        (Mock(), True),
    ],
)
def test_is_debugger_active(mock_return_value, expected_result):
    mock_conf = Mock()
    mock_conf.get_bootstrapping_setting.return_value = (False, [])
    process_manager = ProcessManager(mock_conf)  # This line should now work
    with patch("sys.gettrace", return_value=mock_return_value):
        assert process_manager.is_debugger_active() == expected_result


@pytest.mark.parametrize(
    "debugger_active, input_type, is_interface, expected",
    [
        # Test case 1: Debugger active
        (True, "pcap", False, True),
        # Test case 2: Stdin input
        (False, "stdin", False, True),
        # Test case 3: Cyst input
        (False, "cyst", False, True),
        # Test case 4: Interface input
        (False, "pcap", True, True),
        # Test case 5: Normal case (should stop)
        (False, "pcap", False, False),
    ],
)
def test_should_run_non_stop(
    debugger_active, input_type, is_interface, expected
):
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.is_debugger_active = Mock(return_value=debugger_active)
    process_manager.main.input_type = input_type
    process_manager.main.is_interface = is_interface

    assert process_manager.should_run_non_stop() == expected


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
    process_manager.processes = [Mock(), Mock()]
    process_manager.stopped_modules = []

    with patch(
        "managers.process_manager.green",
        side_effect=["green_module_name", "green_count"],
    ), patch.object(process_manager.main, "print") as mock_print:
        process_manager.print_stopped_module("TestModule")

        assert "TestModule" in process_manager.stopped_modules
        mock_print.assert_called_once()

        printed_str = mock_print.call_args[0][0]
        assert "green_module_name" in printed_str
        assert "Stopped" in printed_str
        assert "green_count left" in printed_str


def test_start_profiler_process():
    process_manager = ModuleFactory().create_process_manager_obj()
    with patch("managers.process_manager.Profiler") as mock_profiler:
        mock_profiler_process = Mock()
        mock_profiler.return_value = mock_profiler_process
        mock_profiler_process.pid = 67890

        result = process_manager.start_profiler_process()

        assert result == mock_profiler_process
        mock_profiler.assert_called_once_with(
            process_manager.main.logger,
            process_manager.main.args.output,
            process_manager.main.redis_port,
            process_manager.termination_event,
            is_profiler_done=process_manager.is_profiler_done,
            profiler_queue=process_manager.profiler_queue,
            is_profiler_done_event=process_manager.is_profiler_done_event,
        )
        mock_profiler_process.start.assert_called_once()
        process_manager.main.print.assert_called_once()
        process_manager.main.db.store_pid.assert_called_once_with(
            "Profiler", 67890
        )


@pytest.mark.parametrize(
    "output_dir, redis_port",
    [
        # Test case 1: Default output directory and Redis port
        ("output", 6379),
        # Test case 2: Custom output directory and Redis port
        ("/custom/output", 6380),
    ],
)
def test_start_evidence_process(output_dir, redis_port):
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.main.args.output = output_dir
    process_manager.main.redis_port = redis_port

    with patch("managers.process_manager.EvidenceHandler") as mock_evidence:
        mock_evidence_process = Mock()
        mock_evidence.return_value = mock_evidence_process
        mock_evidence_process.pid = 13579

        result = process_manager.start_evidence_process()

        assert result == mock_evidence_process
        mock_evidence.assert_called_once_with(
            process_manager.main.logger,
            output_dir,
            redis_port,
            process_manager.evidence_handler_termination_event,
        )
        mock_evidence_process.start.assert_called_once()
        process_manager.main.print.assert_called_once()
        process_manager.main.db.store_pid.assert_called_once_with(
            "EvidenceHandler", 13579
        )


def test_print_started_module():
    process_manager = ModuleFactory().create_process_manager_obj()
    with patch(
        "managers.process_manager.green", return_value="green_module_name"
    ), patch.object(process_manager.main, "print") as mock_print:
        process_manager.print_started_module(
            "TestModule", 12345, "Test description"
        )

        mock_print.assert_called_once_with(
            "\t\tStarting the module green_module_name "
            "(Test description) [PID green_module_name]",
            1,
            0,
        )


@pytest.mark.parametrize(
    "local_files, ti_feeds, ports_called, orgs_called, "
    "whitelist_called, print_called, asyncio_called",
    [  # Testcase1: Update both
        (True, True, True, True, True, True, True),
        # Testcase2: Update local only
        (True, False, True, True, True, False, False),
        # Testcase3: Update TI only
        (False, True, False, False, False, True, True),
        # Testcase4: Don't update
        (False, False, False, False, False, False, False),
    ],
)
@patch("asyncio.run")
@patch("managers.process_manager.Lock")
def test_start_update_manager(
    mock_lock,
    mock_asyncio_run,
    local_files,
    ti_feeds,
    ports_called,
    orgs_called,
    whitelist_called,
    print_called,
    asyncio_called,
):
    process_manager = ModuleFactory().create_process_manager_obj()
    mock_lock_instance = Mock()
    mock_lock.return_value.__enter__.return_value = mock_lock_instance

    mock_update_manager = Mock()
    with patch(
        "managers.process_manager.UpdateManager",
        return_value=mock_update_manager,
    ):
        process_manager.start_update_manager(
            local_files=local_files, ti_feeds=ti_feeds
        )

    assert mock_update_manager.update_ports_info.called is ports_called
    assert mock_update_manager.update_org_files.called is orgs_called
    assert (
        mock_update_manager.update_local_whitelist.called is whitelist_called
    )
    assert mock_update_manager.print.called is print_called
    assert mock_asyncio_run.called is asyncio_called
