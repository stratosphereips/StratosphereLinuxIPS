# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import Mock, patch

import pytest

from managers.process_manager.startup_mixin import StartupMixin
from slips_files.common.input_type import InputType
from tests.module_factory import ModuleFactory


def test_process_manager_includes_startup_mixin() -> None:
    process_manager = ModuleFactory().create_process_manager_obj()

    assert isinstance(process_manager, StartupMixin)


@pytest.mark.parametrize(
    "input_type, input_information, cli_packet_filter, "
    "zeek_or_bro, line_type",
    [
        # Test case 1: pcap input
        (
            InputType.PCAP,
            "test.pcap",
            "tcp port 80",
            "zeek",
            "conn",
        ),
        # Test case 2: zeek input
        (InputType.ZEEK, "test.log", "", "bro", "dns"),
        # Test case 3: stdin input
        (InputType.STDIN, "-", "", "zeek", "http"),
    ],
)
def test_start_input_process(
    input_type,
    input_information,
    cli_packet_filter,
    zeek_or_bro,
    line_type,
):
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.main.input_type = input_type
    process_manager.main.input_information = input_information
    process_manager.main.args.pcapfilter = cli_packet_filter
    process_manager.main.zeek_bro = zeek_or_bro
    process_manager.main.line_type = line_type
    process_manager.main.bloom_filters_man = Mock()

    with patch("managers.process_manager.startup_mixin.Input") as mock_input:
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
            process_manager.main.args,
            process_manager.main.conf,
            process_manager.main.pid,
            process_manager.main.bloom_filters_man,
            is_input_done=process_manager.is_input_done,
            profiler_queue=process_manager.profiler_queue,
            input_type=input_type,
            input_information=input_information,
            cli_packet_filter=cli_packet_filter,
            zeek_or_bro=zeek_or_bro,
            line_type=line_type,
            is_profiler_done_event=process_manager.is_profiler_done_event,
            is_input_done_event=process_manager.is_input_done_event,
            is_input_failed_event=process_manager.is_input_failed_event,
            is_slips_live_updating_event=(
                process_manager.is_slips_live_updating_event
            ),
            is_profiler_done_starting_initial_workers_event=(
                process_manager.is_profiler_done_starting_initial_workers_event
            ),
        )
        mock_input_process.start.assert_called_once()
        process_manager.main.print.assert_called_once()
        process_manager.main.db.store_pid.assert_called_once_with(
            "Input", 54321
        )


def test_start_profiler_process():
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.main.bloom_filters_man = Mock()
    with patch(
        "managers.process_manager.startup_mixin.Profiler"
    ) as mock_profiler, patch.object(
        process_manager.is_profiler_done_starting_initial_workers_event,
        "wait",
    ):
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
            process_manager.main.args,
            process_manager.main.conf,
            process_manager.main.pid,
            process_manager.main.bloom_filters_man,
            is_profiler_done_semaphore=(
                process_manager.is_profiler_done_semaphore
            ),
            profiler_queue=process_manager.profiler_queue,
            is_profiler_done_event=process_manager.is_profiler_done_event,
            is_input_done_event=process_manager.is_input_done_event,
            is_input_failed_event=process_manager.is_input_failed_event,
            is_profiler_done_starting_initial_workers_event=(
                process_manager.is_profiler_done_starting_initial_workers_event
            ),
        )
        mock_profiler_process.start.assert_called_once()
        process_manager.main.print.assert_called_once()
        process_manager.main.db.store_pid.assert_called_once_with(
            "Profiler", 67890
        )


@pytest.mark.parametrize(
    "input_type, should_wait",
    [
        (InputType.INTERFACE, True),
        (InputType.PCAP, False),
    ],
)
def test_start_profiler_process_waits_for_initial_workers(
    input_type, should_wait
):
    """
    Test that only interface profiler startup waits for initial workers.

    Parameters:
    input_type: Input type used for the run.
    should_wait: Whether profiler startup should wait for initial workers.

    Return:
    None.
    """
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.main.bloom_filters_man = Mock()
    process_manager.main.input_type = input_type
    wait_event = (
        process_manager.is_profiler_done_starting_initial_workers_event
    )

    with patch(
        "managers.process_manager.startup_mixin.Profiler"
    ) as mock_profiler, patch.object(wait_event, "wait") as mock_wait:
        mock_profiler_process = Mock()
        mock_profiler.return_value = mock_profiler_process
        mock_profiler_process.pid = 67890

        process_manager.start_profiler_process()

    if should_wait:
        mock_wait.assert_called_once_with(30)
    else:
        mock_wait.assert_not_called()


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
    process_manager.main.bloom_filters_man = Mock()
    process_manager.main.args.output = output_dir
    process_manager.main.redis_port = redis_port

    with patch(
        "managers.process_manager.startup_mixin.EvidenceHandler"
    ) as mock_evidence:
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
            process_manager.main.args,
            process_manager.main.conf,
            process_manager.main.pid,
            process_manager.main.bloom_filters_man,
        )
        mock_evidence_process.start.assert_called_once()
        process_manager.main.print.assert_called_once()
        process_manager.main.db.store_pid.assert_called_once_with(
            "evidence_handler", 13579
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
@patch("managers.process_manager.startup_mixin.Lock")
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
    process_manager.main.args.output = "output"
    mock_lock_instance = Mock()
    mock_lock.return_value.__enter__.return_value = mock_lock_instance

    mock_update_manager = Mock()
    with patch(
        "managers.process_manager.startup_mixin.FeedsUpdateManager",
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
