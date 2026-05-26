# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Unit tests for the profiler worker manager mixin."""

from unittest.mock import Mock, call

import pytest

from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "last_worker_id, should_remove",
    [
        (2, False),
        (3, True),
    ],
)
def test_check_if_stabled_throughput_only_removes_extra_workers(
    last_worker_id: int,
    should_remove: bool,
) -> None:
    """
    Test that stable throughput never removes initial profiler workers.

    Parameters:
    last_worker_id: The last started profiler worker identifier.
    should_remove: Whether a worker should be removed.

    Return:
    None.
    """
    profiler = ModuleFactory().create_profiler_obj()
    profiler.last_worker_id = last_worker_id
    profiler.active_profiler_workers = last_worker_id + 1
    profiler.profiler_queue = Mock()
    profiler.print = Mock()
    profiler.did_5min_pass_since_last_worker_decrease_check = Mock(
        return_value=True
    )
    profiler.db.get_core_module_flows_per_second.side_effect = [100, 80]

    profiler._check_if_stabled_throughput_and_remove_workers()

    if should_remove:
        profiler.profiler_queue.put.assert_called_once_with("stop")
        assert profiler.active_profiler_workers == last_worker_id
        assert profiler.last_worker_id == last_worker_id - 1
        profiler.print.assert_called_once()
    else:
        profiler.profiler_queue.put.assert_not_called()
        assert profiler.active_profiler_workers == last_worker_id + 1
        assert profiler.last_worker_id == last_worker_id
        profiler.print.assert_not_called()


@pytest.mark.parametrize(
    "profiler_fps, input_fps, should_remove",
    [
        (100, 100, True),
        (100, 80, True),
        (80, 100, False),
    ],
)
def test_check_if_stabled_throughput_compares_rates(
    profiler_fps: int,
    input_fps: int,
    should_remove: bool,
) -> None:
    """
    Test that stable throughput removes a worker only when profiler keeps up.

    Parameters:
    profiler_fps: The profiler flows per second.
    input_fps: The input flows per second.
    should_remove: Whether a worker should be removed.

    Return:
    None.
    """
    profiler = ModuleFactory().create_profiler_obj()
    profiler.last_worker_id = 3
    profiler.active_profiler_workers = 4
    profiler.profiler_queue = Mock()
    profiler.print = Mock()
    profiler.did_5min_pass_since_last_worker_decrease_check = Mock(
        return_value=True
    )
    profiler.db.get_core_module_flows_per_second.side_effect = [
        profiler_fps,
        input_fps,
    ]

    profiler._check_if_stabled_throughput_and_remove_workers()

    if should_remove:
        profiler.profiler_queue.put.assert_called_once_with("stop")
        assert profiler.active_profiler_workers == 3
        assert profiler.last_worker_id == 2
    else:
        profiler.profiler_queue.put.assert_not_called()
        assert profiler.active_profiler_workers == 4
        assert profiler.last_worker_id == 3


def test_check_if_stabled_throughput_waits_for_interval() -> None:
    """
    Test that workers are not removed before the decrease interval elapses.

    Return:
    None.
    """
    profiler = ModuleFactory().create_profiler_obj()
    profiler.last_worker_id = 3
    profiler.active_profiler_workers = 4
    profiler.profiler_queue = Mock()
    profiler.did_5min_pass_since_last_worker_decrease_check = Mock(
        return_value=False
    )

    profiler._check_if_stabled_throughput_and_remove_workers()

    profiler.profiler_queue.put.assert_not_called()
    profiler.db.get_core_module_flows_per_second.assert_not_called()
    assert profiler.active_profiler_workers == 4
    assert profiler.last_worker_id == 3


def test_worker_scaling_uses_lowercase_input_metric_key() -> None:
    """
    Test that worker scaling reads the stored lowercase input metric key.

    Return:
    None.
    """
    profiler = ModuleFactory().create_profiler_obj()
    profiler.last_worker_id = 2
    profiler.active_profiler_workers = 3
    profiler.start_profiler_worker = Mock()
    profiler.print = Mock()
    profiler.did_5min_pass_since_last_throughput_check = Mock(
        return_value=True
    )
    profiler.db.get_core_module_flows_per_second.side_effect = [10, 100]

    profiler._check_if_high_throughput_and_add_workers()

    profiler.db.get_core_module_flows_per_second.assert_has_calls(
        [call("profiler"), call("input")]
    )
    profiler.start_profiler_worker.assert_called_once_with(3)


def test_update_lines_read_uses_shared_profiler_counter() -> None:
    """
    Test that profiler throughput uses the shared processed-flow counter.

    Return:
    None.
    """
    profiler = ModuleFactory().create_profiler_obj()
    profiler.db.get_flows_analyzed_by_the_profiler_so_far.return_value = 42

    profiler._update_lines_read_by_all_workers()

    assert profiler.lines == 42


@pytest.mark.parametrize(
    "stored_value, expected_fps",
    [
        ("42", 42.0),
        (None, 0),
        ("invalid", 0),
    ],
)
def test_get_flows_per_second_handles_database_values(
    stored_value: str | None,
    expected_fps: float,
) -> None:
    """
    Test that stored flow rates are converted defensively.

    Parameters:
    stored_value: The value returned by the database.
    expected_fps: The expected converted flows per second.

    Return:
    None.
    """
    profiler = ModuleFactory().create_profiler_obj()
    profiler.db.get_core_module_flows_per_second.return_value = stored_value

    assert profiler._get_flows_per_second("Input") == expected_fps
