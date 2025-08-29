# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import MagicMock
import pytest
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "cpu_profiler_multiprocess, expected_stop_calls, expected_print_calls",
    [  # Testcase1: CPU profiler enabled, not multiprocess
        (False, 1, 1),
        # Testcase2: CPU profiler enabled, multiprocess
        (True, 0, 0),
    ],
)
def test_cpu_profiler_release_enabled(
    cpu_profiler_multiprocess,
    expected_stop_calls,
    expected_print_calls,
):
    handler = ModuleFactory().create_profilers_manager_obj()
    handler.cpu_profiler_enabled = True
    handler.cpu_profiler_multiprocess = cpu_profiler_multiprocess
    handler.cpu_profiler = MagicMock()
    handler.cpu_profiler_release()

    assert handler.cpu_profiler.stop.call_count == expected_stop_calls
    assert handler.cpu_profiler.print.call_count == expected_print_calls


def test_cpu_profiler_release_disabled():
    handler = ModuleFactory().create_profilers_manager_obj()
    handler.cpu_profiler_enabled = False
    handler.cpu_profiler_release()
    assert not hasattr(handler, "memory_profiler")


def test_memory_profiler_release_enabled():
    handler = ModuleFactory().create_profilers_manager_obj()
    handler.memory_profiler_enabled = True
    handler.memory_profiler = MagicMock()
    handler.memory_profiler_release()
    handler.memory_profiler.stop.assert_called_once()


def test_memory_profiler_release_disabled():
    handler = ModuleFactory().create_profilers_manager_obj()
    handler.memory_profiler_enabled = False
    handler.memory_profiler_release()

    assert not hasattr(handler, "memory_profiler")
