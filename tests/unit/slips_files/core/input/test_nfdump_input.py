# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import MagicMock
import pytest
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize("output,expected_total", [("a\nb\n", 2), ("", 0)])
def test_nfdump_read_output_sets_total(output, expected_total):
    input_process = ModuleFactory().create_input_obj("", "nfdump")
    input_process.testing = True
    input_process.print = MagicMock()
    input_process.total_flows = 0

    handler = input_process.input_handlers["nfdump"]
    handler.nfdump_output = output
    total = handler.read_nfdump_output()

    assert total == expected_total
    if output:
        line_sent = input_process.profiler_queue.get()
        assert line_sent["line"]["type"] == "nfdump"
