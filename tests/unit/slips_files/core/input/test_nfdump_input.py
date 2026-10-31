# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import MagicMock
import pytest
from tests.module_factory import ModuleFactory
from slips_files.common.input_type import InputType
from slips_files.core.input.input import SUPPORTED_INPUT_HANDLERS
from slips_files.core.input_profilers.nfdump import Nfdump


@pytest.mark.parametrize("output,expected_total", [("a\nb\n", 2), ("", 0)])
def test_nfdump_read_output_sets_total(output, expected_total):
    input_process = ModuleFactory().create_input_obj("", InputType.NFDUMP)
    input_process.testing = True
    input_process.print = MagicMock()
    input_process.total_flows = 0

    handler = SUPPORTED_INPUT_HANDLERS[InputType.NFDUMP](input_process)
    handler.nfdump_output = output
    total = handler.read_nfdump_output()

    assert total == expected_total
    if output:
        line_sent = input_process.profiler_queue.get()
        assert line_sent["line"]["type"] == "nfdump"


@pytest.mark.parametrize("padded", [False, True])
def test_nfdump_explicit_format_parses(padded: bool) -> None:
    """Accept legacy CSV and the padded explicit nfdump output format.

    Parameters:
        padded: Whether fields contain formatting whitespace.
    """
    input_process = ModuleFactory().create_input_obj("", InputType.NFDUMP)
    fields = [
        "2018-01-12 16:37:30.942",
        "2018-01-12 16:37:31.942",
        "1.000",
        "147.32.80.119",
        "147.32.82.62",
        "52324",
        "902",
        "6",
        "......S.",
        "0",
        "0",
        "1",
        "60",
        "1",
        "40",
        "0",
        "0",
        "2852",
        "2852",
        "0",
        "0",
        "0",
        "I",
    ]
    line = ",".join(f"  {field}  " if padded else field for field in fields)
    flow, _ = Nfdump(input_process.db).process_line({"data": line})
    assert flow.saddr == "147.32.80.119"
    assert flow.daddr == "147.32.82.62"
    assert flow.sport == "52324"
    assert flow.endtime - flow.starttime == 1
    assert flow.sbytes == 60
    assert flow.bytes == 100
    assert flow.pkts == 2
    assert flow.proto == "tcp"
