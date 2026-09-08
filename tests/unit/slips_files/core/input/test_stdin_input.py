# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import patch
import os
from multiprocessing.reduction import DupFd
import pytest
from slips_files.core.input_profilers.argus import Argus
from slips_files.common.input_type import InputType
from slips_files.core.input.input import SUPPORTED_INPUT_HANDLERS
from tests.module_factory import ModuleFactory


def test_stdin_input_parses_zeek_json():
    input_process = ModuleFactory().create_input_obj(
        "zeek", "stdin", line_type="zeek"
    )
    handler = SUPPORTED_INPUT_HANDLERS[InputType.STDIN](input_process)

    with patch.object(handler, "_stdin", return_value=['{"ts": 1}', "done\n"]):
        assert handler.run() is True

    line_sent = input_process.profiler_queue.get()
    assert line_sent["line"]["type"] == "stdin"
    assert line_sent["line"]["line_type"] == "zeek"
    assert line_sent["line"]["data"]["ts"] == 1
    assert line_sent["line"]["interface"] == "default"


def test_stdin_reads_transferred_descriptor() -> None:
    """Read the supplied pipe instead of multiprocessing's replaced stdin."""
    input_process = ModuleFactory().create_input_obj(
        "zeek", "stdin", line_type="zeek"
    )
    read_fd, write_fd = os.pipe()
    try:
        input_process.stdin_descriptor = DupFd(read_fd)
        os.write(write_fd, b'{"ts": 2}\n')
    finally:
        os.close(write_fd)
        os.close(read_fd)
    handler = SUPPORTED_INPUT_HANDLERS[InputType.STDIN](input_process)
    with handler._stdin() as stream:
        assert stream.read() == '{"ts": 2}\n'


@pytest.mark.parametrize("with_header", [True, False])
def test_argus_stdin_keeps_first_flow(with_header: bool) -> None:
    """Accept Argus stdin with or without a header without losing a flow.

    Parameters:
        with_header: Whether the producer sends the field names first.
    """
    input_process = ModuleFactory().create_input_obj("argus", "stdin")
    with patch("sys.argv", ["slips.py", "-f", "argus"]):
        parser = Argus(input_process.db)
    if with_header:
        flow, _ = parser.process_line(
            {
                "data": (
                    "StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,"
                    "sTos,dTos,TotPkts,TotBytes,SrcBytes,SrcPkts"
                )
            }
        )
        assert flow is False
    flow, _ = parser.process_line(
        {
            "data": (
                "2018/01/12 16:37:30.942,1,tcp,192.168.1.2,1234,->,"
                "192.168.1.3,80,CON,0,0,2,100,60,1"
            )
        }
    )
    assert flow.saddr == "192.168.1.2"
    assert flow.pkts == 2
