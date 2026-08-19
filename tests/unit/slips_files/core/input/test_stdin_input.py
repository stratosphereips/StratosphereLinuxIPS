# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import patch
from slips_files.common.input_type import InputType
from slips_files.core.input.input import SUPPORTED_INPUT_HANDLERS
from tests.module_factory import ModuleFactory


def test_stdin_input_parses_zeek_json():
    input_process = ModuleFactory().create_input_obj(
        "zeek", "stdin", line_type="zeek"
    )
    handler = SUPPORTED_INPUT_HANDLERS[InputType.STDIN](input_process)

    with patch.object(handler, "_stdin", return_value=['{"ts": 1}', "done"]):
        assert handler.run() is True

    line_sent = input_process.profiler_queue.get()
    assert line_sent["line"]["type"] == "stdin"
    assert line_sent["line"]["line_type"] == "zeek"
    assert line_sent["line"]["data"]["ts"] == 1
