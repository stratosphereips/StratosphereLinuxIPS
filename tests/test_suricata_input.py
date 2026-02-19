# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import MagicMock
from tests.module_factory import ModuleFactory


def test_suricata_input_reads_lines(tmp_path):
    input_process = ModuleFactory().create_input_obj(
        str(tmp_path / "test.json"), "suricata"
    )
    test_file = tmp_path / "test.json"
    test_file.write_text("line1\n\nline2\n", encoding="utf-8")
    input_process.given_path = str(test_file)
    input_process.get_flows_number = MagicMock(return_value=2)
    input_process.testing = True
    input_process.mark_self_as_done_processing = MagicMock()

    handler = input_process.input_handlers["suricata"]
    assert handler.run() is True

    line_sent = input_process.profiler_queue.get()
    assert line_sent["line"]["type"] == "suricata"
    input_process.mark_self_as_done_processing.assert_called_once()
