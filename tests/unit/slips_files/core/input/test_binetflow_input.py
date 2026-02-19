# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import pytest
from tests.module_factory import ModuleFactory


def test_binetflow_input_runs_and_sends_lines(tmp_path):
    input_process = ModuleFactory().create_input_obj(
        str(tmp_path / "test.binetflow"), "binetflow"
    )
    test_file = tmp_path / "test.binetflow"
    test_file.write_text("header\nflow1\nflow2\n", encoding="utf-8")
    input_process.given_path = str(test_file)
    input_process.testing = False
    input_process.mark_self_as_done_processing = lambda: None

    handler = input_process.input_handlers["binetflow"]
    assert handler.run() is True

    assert input_process.total_flows == 2
    line_sent = input_process.profiler_queue.get()
    assert line_sent["line"]["type"] in {"argus", "argus-tabs"}
    assert line_sent["input_type"] == "binetflow"


@pytest.mark.parametrize(
    "header,expected_type",
    [("field1\tfield2\n", "argus-tabs"), ("field1,field2\n", "argus")],
)
def test_binetflow_input_detects_line_type(tmp_path, header, expected_type):
    input_process = ModuleFactory().create_input_obj(
        str(tmp_path / "test.binetflow"), "binetflow"
    )
    test_file = tmp_path / "test.binetflow"
    test_file.write_text(f"{header}flow1\n", encoding="utf-8")
    input_process.given_path = str(test_file)
    input_process.testing = True
    input_process.mark_self_as_done_processing = lambda: None

    handler = input_process.input_handlers["binetflow"]
    assert handler.run() is True

    line_sent = input_process.profiler_queue.get()
    assert line_sent["line"]["type"] == expected_type
