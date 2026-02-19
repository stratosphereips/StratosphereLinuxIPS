# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from tests.module_factory import ModuleFactory


def test_binetflow_tabs_input_uses_argus_tabs(tmp_path):
    input_process = ModuleFactory().create_input_obj(
        str(tmp_path / "test.binetflow"), "binetflow-tabs"
    )
    test_file = tmp_path / "test.binetflow"
    test_file.write_text("field1\tfield2\nflow1\n", encoding="utf-8")
    input_process.given_path = str(test_file)
    input_process.testing = True
    input_process.mark_self_as_done_processing = lambda: None

    handler = input_process.input_handlers["binetflow-tabs"]
    assert handler.run() is True

    line_sent = input_process.profiler_queue.get()
    assert line_sent["line"]["type"] == "argus-tabs"
