# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import MagicMock
from tests.module_factory import ModuleFactory


def test_cyst_input_stops_on_stop_process_message():
    input_process = ModuleFactory().create_input_obj(
        "", "CYST", line_type="zeek"
    )
    input_process.should_stop = MagicMock(return_value=False)
    input_process.shutdown_gracefully = MagicMock(return_value=True)
    input_process.get_msg = MagicMock(return_value={"data": "stop_process"})

    handler = input_process.input_handlers["CYST"]
    assert handler.run() is True
    input_process.shutdown_gracefully.assert_called_once()
