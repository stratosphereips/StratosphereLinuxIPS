# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
from unittest.mock import MagicMock, patch
from tests.module_factory import ModuleFactory
from slips_files.core.input.zeek.utils.zeek_file_remover import ZeekFileRemover


def test_zeek_file_remover_start_subscribes_once():
    input_process = ModuleFactory().create_input_obj("", "zeek_log_file")
    input_process.db.subscribe = MagicMock(return_value="chan")
    remover = ZeekFileRemover(input_process, input_process.zeek_utils)
    remover.thread.start = MagicMock()

    remover.start()
    remover.start()

    input_process.db.subscribe.assert_called_once_with("remove_old_files")
    remover.thread.start.assert_called_once()
    assert input_process.channels["remove_old_files"] == "chan"


def test_remove_old_zeek_files_closes_and_marks():
    input_process = ModuleFactory().create_input_obj("", "zeek_log_file")
    input_process.should_stop = MagicMock(side_effect=[False, True])
    remover = ZeekFileRemover(input_process, input_process.zeek_utils)
    input_process.channels["remove_old_files"] = "chan"

    old_file = "/tmp/conn.2020-01-01.log"
    new_file = "/tmp/conn.log"
    input_process.zeek_utils.open_file_handlers[new_file] = MagicMock()

    msg = {"data": json.dumps({"old_file": old_file, "new_file": new_file})}
    input_process.get_msg = MagicMock(return_value=msg)

    with patch(
        "slips_files.core.input.zeek.utils.zeek_file_remover.utils.convert_ts_format",
        return_value=123.0,
    ):
        remover.remove_old_zeek_files()

    assert input_process.zeek_utils.open_file_handlers.get(new_file) is None
    assert old_file in input_process.zeek_utils.to_be_deleted
    assert input_process.zeek_utils.time_rotated == 123.0
