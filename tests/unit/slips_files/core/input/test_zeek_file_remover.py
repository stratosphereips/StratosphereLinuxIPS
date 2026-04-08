# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
from unittest.mock import MagicMock, patch

import pytest

from tests.module_factory import ModuleFactory
from slips_files.core.input.zeek.utils.zeek_file_remover import ZeekFileRemover
from slips_files.common.input_type import InputType


def test_zeek_file_remover_start_subscribes_once():
    input_process = ModuleFactory().create_input_obj(
        "", InputType.ZEEK_LOG_FILE
    )
    input_process.db.subscribe = MagicMock(return_value="chan")
    remover = ZeekFileRemover(input_process, input_process.zeek_utils)
    remover.thread.start = MagicMock()

    remover.start()
    remover.start()

    input_process.db.subscribe.assert_called_once_with("remove_old_files")
    remover.thread.start.assert_called_once()
    assert input_process.channels["remove_old_files"] == "chan"


def test_zeek_file_remover_start_uses_existing_subscription():
    input_process = ModuleFactory().create_input_obj(
        "", InputType.ZEEK_LOG_FILE
    )
    input_process.channels["remove_old_files"] = "existing-chan"
    input_process.db.subscribe = MagicMock(return_value="new-chan")
    remover = ZeekFileRemover(input_process, input_process.zeek_utils)
    remover.thread.start = MagicMock()

    remover.start()

    input_process.db.subscribe.assert_called_once_with("remove_old_files")
    remover.thread.start.assert_called_once()
    assert input_process.channels["remove_old_files"] == "new-chan"


def test_remove_old_zeek_files_closes_and_schedules_cleanup():
    input_process = ModuleFactory().create_input_obj(
        "", InputType.ZEEK_LOG_FILE
    )
    input_process.should_stop = MagicMock(side_effect=[False, True])
    remover = ZeekFileRemover(input_process, input_process.zeek_utils)
    input_process.channels["remove_old_files"] = "chan"

    old_file = "/tmp/conn.2020-01-01.log"
    new_file = "/tmp/conn.log"
    mock_handle = MagicMock()
    input_process.zeek_utils.open_file_handles[new_file] = mock_handle

    msg = {"data": json.dumps({"old_file": old_file, "new_file": new_file})}
    input_process.get_msg = MagicMock(return_value=msg)

    with patch("time.time", return_value=123.0):
        remover.remove_old_zeek_files()

    mock_handle.close.assert_called_once()
    assert input_process.zeek_utils.open_file_handles.get(new_file) is None
    assert input_process.zeek_utils.rotated_files_to_delete == [
        (old_file, 123.0 + input_process.keep_rotated_files_for)
    ]


@pytest.mark.parametrize("keep_rotated_files_for", [0, 5])
def test_check_if_time_to_del_rotated_files_deletes_ready_files(
    keep_rotated_files_for,
):
    input_process = ModuleFactory().create_input_obj(
        "", InputType.ZEEK_LOG_FILE
    )
    input_process.keep_rotated_files_for = keep_rotated_files_for
    input_process.zeek_utils.rotated_files_to_delete = [
        ("/tmp/conn.2020-01-01.log", 100.0 + keep_rotated_files_for)
    ]

    with patch(
        "slips_files.core.input.zeek.utils.zeek_input_utils.utils.convert_ts_format",
        return_value=105.0,
    ), patch("slips_files.core.input.zeek.utils.zeek_input_utils.os.remove"):
        input_process.zeek_utils.check_if_time_to_del_rotated_files()

    assert input_process.zeek_utils.rotated_files_to_delete == []


def test_process_rotation_message_deletes_unsupported_files_immediately():
    input_process = ModuleFactory().create_input_obj(
        "", InputType.ZEEK_LOG_FILE
    )
    remover = ZeekFileRemover(input_process, input_process.zeek_utils)
    old_file = "/tmp/loaded_scripts.2020-01-01.log"
    new_file = "/tmp/loaded_scripts.log"

    with patch(
        "slips_files.core.input.zeek.utils.zeek_file_remover.os.remove"
    ) as mock_remove:
        remover.process_rotation_message(
            {"old_file": old_file, "new_file": new_file}
        )

    mock_remove.assert_called_once_with(old_file)
    assert input_process.zeek_utils.rotated_files_to_delete == []
