# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import MagicMock, patch
from tests.module_factory import ModuleFactory


def test_zeek_log_file_input_reads_file(tmp_path):
    test_file = tmp_path / "conn.log"
    test_file.write_text("#fields\nline1\n", encoding="utf-8")

    input_process = ModuleFactory().create_input_obj(
        str(test_file), "zeek_log_file"
    )
    input_process.zeek_utils.is_zeek_tabs_file = MagicMock(return_value=True)
    input_process.get_flows_number = MagicMock(return_value=2)
    input_process.db.set_input_metadata = MagicMock()
    input_process.zeek_utils.read_zeek_files = MagicMock(return_value=2)
    input_process.mark_self_as_done_processing = MagicMock()

    handler = input_process.input_handlers["zeek_log_file"]
    handler.db.add_zeek_file = MagicMock()
    with patch(
        "slips_files.core.input.zeek.zeek_log_file_input.utils.is_ignored_zeek_log_file",
        return_value=False,
    ), patch("os.path.exists", return_value=True):
        assert handler.run() is True

    handler.db.add_zeek_file.assert_called_once()
    input_process.zeek_utils.read_zeek_files.assert_called_once()
    input_process.mark_self_as_done_processing.assert_called_once()
    assert input_process.lines == 2
