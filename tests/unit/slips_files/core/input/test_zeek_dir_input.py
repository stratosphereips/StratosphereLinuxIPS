# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import MagicMock, patch
from tests.module_factory import ModuleFactory


def test_zeek_dir_input_reads_directory(tmp_path):
    input_process = ModuleFactory().create_input_obj(
        str(tmp_path), "zeek_folder"
    )
    input_process.args.growing = False
    input_process.args.interface = "eth0"
    input_process.is_running_non_stop = False
    input_process.testing = True
    input_process.db.is_growing_zeek_dir.return_value = False
    input_process.db.set_input_metadata = MagicMock()
    input_process.zeek_utils.is_zeek_tabs_file = MagicMock(return_value=True)
    input_process.zeek_utils.read_zeek_files = MagicMock(return_value=2)
    input_process.get_flows_number = MagicMock(return_value=2)
    input_process.print_lines_read = MagicMock()
    input_process.mark_self_as_done_processing = MagicMock()

    (tmp_path / "conn.log").write_text("#fields\nline1\n", encoding="utf-8")

    handler = input_process.input_handlers["zeek_folder"]
    handler.observer.start = MagicMock()
    handler.db.add_zeek_file = MagicMock()
    with patch(
        "slips_files.core.input.zeek.zeek_dir_input.utils.is_ignored_zeek_log_file",
        return_value=False,
    ), patch("os.listdir", return_value=["conn.log"]):
        assert handler.run() is True

    handler.db.add_zeek_file.assert_called_once()
    input_process.zeek_utils.read_zeek_files.assert_called_once()
    input_process.print_lines_read.assert_called_once()
    input_process.mark_self_as_done_processing.assert_called_once()
    assert input_process.lines == 2
