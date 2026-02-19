# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import MagicMock, patch
from tests.module_factory import ModuleFactory


def test_interface_input_runs_for_single_interface(tmp_path):
    input_process = ModuleFactory().create_input_obj("", "interface")
    input_process.zeek_dir = str(tmp_path)
    input_process.args.interface = "eth0"
    input_process.args.access_point = False
    input_process.is_running_non_stop = False
    input_process.zeek_utils.ensure_zeek_dir = MagicMock()
    input_process.zeek_utils.init_zeek = MagicMock()
    input_process.zeek_utils.read_zeek_files = MagicMock(return_value=4)
    input_process.print_lines_read = MagicMock()
    input_process.mark_self_as_done_processing = MagicMock()

    handler = input_process.input_handlers["interface"]
    with patch("os.path.exists", return_value=True):
        assert handler.run() is True

    input_process.zeek_utils.ensure_zeek_dir.assert_called_once()
    input_process.zeek_utils.init_zeek.assert_called_once()
    input_process.zeek_utils.read_zeek_files.assert_called_once()
    input_process.print_lines_read.assert_called_once()
    input_process.mark_self_as_done_processing.assert_called_once()
    assert input_process.lines == 4
