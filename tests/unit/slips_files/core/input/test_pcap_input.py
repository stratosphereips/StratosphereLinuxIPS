# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import MagicMock
from tests.module_factory import ModuleFactory


def test_pcap_input_runs_through_zeek_utils(tmp_path):
    input_process = ModuleFactory().create_input_obj(
        "dataset/test7-malicious.pcap", "pcap"
    )
    input_process.zeek_dir = str(tmp_path)
    input_process.is_running_non_stop = False
    input_process.zeek_utils.ensure_zeek_dir = MagicMock()
    input_process.zeek_utils.init_zeek = MagicMock()
    input_process.zeek_utils.read_zeek_files = MagicMock(return_value=3)
    input_process.print_lines_read = MagicMock()
    input_process.mark_self_as_done_processing = MagicMock()

    handler = input_process.input_handlers["pcap"]
    assert handler.run() is True

    input_process.zeek_utils.ensure_zeek_dir.assert_called_once()
    input_process.zeek_utils.init_zeek.assert_called_once()
    input_process.zeek_utils.read_zeek_files.assert_called_once()
    input_process.print_lines_read.assert_called_once()
    input_process.mark_self_as_done_processing.assert_called_once()
    assert input_process.lines == 3
