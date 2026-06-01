# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

import pytest

from slips_files.common.input_type import InputType
from slips_files.core.zeek_cmd_builder import ZeekCommandBuilder
from tests.module_factory import ModuleFactory


def create_zeek_command_builder(input_type: InputType) -> ZeekCommandBuilder:
    """
    Create a Zeek command builder for tests.

    Parameters:
    input_type: Type of input Zeek should process.

    Return:
    Configured ZeekCommandBuilder instance.
    """
    return ZeekCommandBuilder(
        zeek_or_bro="zeek",
        input_type=input_type,
        default_rotation_interval="1 day",
        enable_rotation=True,
        tcp_inactivity_timeout=5,
    )


def test_sanitize_packet_filter_rejects_newlines():
    input_process = ModuleFactory().create_input_obj(
        "", InputType.ZEEK_LOG_FILE
    )
    builder = create_zeek_command_builder(input_process.input_type)

    with pytest.raises(ValueError):
        builder._sanitize_packet_filter("tcp\nport 80")


def test_sanitize_zeek_target_rejects_unsafe_interface():
    input_process = ModuleFactory().create_input_obj("", InputType.INTERFACE)
    builder = create_zeek_command_builder(input_process.input_type)

    with pytest.raises(ValueError):
        builder._sanitize_zeek_target("eth0;rm -rf /")
