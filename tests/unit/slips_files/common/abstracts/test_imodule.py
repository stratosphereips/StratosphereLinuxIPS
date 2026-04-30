# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json

from tests.module_factory import ModuleFactory
from slips_files.common.slips_utils import utils


def test_imodule_exposes_slips_version():
    ip_info = ModuleFactory().create_ip_info_obj()

    assert ip_info.slips_version == utils.get_slips_version()


def test_get_msg_discards_messages_with_different_version():
    ip_info = ModuleFactory().create_ip_info_obj()
    ip_info.channels = {"new_ip": "channel_obj"}
    ip_info.channel_tracker = ip_info.init_channel_tracker()
    ip_info.db.get_message.return_value = {
        "channel": "new_ip",
        "data": json.dumps({"text": "1.2.3.4", "version": "0.0.0"}),
    }

    msg = ip_info.get_msg("new_ip")

    assert msg is None
    assert ip_info.channel_tracker["new_ip"]["msg_received"] is False
    ip_info.db.incr_msgs_received_in_channel.assert_not_called()


def test_get_msg_accepts_messages_with_current_version():
    ip_info = ModuleFactory().create_ip_info_obj()
    ip_info.channels = {"new_ip": "channel_obj"}
    ip_info.channel_tracker = ip_info.init_channel_tracker()
    message = {
        "channel": "new_ip",
        "data": json.dumps(
            {"text": "1.2.3.4", "version": ip_info.slips_version}
        ),
    }
    ip_info.db.get_message.return_value = message

    msg = ip_info.get_msg("new_ip")

    assert msg == message
    assert ip_info.channel_tracker["new_ip"]["msg_received"] is True
    ip_info.db.incr_msgs_received_in_channel.assert_called_once_with(
        ip_info.name, "new_ip"
    )
