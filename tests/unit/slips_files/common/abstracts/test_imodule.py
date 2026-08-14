# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
from unittest.mock import Mock

import pytest

from tests.module_factory import ModuleFactory
from slips_files.common.abstracts.imodule import IModule
from slips_files.common.slips_utils import utils


def test_imodule_exposes_slips_version():
    ip_info = ModuleFactory().create_ip_info_obj()

    assert ip_info.slips_version == utils.get_slips_version()


@pytest.mark.parametrize(
    "module_name",
    ["imodule", "http_analyzer", "p2p_trust", "module1"],
)
def test_imodule_accepts_snake_case_name(module_name):
    """Ensure IModule subclasses can define snake_case names."""
    module_factory = ModuleFactory()

    class SnakeCaseNameModule(IModule):
        """Test module with a snake_case name."""

        name = module_name

    assert module_factory.logger is not None
    assert SnakeCaseNameModule.name == module_name


@pytest.mark.parametrize(
    "module_name",
    [
        "RegexGenerator",
        "T Cell",
        "module-name",
        "module__name",
        "module_",
        "_module",
        "1module",
        "",
        None,
    ],
)
def test_imodule_rejects_non_snake_case_name(module_name):
    """Ensure IModule subclasses reject names that are not snake_case."""
    module_factory = ModuleFactory()

    with pytest.raises(
        RuntimeError,
        match="NonSnakeCaseNameModule.name must be snake_case",
    ):

        class NonSnakeCaseNameModule(IModule):
            """Test module with a non-snake-case name."""

            name = module_name

    assert module_factory.logger is not None


def test_imodule_init_rejects_unsupported_module_name():
    """Ensure IModule init rejects names missing from the supported enum."""
    module_factory = ModuleFactory()

    class UnsupportedModule(IModule):
        """Test module with a missing supported module enum entry."""

        name = "module1"

        def init(self, **kwargs):
            pass

        def subscribe_to_channels(self):
            pass

        def main(self):
            pass

    with pytest.raises(
        RuntimeError,
        match="UnsupportedModule.name='module1' is not registered",
    ):
        UnsupportedModule(
            logger=module_factory.logger,
            output_dir="dummy_output_dir",
            redis_port=6379,
            termination_event=Mock(),
            slips_args=Mock(),
            conf=Mock(),
            ppid=1234,
            bloom_filters_manager=Mock(),
        )


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
