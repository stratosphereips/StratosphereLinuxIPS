# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

import json
import os
from pathlib import Path
import stat
from unittest.mock import Mock, patch

import pytest
import yaml

from modules.iris.iris import Iris
from slips_files.common.ips import IPV4_LOCALHOST
from tests.module_factory import ModuleFactory


def create_iris(tmp_path) -> Iris:
    """
    Create a minimal Iris object for unit tests.

    Parameters:
        tmp_path: pytest tmp dir used as the module output dir.

    Returns:
        An Iris instance with mocked dependencies.
    """
    iris = Iris.__new__(Iris)
    iris.db = Mock()
    iris.db.get_wifi_interface.return_value = "wlan0"
    iris.db.get_host_ip.return_value = "192.168.1.5"
    iris.print = Mock()
    iris.output_dir = str(tmp_path / "iris")
    return iris


@pytest.mark.parametrize(
    "user_config",
    [
        {"Redis": {"Host": "10.0.0.1", "Tl2NlChannel": "x"}, "Server": {}},
        {"Identity": {"GenerateNewKey": True}},
        {},
    ],
)
def test_iris_configurator_passes_redis_password(tmp_path, user_config):
    """
    Ensure the runtime iris config carries slips' shared redis
    password and connection details, whatever the user config holds.

    Parameters:
        tmp_path: pytest tmp dir.
        user_config: content of the user's iris config yaml.

    Returns:
        None.
    """
    iris = create_iris(tmp_path)
    user_conf = tmp_path / "iris_config.yaml"
    user_conf.write_text(yaml.dump(user_config))

    with patch(
        "modules.iris.iris.ensure_redis_password", return_value="s3cret"
    ):
        runtime_conf = iris._iris_configurator(str(user_conf), 6379)

    written = yaml.safe_load(open(runtime_conf))
    assert written["Redis"] == {
        "Host": IPV4_LOCALHOST,
        "Port": 6379,
        "Tl2NlChannel": "iris_internal",
        "Password": "s3cret",
    }
    assert written["Server"]["Host"] == "192.168.1.5"
    assert written["Server"]["DhtServerMode"] == "true"
    for key in user_config:
        if key not in ("Redis", "Server"):
            assert written[key] == user_config[key]


def test_iris_configurator_keeps_user_config_untouched(tmp_path):
    """
    Ensure the password goes to a 0600 runtime copy in the output dir
    and the user's tracked iris config is left as is.

    Parameters:
        tmp_path: pytest tmp dir.

    Returns:
        None.
    """
    iris = create_iris(tmp_path)
    user_conf = tmp_path / "iris_config.yaml"
    original = yaml.dump({"Redis": {"Host": "127.0.0.1"}})
    user_conf.write_text(original)

    with patch(
        "modules.iris.iris.ensure_redis_password", return_value="s3cret"
    ):
        runtime_conf = iris._iris_configurator(str(user_conf), 6379)

    assert runtime_conf == os.path.join(iris.output_dir, "iris_config.yaml")
    assert runtime_conf != str(user_conf)
    assert user_conf.read_text() == original
    assert "s3cret" not in user_conf.read_text()
    assert stat.S_IMODE(os.stat(runtime_conf).st_mode) == 0o600


def test_iris_configurator_returns_none_when_config_missing(tmp_path):
    """
    Ensure a missing user config is reported and yields None.

    Parameters:
        tmp_path: pytest tmp dir.

    Returns:
        None.
    """
    iris = create_iris(tmp_path)
    assert iris._iris_configurator(str(tmp_path / "nope.yaml"), 6379) is None
    iris.print.assert_called_once()


def test_pre_main_starts_iris_with_runtime_config(tmp_path):
    """
    Ensure iris is launched with the runtime config path, relative to
    the iris binary dir, not with the user's config.

    Parameters:
        tmp_path: pytest tmp dir.

    Returns:
        None.
    """
    iris = create_iris(tmp_path)
    iris.redis_port = 6379
    runtime_conf = os.path.join(iris.output_dir, "iris_config.yaml")
    iris._iris_configurator = Mock(return_value=runtime_conf)
    iris.get_module_specific_output_path = Mock(
        return_value=str(tmp_path / "iris_logs.txt")
    )

    with (
        patch("modules.iris.iris.ConfigParser") as conf,
        patch("modules.iris.iris.subprocess.Popen") as mock_popen,
    ):
        conf.return_value.get_iris_config_location.return_value = (
            "config/iris_config.yaml"
        )
        iris.pre_main()

    iris._iris_configurator.assert_called_once_with(
        "config/iris_config.yaml", 6379
    )
    command = mock_popen.call_args.args[0]
    assert command[1] == "--conf"
    assert (
        Path(mock_popen.call_args.kwargs["cwd"]) / command[2]
    ).resolve() == (Path(runtime_conf))
    assert not iris.stopFlag
    iris.log_file.close()


@pytest.mark.parametrize(
    "version,kind,expected",
    [
        (1, "nl2tl_alert", True),
        (2, "nl2tl_alert", False),
        (1, "tl2nl_alert", False),
        ("1.1.23", "nl2tl_alert", False),
    ],
)
def test_iris_protocol_version(
    version: object, kind: str, expected: bool
) -> None:
    """Validate external messages using Iris's numeric protocol version.

    Parameters:
        version: Version received from the Go peer.
        kind: Incoming protocol message type.
        expected: Expected acceptance decision.
    """
    iris = ModuleFactory().create_iris_obj()
    message = {
        "channel": "iris_internal",
        "data": json.dumps({"version": version, "type": kind}),
    }
    assert iris.is_msg_version_compatible(message, "iris_internal") is expected


def test_iris_translates_versions_at_protocol_boundary() -> None:
    """Preserve the payload while using each side's own version field."""
    iris = ModuleFactory().create_iris_obj()
    outgoing = {
        "version": iris.slips_version,
        "type": "tl2nl_alert",
        "data": {"payload": "synthetic-test"},
    }
    incoming = {
        "version": 1,
        "type": "nl2tl_alert",
        "data": {"payload": "synthetic-reply"},
    }
    iris.get_msg = Mock(
        side_effect=[
            {"data": json.dumps(outgoing)},
            {"data": json.dumps(incoming)},
        ]
    )
    iris._simplex_duplex_translator()
    calls = iris.db.publish.call_args_list
    assert calls[0].args[0] == "iris_internal"
    assert json.loads(calls[0].args[1]) == {**outgoing, "version": 1}
    assert calls[0].kwargs == {"add_version": False}
    assert calls[1].args == ("network2fides", json.dumps(incoming))


def test_iris_native_binary_keeps_module_working_directory() -> None:
    """Resolve a custom native executable and config from the module cwd."""
    iris = ModuleFactory().create_iris_obj()
    iris._iris_configurator = Mock(return_value="output/iris_config.yaml")
    iris.get_module_specific_output_path = Mock(return_value="iris_logs.txt")
    with (
        patch("modules.iris.iris.ConfigParser") as parser,
        patch("modules.iris.iris.subprocess.Popen") as popen,
        patch("builtins.open"),
    ):
        parser.return_value.read_configuration.return_value = "output/bin/iris"
        parser.return_value.get_iris_config_location.return_value = (
            "config/iris_config.yaml"
        )
        iris.pre_main()
    assert popen.call_args.args[0] == [
        "../../output/bin/iris",
        "--conf",
        "../../output/iris_config.yaml",
    ]
    assert popen.call_args.kwargs["cwd"] == Path("modules/iris")
