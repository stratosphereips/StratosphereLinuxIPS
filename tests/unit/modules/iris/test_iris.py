"""Verify the boundary between Slips messages and the Iris Go protocol."""

import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from tests.module_factory import ModuleFactory


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
    assert iris.is_msg_version_compatible(message) is expected


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
    iris._iris_configurator = Mock(return_value=9010)
    iris.get_module_specific_output_path = Mock(return_value="iris_logs.txt")
    with patch("modules.iris.iris.ConfigParser") as parser, patch(
        "modules.iris.iris.subprocess.Popen"
    ) as popen, patch("builtins.open"):
        parser.return_value.read_configuration.return_value = "output/bin/iris"
        parser.return_value.get_iris_config_location.return_value = (
            "config/iris_config.yaml"
        )
        iris.pre_main()
    assert popen.call_args.args[0] == [
        "../../output/bin/iris",
        "--conf",
        "../../config/iris_config.yaml",
    ]
    assert popen.call_args.kwargs["cwd"] == Path("modules/iris")
