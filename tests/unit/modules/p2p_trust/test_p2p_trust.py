# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

import errno
import json
import signal
from types import SimpleNamespace
from unittest.mock import Mock, call, patch

import pytest

from modules.p2p_trust.p2p_trust import Trust
from modules.p2p_trust.utils.utils import get_ip_info_from_slips
from slips_files.common.abstracts.imodule import IModule
from tests.module_factory import ModuleFactory


def create_trust():
    """
    Create a minimal Trust object for unit tests.

    Returns:
        A Trust instance with mocked dependencies.
    """
    trust = Trust.__new__(Trust)
    trust.start_pigeon = True
    trust.args = SimpleNamespace(is_slips_started_by_an_update=False)
    trust.conf = Mock()
    trust.conf.use_local_p2p.return_value = False
    trust.db = Mock()
    trust.print = Mock()
    trust.parent_output_dir = "output"
    trust.pigeon_binary_dir = "p2p4slips"
    trust.pigeon_binary = "p2p4slips/p2p4slips"
    trust.slips_version = "1.2.3"
    return trust


@pytest.mark.parametrize(
    "is_slips_started_by_an_update,use_local_p2p,expected",
    [
        (False, False, False),
        (False, True, False),
        (True, False, False),
        (True, True, True),
    ],
)
def test_should_rebuild_pigeon_binary(
    is_slips_started_by_an_update, use_local_p2p, expected
):
    """
    Ensure the p2p binary rebuild only runs for updated local p2p runs.

    Parameters:
        is_slips_started_by_an_update: Whether Slips was restarted by update.
        use_local_p2p: Whether local p2p is enabled in config.
        expected: Expected rebuild decision.

    Returns:
        None.
    """
    trust = create_trust()
    trust.args.is_slips_started_by_an_update = is_slips_started_by_an_update
    trust.conf.use_local_p2p.return_value = use_local_p2p

    assert trust._should_rebuild_pigeon_binary() is expected


def test_rebuild_pigeon_binary_after_slips_update_runs_go_build():
    """
    Ensure the p2p module rebuilds p2p4slips after a live update.

    Returns:
        None.
    """
    trust = create_trust()
    trust.args.is_slips_started_by_an_update = True
    trust.conf.use_local_p2p.return_value = True

    with patch("modules.p2p_trust.p2p_trust.subprocess.run") as mock_run:
        assert trust._rebuild_pigeon_binary_after_slips_update() is True

    mock_run.assert_called_once_with(
        ["go", "build", "-buildvcs=false"],
        cwd="p2p4slips",
        check=True,
        capture_output=True,
        text=True,
    )
    assert trust.print.call_args_list == [
        call(
            "Rebuilding p2p4slips after Slips update. This can take "
            "some time."
        ),
        call("Done rebuilding p2p4slips after Slips update."),
    ]


def test_rebuild_pigeon_binary_after_slips_update_stops_on_build_error():
    """
    Ensure build failures are reported and stop p2p startup.

    Returns:
        None.
    """
    trust = create_trust()
    trust.args.is_slips_started_by_an_update = True
    trust.conf.use_local_p2p.return_value = True

    with patch(
        "modules.p2p_trust.p2p_trust.subprocess.run",
        side_effect=OSError("go not found"),
    ):
        assert trust._rebuild_pigeon_binary_after_slips_update() is False

    assert trust.print.call_args_list == [
        call(
            "Rebuilding p2p4slips after Slips update. This can take "
            "some time."
        ),
        call(
            "Warning: Failed to rebuild p2p4slips after Slips update. "
            "Error: go not found"
        ),
    ]


def test_start_pigeon_passes_runtime_arguments_to_go():
    """
    Ensure the Go Pigeon process receives the configured runtime arguments.

    Returns:
        None.
    """
    trust = create_trust()
    trust.port = 32769
    trust.host = "172.16.2.4"
    trust.redis_port = 32768
    trust.pygo_channel_raw = "p2p_pygo"
    trust.gopy_channel_raw = "p2p_gopy"
    trust.create_p2p_logfile = False
    trust.p2p_trust_runtime_dir = "permanent/p2p_trust_runtime"
    trust.pigeon_key_file = "pigeon;peer1.keys"
    trust._rebuild_pigeon_binary_after_slips_update = Mock(return_value=True)

    with (
        patch("modules.p2p_trust.p2p_trust.shutil.which", return_value=True),
        patch("modules.p2p_trust.p2p_trust.subprocess.Popen") as mock_popen,
    ):
        trust._start_pigeon()

    executable = mock_popen.call_args.args[0]
    key_index = executable.index("-key-file")
    assert executable[key_index + 1] == "pigeonpeer1.keys"
    assert "--redis-db" in executable
    assert f"localhost:{trust.redis_port}" in executable
    version_index = executable.index("-slips-version")
    assert executable[version_index + 1] == trust.slips_version
    assert mock_popen.call_args.kwargs["cwd"] == "permanent/p2p_trust_runtime"


def test_start_pigeon_rebuilds_and_retries_on_exec_format_error():
    """
    Ensure incompatible p2p4slips binaries are rebuilt and retried.

    Returns:
        None.
    """
    trust = create_trust()
    trust.port = 32769
    trust.host = "172.16.2.4"
    trust.redis_port = 32768
    trust.pygo_channel_raw = "p2p_pygo"
    trust.gopy_channel_raw = "p2p_gopy"
    trust.create_p2p_logfile = False
    trust.p2p_trust_runtime_dir = "permanent/p2p_trust_runtime"
    trust.pigeon_key_file = "pigeon.keys"
    trust._rebuild_pigeon_binary_after_slips_update = Mock(return_value=True)
    trust._build_pigeon_binary = Mock(return_value=True)
    exec_error = OSError(errno.ENOEXEC, "Exec format error")
    pigeon_process = Mock()

    with (
        patch("modules.p2p_trust.p2p_trust.shutil.which", return_value=True),
        patch(
            "modules.p2p_trust.p2p_trust.subprocess.Popen",
            side_effect=[exec_error, pigeon_process],
        ) as mock_popen,
    ):
        trust._start_pigeon()

    assert trust.pigeon == pigeon_process
    assert mock_popen.call_count == 2
    trust._build_pigeon_binary.assert_called_once_with("for this system")
    trust.print.assert_any_call(
        "Warning: p2p4slips binary is not executable on this system. "
        "Trying to rebuild it locally."
    )


def test_start_pigeon_reports_start_errors_without_retry():
    """
    Ensure non-format startup errors are reported without rebuilding.

    Returns:
        None.
    """
    trust = create_trust()
    trust.port = 32769
    trust.host = "172.16.2.4"
    trust.redis_port = 32768
    trust.pygo_channel_raw = "p2p_pygo"
    trust.gopy_channel_raw = "p2p_gopy"
    trust.create_p2p_logfile = False
    trust.p2p_trust_runtime_dir = "permanent/p2p_trust_runtime"
    trust.pigeon_key_file = "pigeon.keys"
    trust._rebuild_pigeon_binary_after_slips_update = Mock(return_value=True)
    trust._build_pigeon_binary = Mock()

    with (
        patch("modules.p2p_trust.p2p_trust.shutil.which", return_value=True),
        patch(
            "modules.p2p_trust.p2p_trust.subprocess.Popen",
            side_effect=OSError(errno.EACCES, "Permission denied"),
        ) as mock_popen,
    ):
        trust._start_pigeon()

    assert trust.pigeon is None
    mock_popen.assert_called_once()
    trust._build_pigeon_binary.assert_not_called()
    trust.print.assert_any_call(
        "Warning: Failed to start p2p4slips. Error: "
        "[Errno 13] Permission denied"
    )


@pytest.mark.parametrize(
    "ip_info",
    [
        {},
        {"score": None, "confidence": 0.8},
        {"score": "invalid", "confidence": 0.8},
        {"score": 0.5},
        {"score": 0.5, "confidence": None},
        {"score": 0.5, "confidence": "invalid"},
        {"threat_level": "invalid", "confidence": 0.8},
    ],
)
def test_get_ip_info_rejects_missing_or_malformed_values(
    ip_info: dict,
) -> None:
    """
    Return no opinion when a stored score or confidence cannot be converted.

    Parameters:
        ip_info: Simulated IP metadata returned by Redis.
    """
    module_factory = ModuleFactory()
    db = module_factory.create_go_director_obj().db
    db.get_ip_info.side_effect = lambda _ip, field: ip_info.get(field)

    assert get_ip_info_from_slips("192.0.2.1", db) == (None, None)


def test_main_continues_after_one_malformed_gopy_message() -> None:
    """Process the next Go message after one malformed message is ignored."""
    module_factory = ModuleFactory()
    trust = create_trust()
    trust.logger = module_factory.logger
    trust.create_p2p_logfile = False
    trust.p2p_data_request_channel = "p2p_data_request"
    trust.gopy_channel = "p2p_gopy"
    trust.pigeon = Mock()
    trust.pigeon.poll.return_value = None
    trust.mutliaddress_printed = True
    valid_data = {
        "message_type": "peer_update",
        "message_contents": {"peerid": "peer-1"},
    }
    trust.get_msg = Mock(
        side_effect=[
            None,
            None,
            {"data": "malformed"},
            None,
            None,
            {"data": json.dumps(valid_data)},
        ]
    )
    trust.go_director = Mock()
    trust.gopy_callback = Mock(wraps=trust.gopy_callback)

    trust.main()
    trust.main()

    assert trust.gopy_callback.call_count == 2
    trust.go_director.handle_gopy_data.assert_called_once_with(valid_data)
    warning = trust.print.call_args.args
    assert warning[0].startswith(
        "Warning: Ignoring malformed p2p_gopy message after processing failed:"
    )
    assert warning[1:] == (0, 1)


def test_stop_pigeon_waits_for_child_exit() -> None:
    """Signal the Go child and wait for it before clearing the process handle."""
    module_factory = ModuleFactory()
    trust = create_trust()
    trust.logger = module_factory.logger
    trust.pigeon = Mock()
    trust.pigeon.poll.return_value = None
    pigeon = trust.pigeon

    trust._stop_pigeon()

    pigeon.send_signal.assert_called_once_with(signal.SIGINT)
    pigeon.wait.assert_called_once_with(timeout=5)
    assert trust.pigeon is None


def test_run_stops_pigeon_after_unexpected_module_exit() -> None:
    """Stop the Go child even when the common module runner exits on error."""
    module_factory = ModuleFactory()
    trust = create_trust()
    trust.logger = module_factory.logger
    trust._stop_pigeon = Mock()

    with patch.object(IModule, "run", side_effect=RuntimeError("boom")):
        with pytest.raises(RuntimeError, match="boom"):
            trust.run()

    trust._stop_pigeon.assert_called_once_with()
