# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

from types import SimpleNamespace
from unittest.mock import Mock, call, patch

import pytest

from modules.p2p_trust.p2p_trust import Trust


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
        ["go", "build"],
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
    assert mock_popen.call_args.kwargs["cwd"] == "permanent/p2p_trust_runtime"
