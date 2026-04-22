# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import subprocess
from unittest.mock import Mock, patch

import pytest
from git import GitCommandError

from managers.update_manager import UpdateManager


def create_update_manager():
    """
    Create an UpdateManager with mocked external dependencies.

    Returns:
        UpdateManager instance for unit tests.
    """
    db = Mock()
    db.is_running_non_stop.return_value = True

    conf = Mock()
    conf.get_args.return_value = Mock(is_slips_started_by_an_update=False)
    conf.auto_update_slips.return_value = True

    with patch("managers.update_manager.ConfigParser", return_value=conf):
        return UpdateManager(
            database=db,
            is_slips_live_updating_event=Mock(),
            print_func=Mock(),
        )


@pytest.mark.parametrize(
    "remote_url, expected_link",
    [
        (
            "https://github.com/stratosphereips/StratosphereLinuxIPS.git",
            "https://raw.githubusercontent.com/stratosphereips/"
            "StratosphereLinuxIPS/master/update.json",
        ),
        (
            "git@github.com:stratosphereips/StratosphereLinuxIPS.git",
            "https://raw.githubusercontent.com/stratosphereips/"
            "StratosphereLinuxIPS/master/update.json",
        ),
        ("https://example.com/stratosphereips/StratosphereLinuxIPS.git", None),
    ],
)
def test_get_master_update_json_link(remote_url, expected_link):
    update_manager = create_update_manager()
    repo = Mock()
    repo.remote.return_value.url = remote_url

    with patch("managers.update_manager.Repo", return_value=repo):
        assert update_manager._get_master_update_json_link() == expected_link


@pytest.mark.parametrize(
    "update_json, expected_dependencies, expected_compatibility",
    [
        (
            '{"has_new_dependencies": true, "backwards_compatible": false}',
            True,
            False,
        ),
        (
            "{\n"
            '  "has_new_dependencies": false,\n'
            '  "backwards_compatible": true,\n'
            "}\n",
            False,
            True,
        ),
    ],
)
def test_update_json_flags(
    update_json, expected_dependencies, expected_compatibility
):
    update_manager = create_update_manager()
    response = Mock()
    response.read.return_value = update_json.encode("utf-8")
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=None)

    with patch.object(
        update_manager,
        "_get_master_update_json_link",
        return_value=(
            "https://raw.githubusercontent.com/org/repo/master/update.json"
        ),
    ), patch(
        "managers.update_manager.request.urlopen", return_value=response
    ) as mock_urlopen:
        assert (
            update_manager._new_version_has_new_dependencies()
            == expected_dependencies
        )
        assert (
            update_manager._is_new_version_backwards_compatible()
            == expected_compatibility
        )
        mock_urlopen.assert_called_once()


@pytest.mark.parametrize(
    "update_payload, expected_dependencies, expected_compatibility",
    [
        (None, True, False),
        ("not-json", True, False),
    ],
)
def test_update_json_fallbacks(
    update_payload,
    expected_dependencies,
    expected_compatibility,
):
    update_manager = create_update_manager()

    patches = [
        patch.object(
            update_manager,
            "_get_master_update_json_link",
            return_value=(
                "https://raw.githubusercontent.com/org/repo/master/update.json"
            ),
        )
    ]

    if update_payload is None:
        patches.append(
            patch(
                "managers.update_manager.request.urlopen",
                side_effect=OSError("network error"),
            )
        )
    else:
        response = Mock()
        response.read.return_value = update_payload.encode("utf-8")
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=None)
        patches.append(
            patch(
                "managers.update_manager.request.urlopen",
                return_value=response,
            )
        )

    with patches[0], patches[1]:
        assert (
            update_manager._new_version_has_new_dependencies()
            == expected_dependencies
        )
        assert (
            update_manager._is_new_version_backwards_compatible()
            == expected_compatibility
        )


def test_get_updated_slips_command_appends_update_flag():
    update_manager = create_update_manager()
    process = Mock()
    process.cmdline.return_value = ["python3", "slips.py", "-i", "eth0"]

    with patch("managers.update_manager.psutil.Process", return_value=process):
        assert update_manager._get_updated_slips_command() == [
            "python3",
            "slips.py",
            "-i",
            "eth0",
            "-u",
        ]


def test_start_updated_slips_verison_starts_detached_process():
    update_manager = create_update_manager()
    update_manager._get_updated_slips_command = Mock(
        return_value=["python3", "slips.py", "-i", "eth0", "-u"]
    )

    with patch("managers.update_manager.subprocess.Popen") as popen:
        process = update_manager.start_updated_slips_version()

    assert process == popen.return_value
    popen.assert_called_once_with(
        ["python3", "slips.py", "-i", "eth0", "-u"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
    )


def test_update_slips_starts_updated_process_before_stopping_current_slips():
    update_manager = create_update_manager()
    calls = []
    update_manager.git_pull_master = Mock(
        side_effect=lambda: calls.append("git_pull_master")
    )
    update_manager.start_updated_slips_version = Mock(
        side_effect=lambda: calls.append("start_updated_slips_verison")
    )
    update_manager.is_slips_live_updating_event.set = Mock(
        side_effect=lambda: calls.append("set_update_event")
    )

    update_manager.update_slips()

    update_manager.git_pull_master.assert_called_once()
    update_manager.start_updated_slips_version.assert_called_once()
    update_manager.is_slips_live_updating_event.set.assert_called_once()
    assert calls == [
        "git_pull_master",
        "start_updated_slips_verison",
        "set_update_event",
    ]


def test_update_slips_aborts_when_local_changes_block_checkout():
    """
    Ensure local checkout conflicts abort the update without stopping Slips.

    Returns:
        None.
    """
    update_manager = create_update_manager()
    update_manager.cached_update_info = {"version": "1.2.3"}
    git_error = GitCommandError(
        "git checkout origin/master",
        1,
        stderr=(
            "error: Your local changes to the following files would be "
            "overwritten by checkout:\n"
            "\tconfig/slips.yaml\n"
            "Please commit your changes or stash them before you switch "
            "branches.\n"
            "Aborting"
        ),
    )
    update_manager.git_pull_master = Mock(side_effect=git_error)
    update_manager.start_updated_slips_version = Mock()

    update_manager.update_slips()

    update_manager.git_pull_master.assert_called_once()
    update_manager.start_updated_slips_version.assert_not_called()
    update_manager.is_slips_live_updating_event.set.assert_not_called()
    update_manager.print.assert_called_once_with(
        "Uncommitted changes to ['config/slips.yaml'] detected. "
        "Aborting update to Slips v1.2.3, please update Slips manually."
    )


def test_update_slips_reraises_unrelated_git_errors():
    """
    Ensure unexpected git failures are not hidden by the update manager.

    Returns:
        None.
    """
    update_manager = create_update_manager()
    git_error = GitCommandError(
        "git checkout origin/master",
        128,
        stderr="fatal: not a git repository",
    )
    update_manager.git_pull_master = Mock(side_effect=git_error)
    update_manager.start_updated_slips_version = Mock()

    with pytest.raises(GitCommandError):
        update_manager.update_slips()

    update_manager.start_updated_slips_version.assert_not_called()
    update_manager.is_slips_live_updating_event.set.assert_not_called()
