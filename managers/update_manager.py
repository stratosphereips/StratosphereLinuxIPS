# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only


"""
Handles updating of slips version
"""

import json
import re
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional
from urllib import error, request

import psutil
from git import (
    GitCommandError,
    InvalidGitRepositoryError,
    NoSuchPathError,
    Repo,
)
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from slips_files.core.database.database_manager import DBManager


class UpdateManager:
    def __init__(
        self,
        database: DBManager = None,
        is_slips_live_updating_event=None,
        print_func=None,
    ):
        self.db = database
        self.is_slips_live_updating_event = is_slips_live_updating_event
        self.is_running_non_stop: bool = self.db.is_running_non_stop()
        self.cached_update_info: Optional[Dict[str, Any]] = None
        self.conf = ConfigParser()
        self.args = self.conf.get_args()
        # The very first time, slips is started by the user via CLI. then
        # for each new update, it's started by this update manager.
        # this func returns true if the user just started slips from cli.
        self.is_first_run: bool = (
            True if not self.args.is_slips_started_by_an_update else False
        )
        self._read_configuration()
        self.last_update_time = 0
        self.print = print_func

    def _read_configuration(self):
        self.auto_update_slips_enabled = self.conf.auto_update_slips()

    def _get_master_update_json_link(self) -> Optional[str]:
        """
        Build the raw GitHub URL for update.json on the master branch.

        Returns:
            The raw update.json URL if the origin remote is supported,
            otherwise None.
        """
        try:
            remote_url = Repo(".").remote("origin").url
        except (ValueError, InvalidGitRepositoryError, NoSuchPathError):
            return None

        remote_url = remote_url.strip().removesuffix(".git").rstrip("/")
        github_prefixes = (
            "https://github.com/",
            "http://github.com/",
            "ssh://git@github.com/",
        )

        repo_path = None
        if remote_url.startswith("git@github.com:"):
            repo_path = remote_url.split(":", maxsplit=1)[1]
        else:
            for prefix in github_prefixes:
                if remote_url.startswith(prefix):
                    repo_path = remote_url.removeprefix(prefix)
                    break

        if not repo_path:
            return None

        return (
            f"https://raw.githubusercontent.com/{repo_path}/master/update.json"
        )

    def _read_master_update_json(self) -> Dict[str, Any]:
        """
        Read the update.json file from the origin/master branch of slips repo.

        Returns:
            Parsed update metadata if it can be fetched and decoded,
            otherwise an empty dictionary.
        """
        if self.cached_update_info is not None:
            return self.cached_update_info

        update_json_link = self._get_master_update_json_link()
        if not update_json_link:
            self.cached_update_info = {}
            return self.cached_update_info

        try:
            with request.urlopen(update_json_link, timeout=5) as response:
                update_text = response.read().decode("utf-8")
        except (OSError, UnicodeDecodeError, error.URLError):
            self.cached_update_info = {}
            return self.cached_update_info

        sanitized_update_text = re.sub(r",(\s*[}\]])", r"\1", update_text)
        try:
            update_data = json.loads(sanitized_update_text)
        except json.JSONDecodeError:
            self.cached_update_info = {}
            return self.cached_update_info

        self.cached_update_info = (
            update_data if isinstance(update_data, dict) else {}
        )
        return self.cached_update_info

    def _new_version_has_new_dependencies(self) -> bool:
        """
        Check whether the version on master introduces new dependencies.

        Returns:
            True if update.json reports new dependencies or the metadata
            cannot be read safely, otherwise False.
        """
        update_data = self._read_master_update_json()
        return bool(update_data.get("has_new_dependencies", True))

    def _is_new_version_backwards_compatible(self) -> bool:
        """
        Check whether the version on master is backwards compatible.

        Returns:
            True if update.json marks the update as backwards compatible,
            otherwise False.
        """
        update_data = self._read_master_update_json()
        return bool(update_data.get("backwards_compatible", False))

    def _is_new_version_available(self) -> bool:
        update_data = self._read_master_update_json()
        latest_version = update_data.get("version", False)

        if not latest_version:
            return False

        return utils.get_current_version() != latest_version

    def git_pull_master(self):
        """
        Pull the latest origin/master changes and check them out.

        Returns:
            The checked out origin/master commit.
        """
        repo = Repo(".")
        repo.remote("origin").fetch("master")
        repo.git.checkout("origin/master")
        return repo.head.commit

    def _get_checkout_overwritten_files(
        self, git_error: GitCommandError
    ) -> List[str]:
        """
        Extract files Git says would be overwritten by checkout.
        we'll just print them to the user.

        Parameters:
            git_error: The GitPython checkout failure.

        Returns:
            The local paths reported by Git, or an empty list if this is not
            a local-change checkout conflict.
        """
        stderr = getattr(git_error, "stderr", "") or str(git_error)
        if (
            "Your local changes to the following files would be "
            "overwritten by checkout" not in stderr
        ):
            return []

        files = []
        is_file_list = False
        for line in stderr.splitlines():
            stripped_line = line.strip().strip("'")
            if (
                "Your local changes to the following files would be "
                "overwritten by checkout" in stripped_line
            ):
                is_file_list = True
                continue

            if not is_file_list:
                continue

            if stripped_line.startswith(("Please commit", "Aborting")):
                break

            if stripped_line:
                files.append(stripped_line)

        return files

    def _get_target_update_version(self) -> Optional[str]:
        """
        Get the target Slips version from cached update metadata.

        Returns:
            The update version if known, otherwise None.
        """
        update_data = (
            self.cached_update_info or self._read_master_update_json()
        )
        version = update_data.get("version")
        return version if isinstance(version, str) and version else None

    def _get_updated_slips_command(self) -> List[str]:
        """
        Build the command used to start the updated Slips process.

        Returns:
            The current Slips cmd plus (-u). If the current Slips was
            started with -m, pass the current Redis port explicitly so the
            updated process reuses it.
        """
        try:
            cmd = psutil.Process().cmdline()
        except psutil.Error:
            cmd = []

        if not cmd:
            cmd = [sys.executable, *sys.argv]

        cmd = [*cmd, "-u"]

        if self.args.multiinstance:
            cmd.remove("-m")
            redis_port = self.db.get_used_redis_port()
            cmd.extend(["-P", str(redis_port)])

        return cmd

    def start_updated_slips_version(self) -> subprocess.Popen:
        """
        Starts the updated Slips as an independent process.

        Returns:
            The detached process handle for the updated Slips process.
        """
        cmd: List[str] = self._get_updated_slips_command()

        str_cmd = " ".join(cmd)
        self.print(f"Starting updated Slips version using command: {str_cmd}")

        # without dev/null redirection, the new updated slips will use the
        # same cli as the old slips. so this is intentional.
        process = subprocess.Popen(
            cmd,
            close_fds=True,
        )

        self.print("Done starting the updated Slips version.")
        return process

    def _warn_about_aborted_update(
        self, git_error: Optional[GitCommandError] = None
    ):
        overwritten_files = self._get_checkout_overwritten_files(git_error)
        if not overwritten_files:
            raise

        target_version = self._get_target_update_version()
        update_target = (
            f"Slips v{target_version}"
            if target_version
            else "the new Slips version"
        )
        self.print(
            f"Warning: Uncommitted changes to {overwritten_files} detected. "
            f"Aborting update to {update_target}, please update Slips "
            "manually."
        )

    def update_slips(self):
        try:
            self.git_pull_master()
        except GitCommandError as git_error:
            self._warn_about_aborted_update(git_error)
            return

        self.start_updated_slips_version()
        # this event
        # - signals input.py to stop recving input and start draining flows
        # - and signals the process_manager() to call shutdown_gracefully()
        self.is_slips_live_updating_event.set()

    def _did_1d_pass_since_last_update(self) -> bool:
        """
        returns true once every 1 day.
        """
        update_interval = 60 * 60 * 24
        if time.time() >= self.last_update_time + update_interval:
            self.last_update_time = time.time()
            return True
        return False

    def check_for_update_every_1_day(self) -> bool:
        """
        return sTrue if a new compatible version is available and slips
        should update itself
        """
        if self._did_1d_pass_since_last_update():
            should_update: bool = self.should_update_slips()
            # @@@@@@@@@@@@@@@@@@@@@@
            should_update = True

            if should_update:
                self.print(
                    "A new version of Slips is available. "
                    "Updating slips now."
                )
            else:
                self.print(
                    "No new version of Slips is available. "
                    "Slips will check again after 1 day."
                )
            return should_update
        return False

    def should_update_slips(self) -> bool:
        """
        returns true if the auto_update param in the config file is set to
        true, and we're running on an interface, and there is a new
        compatible version of slips.
        """
        if not self.auto_update_slips_enabled:
            return False

        if not self.is_running_non_stop:
            # only update slips when running on an interface.
            return False

        if not self._is_new_version_available():
            return False

        if (
            self._is_new_version_backwards_compatible()
            and not self._new_version_has_new_dependencies()
        ):
            return True

        return False
