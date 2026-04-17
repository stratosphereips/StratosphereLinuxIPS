# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only


"""
Handles updating of slips version
"""

import json
import re
import time
from typing import Any, Dict, Optional
from urllib import error, request

from git import InvalidGitRepositoryError, NoSuchPathError, Repo
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.core.database.database_manager import DBManager


class UpdateManager:
    def __init__(self, db: DBManager = None, is_slips_live_updating=None):
        self.db = db
        self.is_slips_live_updating = is_slips_live_updating
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
        latest_version = bool(update_data.get("version", False))

        if not latest_version:
            return False

        current_version = open("VERSION").read().strip()
        return current_version == latest_version

    def update_slips(self):
        # if self.is_first_run:
        #     # we're not live updating, there isnt going to be an older
        #     # version of slips draining in this case.
        #     ...
        # else:
        #     # prep for handover. old version to the new one.
        #     ...
        # self.is_slips_live_updating.set()
        ...

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
            return self.should_update_slips()
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
