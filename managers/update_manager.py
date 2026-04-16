# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only


"""
Handles updating of slips version
"""

import json
import re
from typing import Any, Dict, Optional
from urllib import error, request

from git import InvalidGitRepositoryError, NoSuchPathError, Repo
from slips_files.common.parsers.config_parser import ConfigParser


class UpdateManager:
    def __init__(self, is_first_run: bool):
        self.read_configuration()
        self.is_first_run = is_first_run
        self.cached_update_info: Optional[Dict[str, Any]] = None

    def read_configuration(self):
        conf = ConfigParser()
        self.update_slips = conf.auto_update_slips()

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
        Read the update.json metadata from the origin/master branch.

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

    def new_version_has_new_dependencies(self) -> bool:
        """
        Check whether the version on master introduces new dependencies.

        Returns:
            True if update.json reports new dependencies or the metadata
            cannot be read safely, otherwise False.
        """
        update_data = self._read_master_update_json()
        return bool(update_data.get("has_new_dependencies", True))

    def new_version_is_backwards_compatible(self) -> bool:
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

    def _update_slips_version(self):
        if self.is_first_run:
            # we're not live updating, there isnt going to be an older
            # version of slips draining in this case.
            ...
        else:
            # prep for handover. old version to the new one.
            ...

    def should_update_slips(self) -> bool:
        if not self.update_slips:
            return False

        # Never live update when analyzing anything other than an interface
        # If  not running on interface: return false
        # return (new_version_available() and
        #         new_version_supports_backwards_compatibility()):
