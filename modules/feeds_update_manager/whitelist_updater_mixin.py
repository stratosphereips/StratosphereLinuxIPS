# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>

# SPDX-License-Identifier: GPL-2.0-only


import contextlib
import os

import requests

from modules.feeds_update_manager.remote_feed_updater_mixin import CHUNK_SIZE
from slips_files.common.slips_utils import utils


class WhitelistUpdaterMixin:
    """Update whitelist, organization, and MAC database feeds."""

    def should_update_online_whitelist(self) -> bool:
        """
        Decides whether to update or not based on the update period
        Used for online whitelist specified in slips.conf
        """
        if not self.enable_online_whitelist:
            return False

        if not self._did_update_period_pass(
            self.online_whitelist_update_period,
            "tranco_whitelist",
        ):
            self.loaded_ti_files += 1
            return False

        # update period passed
        # response will be used to get e-tag, and if the file was updated
        # the same response will be used to update the content in our db
        response = self.download_file(self.online_whitelist)
        if not response:
            return False

        self.responses["tranco_whitelist"] = response
        return True

    def _is_mac_db_file_on_disk(self) -> bool:
        """checks if the mac db is present in databases/"""
        return os.path.isfile(self.path_to_mac_db)

    def check_if_update_org(self, file):
        """checks if we should update organizations' info
        based on the hash of thegiven file"""
        cached_hash = self.db.get_ti_feed_info(file).get("hash", "")
        if utils.get_sha256_hash_of_file_contents(file) != cached_hash:
            return True

    def get_whitelisted_orgs(self) -> list:

        whitelisted_orgs: dict = self.db.get_whitelist("organizations")
        whitelisted_orgs: list = list(whitelisted_orgs.keys())
        return whitelisted_orgs

    def update_local_whitelist(self):
        """
        parses the local whitelist using the whitelist
         parser and stores it in the db
         is only called when slips starts.
        """
        if self.enable_local_whitelist:
            self.whitelist.update()

    def update_org_files(self):
        """
        This func handles organizations whitelist files.
        It updates the local IoCs of every supported organization in the db
        and initializes the bloom filters
        """
        for org in utils.supported_orgs:
            org_ips = os.path.join(self.org_info_path, f"{org}_ip_ranges")
            org_asn = os.path.join(self.org_info_path, f"{org}_asn")
            org_domains = os.path.join(self.org_info_path, f"{org}_domains")

            if self.check_if_update_org(org_ips):
                self.whitelist.parser.load_org_ips(org)

            if self.check_if_update_org(org_domains):
                self.whitelist.parser.load_org_domains(org)

            if self.check_if_update_org(org_asn):
                self.whitelist.parser.load_org_asn(org)

            for file in (org_ips, org_domains, org_asn):
                info = {
                    "hash": utils.get_sha256_hash_of_file_contents(file),
                }
                self._mark_feed_as_updated(file, info)

    def update_mac_db(self):
        """
        Updates the mac db using the response stored in self.responses
        """
        response = self.responses.pop("mac_db")
        with response:
            if response.status_code != 200:
                return False

            self.log("Updating the MAC database.")
            try:
                self._write_mac_db(response)
            except requests.exceptions.RequestException as e:
                self.log(f"Error downloading the MAC database: {e}")
                return False

        self._mark_feed_as_updated(self.mac_db_link)
        return True

    def _write_mac_db(self, response) -> None:
        """
        Streams the mac db to disk as 1 json per line. It is written to a
        temp file first so a failed download never corrupts the current db.
        """
        tmp_path = f"{self.path_to_mac_db}.tmp"
        try:
            with open(tmp_path, "wb") as mac_db:
                # a ",{" separator may be split between 2 chunks, so a
                # trailing "," is held back until the next chunk arrives
                pending = b""
                for chunk in response.iter_content(chunk_size=CHUNK_SIZE):
                    data = pending + chunk
                    pending = b"," if data.endswith(b",") else b""
                    if pending:
                        data = data[:-1]
                    mac_db.write(
                        data.replace(b"]", b"")
                        .replace(b"[", b"")
                        .replace(b",{", b"\n{")
                    )
                mac_db.write(pending)
            os.replace(tmp_path, self.path_to_mac_db)
        except Exception:
            with contextlib.suppress(FileNotFoundError):
                os.remove(tmp_path)
            raise

    def _update_online_whitelist(self) -> None:
        """
        Updates online tranco whitelist defined in slips.yaml
         online_whitelist key
        """
        response = self.responses.pop("tranco_whitelist")
        domains = []
        try:
            with response:
                for raw_line in response.iter_lines():
                    parts = raw_line.decode("utf-8", errors="replace").split(
                        ",", 1
                    )
                    if len(parts) != 2:
                        continue
                    domain = parts[1].strip().lower()
                    if not utils.is_valid_domain(domain):
                        continue
                    domains.append(domain)
        except requests.exceptions.RequestException as e:
            self.log(f"Error downloading the tranco whitelist: {e}")
            return

        self.db.store_tranco_whitelisted_domains(domains)

        self._mark_feed_as_updated("tranco_whitelist")

    def _download_mac_db(self):
        """
        saves the mac db response to self.responses
        """
        response = self.download_file(self.mac_db_link)
        if not response:
            return False

        self.responses["mac_db"] = response
        return True

    def _should_update_mac_db(self) -> bool:
        """
        checks whether or not slips should download the mac db based on
        its availability on disk and the update period

        the response will be stored in self.responses if the file is old
        and needs to be updated
        """
        if not self._is_mac_db_file_on_disk():
            # whether the period passed or not, the db needs to be
            # re-downloaded
            return self._download_mac_db()

        if not self._did_update_period_pass(
            self.mac_db_update_period, self.mac_db_link
        ):
            # Update period hasn't passed yet, the file is on disk and
            # up to date
            self.loaded_ti_files += 1
            return False

        return self._download_mac_db()
