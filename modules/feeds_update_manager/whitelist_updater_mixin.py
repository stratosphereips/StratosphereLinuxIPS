# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>

# SPDX-License-Identifier: GPL-2.0-only


import os

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

        if not self.db.is_tranco_whitelist_expired():
            # tranco whitelist not expired yet
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
        response = self.responses["mac_db"]
        if response.status_code != 200:
            return False

        self.log("Updating the MAC database.")

        # write to file the info as 1 json per line
        mac_info = (
            response.text.replace("]", "")
            .replace("[", "")
            .replace(",{", "\n{")
        )
        with open(self.path_to_mac_db, "w") as mac_db:
            mac_db.write(mac_info)

        self._mark_feed_as_updated(self.mac_db_link)
        return True

    def _update_online_whitelist(self):
        """
        Updates online tranco whitelist defined in slips.yaml
         online_whitelist key
        """
        # delete the old ones
        self.db.delete_tranco_whitelist()
        response = self.responses["tranco_whitelist"]
        domains = []
        for line in response.text.splitlines():
            domain = line.split(",")[1].strip()
            domains.append(domain)
        self.db.store_tranco_whitelisted_domains(
            domains, ttl=self.online_whitelist_update_period
        )

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
