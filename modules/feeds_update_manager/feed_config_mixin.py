# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>

# SPDX-License-Identifier: GPL-2.0-only


import os
from typing import Dict

from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils


class FeedConfigMixin:
    """Read feed update configuration and feed metadata."""

    def _read_riskiq_creds(self, risk_iq_credentials_path: str) -> None:
        """
        Read RiskIQ credentials from the configured relative path.

        :param risk_iq_credentials_path: path to the RiskIQ credentials file
        """
        self.riskiq_email = None
        self.riskiq_key = None

        if not risk_iq_credentials_path:
            return

        if not os.path.exists(risk_iq_credentials_path):
            return

        with open(risk_iq_credentials_path, "r") as f:
            self.riskiq_email = f.readline().replace("\n", "")
            self.riskiq_key = f.readline().replace("\n", "")

    def read_configuration(self):
        """
        Read feed update configuration and cache it on the manager instance.
        """
        conf = ConfigParser()

        self.update_period = conf.update_period()

        self.path_to_remote_ti_files_dir = conf.remote_ti_data_path()
        if not os.path.exists(self.path_to_remote_ti_files_dir):
            os.makedirs(self.path_to_remote_ti_files_dir, exist_ok=True)
            # only owner can r/w/x
            os.chmod(self.path_to_remote_ti_files_dir, 0o700)

        self.ti_feeds_path = conf.ti_files()
        self.url_feeds = self.get_feed_details(self.ti_feeds_path)
        self.ja3_feeds_path = conf.ja3_feeds()
        self.ja3_feeds = self.get_feed_details(self.ja3_feeds_path)

        self.ssl_feeds_path = conf.ssl_feeds()
        self.ssl_feeds = self.get_feed_details(self.ssl_feeds_path)
        self.tor_nodes_feed_link = (
            "https://check.torproject.org/torbulkexitlist"
        )
        self.tor_nodes_feeds = {self.tor_nodes_feed_link: {}}
        risk_iq_credentials_path = conf.RiskIQ_credentials_path()
        self._read_riskiq_creds(risk_iq_credentials_path)
        self.riskiq_update_period = conf.riskiq_update_period()

        self.mac_db_update_period = conf.mac_db_update_period()
        self.mac_db_link = conf.mac_db_link()

        self.online_whitelist_update_period = (
            conf.online_whitelist_update_period()
        )
        self.online_whitelist = conf.online_whitelist()
        self.enable_online_whitelist: bool = conf.enable_online_whitelist()
        self.enable_local_whitelist: bool = conf.enable_local_whitelist()

    def get_feed_details(self, feeds_path) -> Dict[str, Dict[str, str]]:
        """
        Parse links, threat level and tags from the given feeds_path file and
        return
         a dict with feed info
        """
        try:
            with open(feeds_path, "r") as feeds_file:
                feeds: str = feeds_file.read()
        except FileNotFoundError:
            self.print(
                f"Error finding {feeds_path}. Feed won't be added to slips."
            )
            return {}

        # this dict will contain every link and its threat_level
        parsed_feeds = {}

        for line in feeds.splitlines():
            if line.startswith("#"):
                continue
            # remove all spaces
            line = line.strip().replace(" ", "")
            # each line is https://abc.d/e,medium,['tag1','tag2']
            line = line.split(",")
            url, threat_level = line[0], line[1]
            tags: str = " ".join(line[2:])
            tags = (
                tags.replace("[", "")
                .replace("]", "")
                .replace("'", "")
                .replace('"', "")
                .split(",")
            )
            url = utils.sanitize(url.strip())

            threat_level = threat_level.lower()
            # remove commented lines from the cache db
            if url.startswith(";"):
                feed = url.split("/")[-1]
                if self.db.get_ti_feed_info(feed):
                    self.db.delete_feed_entries(feed)
                    # to avoid calling delete_feed again with the same feed
                    self.db.delete_ti_feed(feed)
                continue

            # make sure the given tl is valid
            if not utils.is_valid_threat_level(threat_level):
                # not a valid threat_level
                self.print(
                    f"Invalid threat level found in slips.conf: {threat_level} "
                    f"for TI feed: {url}. Using 'low' instead.",
                    0,
                    1,
                )
                threat_level = "low"

            parsed_feeds[url] = {"threat_level": threat_level, "tags": tags}
        return parsed_feeds
