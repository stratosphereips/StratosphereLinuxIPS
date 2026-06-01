# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import asyncio
from asyncio import Task
from typing import Dict

from exclusiveprocess import (
    Lock,
    CannotAcquireLock,
)

from modules.feeds_update_manager.feed_config_mixin import FeedConfigMixin
from modules.feeds_update_manager.feed_update_policy_mixin import (
    FeedUpdatePolicyMixin,
)
from modules.feeds_update_manager.fingerprint_feed_parser_mixin import (
    FingerprintFeedParserMixin,
)
from modules.feeds_update_manager.local_feed_updater_mixin import (
    LocalFeedUpdaterMixin,
)
from modules.feeds_update_manager.remote_feed_updater_mixin import (
    RemoteFeedUpdaterMixin,
)
from modules.feeds_update_manager.ti_feed_parser_mixin import (
    TIFeedParserMixin,
)
from modules.feeds_update_manager.whitelist_updater_mixin import (
    WhitelistUpdaterMixin,
)
from slips_files.common.timer_manager import PeriodicUpdateTimer
from slips_files.common.abstracts.imodule import IModule
from slips_files.core.helpers.whitelist.whitelist import Whitelist


class FeedsUpdateManager(
    FeedConfigMixin,
    FeedUpdatePolicyMixin,
    FingerprintFeedParserMixin,
    LocalFeedUpdaterMixin,
    RemoteFeedUpdaterMixin,
    TIFeedParserMixin,
    WhitelistUpdaterMixin,
    IModule,
):

    name = "feeds_update_manager"

    description = "Update Threat Intelligence feeds"

    authors = ["Kamila Babayeva", "Alya Gomaa"]

    def init(self):
        self.read_configuration()
        self.update_timer = PeriodicUpdateTimer(
            (
                self.update_period,
                self.mac_db_update_period,
                self.online_whitelist_update_period,
            ),
            self.update_ti_files,
        )

        self.read_configuration()
        self.loaded_ti_files = 0
        # don't store iocs older than 1 week
        self.max_days_to_keep_ti_files = 7
        self.whitelist = Whitelist(self.logger, self.db, self.bloom_filters)
        self.slips_logfile = self.db.get_stdfile("stdout")
        self.org_info_path = "slips_files/organizations_info/"
        self.path_to_mac_db = "databases/macaddress-db.json"
        # if any keyword of the following is present in a line
        # then this line should be ignored by slips
        # either a not supported ioc type or a header line etc.
        # make sure the header keywords are lowercase because
        # we convert lines to lowercase when comparing
        self.header_keywords = (
            "type",
            "first_seen_utc",
            "ip_v4",
            '"domain"',
            '#"type"',
            "#fields",
            "number",
            "atom_type",
            "attacker",
            "score",
        )
        self.ignored_IoCs = ("email", "url", "file_hash", "file")
        # to track how many times an ip is present in different blacklists
        self.ips_ctr = {}
        self.first_time_reading_files = False
        # store the responses of the files that should be updated when their
        # update period passed
        self.responses = {}

    def subscribe_to_channels(self):
        self.channels = {}

    def log(self, text):
        """
        sends the text to output process to log it to slips.log without
         printing to the cli
        """
        self.print(text, verbose=0, debug=1, log_to_logfiles_only=True)

    def _handle_task_exception(self, task):
        try:
            exception = task.exception()
        except asyncio.CancelledError:
            return  # Task was cancelled, not an error
        if exception:
            self.print(f"Unhandled exception in task: {exception}")
            self.print_traceback()

    async def update(self) -> bool:
        """
        Main function. It tries to update the TI files from a remote server
        we update different types of files remote TI files, remote JA3 feeds,
         RiskIQ domains and local slips files
        """
        if self.update_period <= 0:
            # User does not want to update the malicious IP list.
            self.print(
                "Not Updating the remote file of malicious IPs and domains. "
                "update period is <= 0.",
                0,
                1,
            )
            return False

        try:
            self.log("Checking if we need to download TI files.")

            if self._should_update_mac_db():
                self.update_mac_db()

            if self.should_update_online_whitelist():
                self._update_online_whitelist()

            ############### Update remote TI files ################
            feeds = (
                self.url_feeds,
                self.ja3_feeds,
                self.ssl_feeds,
                self.tor_nodes_feeds,
            )
            # Check if the remote file is newer than our own
            # For each file that we should update`
            files_to_download: Dict[str, Dict[str, str]] = {}
            for feed in feeds:
                files_to_download.update(feed)

            # before updating any feeds, make sure that the cached feeds
            # are not using any feed that is not given in the config of
            # this run (self.url_feeds, self.ja3_feeds, self.ssl_feeds)
            self._delete_unused_cached_remote_feeds()

            for file_to_download in files_to_download:
                if self.should_update(file_to_download, self.update_period):
                    # failed to get the response, either a server problem
                    # or the file is up to date so the response isn't needed
                    # either way __check_if_update handles the error printing

                    # this run wasn't started with existing ti files in the db
                    self.first_time_reading_files = True

                    # every function call to update_ti_file is now running
                    # concurrently instead of serially
                    # so when a server's taking a while to give us the TI
                    # feed, we proceed to download the next file instead of
                    # being idle
                    task = asyncio.create_task(
                        self.update_ti_file(file_to_download)
                    )
                    task.add_done_callback(self._handle_task_exception)
            #######################################################
            # in case of risk_iq files, we don't have a link for them in
            # ti_files, We update these files using their API
            # check if we have a username and api key and a week has passed
            # since we last updated
            if self.should_update("riskiq_domains", self.riskiq_update_period):
                self.update_riskiq_feed()

            # wait for all TI files to update
            try:
                await task
            except (UnboundLocalError, asyncio.exceptions.CancelledError):
                # in case all our files are updated, we don't
                # have task defined, skip
                pass

            self.db.set_loaded_ti_files(self.loaded_ti_files)
            self.print_duplicate_ip_summary()
            self.loaded_ti_files = 0
        except KeyboardInterrupt:
            return False

    async def update_ti_files(self):
        """
        Update TI files and store them in database before slips starts
        """
        # create_task is used to run update() function
        # concurrently instead of serially
        self.update_finished: Task = asyncio.create_task(self.update())
        self.update_finished.add_done_callback(self._handle_task_exception)

        await self.update_finished
        self.print(
            f"{self.db.get_loaded_ti_feeds_number()} "
            f"TI files successfully loaded."
        )

    def shutdown_gracefully(self):
        # terminating the timer for the process to be killed
        self.update_timer.cancel()
        return True

    def pre_main(self):
        """this method runs only once"""
        try:
            # only one instance of slips should be able to update TI files at a time
            # so this function will only be allowed to run from 1 slips instance.
            with Lock(name="slips_feeds_update"):
                asyncio.run(self.update_ti_files())
                # Starting timer to update files
                self.update_timer.start()
        except CannotAcquireLock:
            # another instance of slips is updating TI files, tranco
            # whitelists and mac db
            return 1

    def main(self):
        """
        nothing should run in a loop in this module
        """
        # Prevent tight CPU loop, but wake immediately on shutdown.
        self.termination_event.wait(timeout=0.1)
