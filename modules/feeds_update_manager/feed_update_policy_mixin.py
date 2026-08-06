# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>

# SPDX-License-Identifier: GPL-2.0-only


import sys
import time
import traceback
from typing import Dict, List

import requests


class FeedUpdatePolicyMixin:
    """Decide whether cached feeds need refreshing."""

    def download_file(self, file_to_download: str) -> requests.Response | bool:
        """Download a remote feed with retries.

        Parameters:
            file_to_download: Remote feed URL to download.

        Return:
            The response when the download succeeds, otherwise False.
        """
        error = ""
        # Retry 5 times to get the TI file if an error occurred.
        for _try in range(5):
            try:
                response = requests.get(
                    file_to_download, timeout=5, verify=False
                )
                if response.status_code != 200:
                    error = (
                        f"An error occurred while downloading the file {file_to_download}."
                        f"status code: {response.status_code}. Aborting"
                    )
                else:
                    return response
            except requests.exceptions.ReadTimeout:
                error = (
                    f"Timeout reached while downloading the file "
                    f"{file_to_download}. Aborting."
                )

            except (
                requests.exceptions.ConnectionError,
                requests.exceptions.ChunkedEncodingError,
            ):
                error = (
                    f"Connection error while downloading the file "
                    f"{file_to_download}. Aborting."
                )

        if error:
            self.print(f"Warning: {error}", 1, 0)
            return False

    def get_last_modified(self, response) -> str:
        """
        returns Last-Modified field of TI file.
        Called when the file doesn't have an e-tag
        :param response: the output of a request done with requests library
        """
        return response.headers.get("Last-Modified", False)

    def _did_update_period_pass(self, period, file) -> bool:
        """
        checks if the given period passed since the last time we
         updated the given file
        """
        # Get the last time this file was updated
        ti_file_info: dict = self.db.get_ti_feed_info(file)
        last_update = ti_file_info.get("time", float("-inf"))
        return last_update + period <= time.time()

    def _mark_feed_as_updated(self, feed, extra_info: dict = {}):
        """
        sets the time we're done updating the feed in the db and increases
        the number of loaded ti feeds
        :param feed: name or link of the updated feed
        :param extra_info: to store about the update of the given feen in
        the db
        e.g. last-modified, e-tag, hash etc
        """
        now = time.time()
        # update the time we last checked this file for update
        self.db.set_feed_last_update_time(feed, now)

        extra_info.update({"time": now})
        self.db.set_ti_feed_info(feed, extra_info)

        self.loaded_ti_files += 1

    def should_update(self, file_to_download: str, update_period) -> bool:
        """
        Decides whether to update or not based on the update period and e-tag.
        Used for remote files that are updated periodically
        the response will be stored in self.responses if the file is old
        and needs to be updated
        :param file_to_download: url that contains the file to download
        :param update_period: after how many seconds do we need to update
        this file?
        """
        if not self._did_update_period_pass(update_period, file_to_download):
            # Update period hasn't passed yet, but the file is in our db
            self.loaded_ti_files += 1
            return False

        # update period passed
        if "risk" in file_to_download:
            # updating risk_iq TI data does not depend on an e-tag
            return True

        # Update only if the e-tag is different
        try:
            # response will be used to get e-tag, and if the file was updated
            # the same response will be used to update the content in our db
            response = self.download_file(file_to_download)
            if not response:
                return False

            # Get the E-TAG of this file to compare with current files
            ti_file_info: dict = self.db.get_ti_feed_info(file_to_download)
            old_e_tag = ti_file_info.get("e-tag", "")
            # Check now if E-TAG of file in github is same as downloaded
            # file here.
            new_e_tag = self.get_e_tag(response)
            if not new_e_tag:
                # use last modified instead
                cached_last_modified = ti_file_info.get("Last-Modified", "")
                new_last_modified = self.get_last_modified(response)

                if not new_last_modified:
                    self.log(
                        f"Error updating {file_to_download}."
                        f" Doesn't have an e-tag or Last-Modified field."
                    )
                    return False

                # use last modified date instead of e-tag
                if new_last_modified != cached_last_modified:
                    self.responses[file_to_download] = response
                    return True
                else:
                    self._mark_feed_as_updated(file_to_download)
                    return False

            if old_e_tag != new_e_tag:
                # Our TI file is old. Download the new one.
                # we'll be storing this e-tag in our database
                self.responses[file_to_download] = response
                return True

            else:
                # old_e_tag == new_e_tag
                # update period passed but the file hasnt changed on the
                # server, no need to update
                # Store the update time like we downloaded it anyway
                self._mark_feed_as_updated(file_to_download)
                return False

        except Exception:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(
                f"Problem on should_update() line {exception_line}", 0, 1
            )
            self.print(traceback.format_exc(), 0, 1)
        return False

    def get_e_tag(self, response):
        """
        :param response: the output of a request done with requests library
        """
        return response.headers.get("ETag", False)

    def _delete_unused_cached_remote_feeds(self):
        """
        Slips caches all the feeds it downloads. If the user deleted any of
        the feeds used, like literally deleted it (not using ;) the feeds
        will still be there in the cache. the purpose of this function is
        to delete these unused feeds from the cache
        """
        # get the cached feeds
        loaded_feeds: Dict[str, Dict[str, str]] = self.db.get_loaded_ti_feeds()
        # filter remote ones only, bc the loaded feeds have local ones too
        cached_remote_feeds: List[str] = [
            feed for feed in loaded_feeds if feed.startswith("http")
        ]

        # get the remote feeds that should be used from the config file
        remote_feeds_from_config: List[str] = (
            list(self.url_feeds.keys())
            + list(self.ja3_feeds)
            + list(self.ssl_feeds)
            + [self.mac_db_link]
        )
        for feed in cached_remote_feeds:
            # check is the feed should be used. is it in the given config
            # of this run?
            if feed not in remote_feeds_from_config:
                # delete the feed from the cache
                self.db.delete_ti_feed(feed)
                self.db.delete_feed_entries(feed)
                self.print(
                    f"Deleted feed {feed} from cache",
                    2,
                    0,
                    log_to_logfiles_only=True,
                )
        self.loaded_ti_files -= 1
