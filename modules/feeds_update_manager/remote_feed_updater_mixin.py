# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>

# SPDX-License-Identifier: GPL-2.0-only


import datetime
import json
import os
import sys
import time
import traceback

import requests


class RemoteFeedUpdaterMixin:
    """Download, persist, and parse remote feeds."""

    def write_file_to_disk(self, response, full_path):
        with open(full_path, "w") as f:
            f.write(response.text)

    async def update_ti_file(self, link_to_download: str) -> bool:
        """
        Update remote TI files, JA3 feeds and SSL feeds by writing them to
        disk and parsing them
        """
        try:
            self.log(f"Updating the remote file {link_to_download}")
            response = self.responses[link_to_download]
            file_name_to_download = link_to_download.split("/")[-1]

            # first download the file and save it locally
            full_path = os.path.join(
                self.path_to_remote_ti_files_dir, file_name_to_download
            )
            self.write_file_to_disk(response, full_path)

            # File is updated in the server and was in our database.
            # Delete previous iocs of this file.
            self.db.delete_feed_entries(link_to_download)

            # ja3 files and ti_files are parsed differently, check which file is this
            # is it ja3 feed?
            if link_to_download in self.ja3_feeds and not self.parse_ja3_feed(
                link_to_download, full_path
            ):
                self.print(
                    f"Error parsing JA3 feed {link_to_download}. "
                    f"Updating was aborted.",
                    0,
                    1,
                )
                return False

            # is it a ti_file? load updated IPs/domains to the database
            elif link_to_download in self.url_feeds and not self.parse_ti_feed(
                link_to_download, full_path
            ):
                self.print(
                    f"Error parsing feed {link_to_download}. "
                    f"Updating was aborted.",
                    0,
                    1,
                )
                return False
            elif (
                link_to_download in self.ssl_feeds
                and not self.parse_ssl_feed(link_to_download, full_path)
            ):
                self.print(
                    f"Error parsing feed {link_to_download}. "
                    f"Updating was aborted.",
                    0,
                    1,
                )
                return False

            # Store the new etag and time of file in the database
            file_info = {
                "e-tag": self.get_e_tag(response),
                "time": time.time(),
                "Last-Modified": self.get_last_modified(response),
            }
            self._mark_feed_as_updated(link_to_download, extra_info=file_info)
            self.log(
                f"Successfully updated the remote file {link_to_download}"
            )

            # done parsing the file, delete it from disk
            try:
                os.remove(full_path)
            except FileNotFoundError:
                # this happens in integration tests, when another test deletes
                # the file while this one is updating it, ignore it
                pass

            return True

        except Exception:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(
                f"Problem on update_ti_file() line {exception_line}", 0, 1
            )
            self.print(traceback.format_exc(), 0, 1)
            return False

    def update_riskiq_feed(self):
        """Get and parse RiskIQ feed"""
        if not (self.riskiq_email and self.riskiq_key):
            return False
        try:
            self.log("Updating RiskIQ domains")
            url = "https://api.riskiq.net/pt/v2/articles/indicators"
            auth = (self.riskiq_email, self.riskiq_key)
            today = datetime.date.today()
            days_ago = datetime.timedelta(7)
            a_week_ago = today - days_ago
            data = {
                "startDateInclusive": a_week_ago.strftime("%Y-%m-%d"),
                "endDateExclusive": today.strftime("%Y-%m-%d"),
            }
            # Specifying json= here instead of data= ensures that the
            # Content-Type header is application/json, which is necessary.
            response = requests.get(
                url, timeout=5, auth=auth, json=data
            ).json()
            # extract domains only from the response
            try:
                response = response["indicators"]
                for indicator in response:
                    # each indicator is a dict
                    malicious_domains_dict = {}
                    if indicator.get("type", "") == "domain":
                        domain = indicator["value"]
                        malicious_domains_dict[domain] = json.dumps(
                            {
                                "description": "malicious domain detected by RiskIQ",
                                "source": url,
                            }
                        )
                        self.db.add_domains_to_ioc(malicious_domains_dict)
            except KeyError:
                self.print(
                    f'RiskIQ returned: {response["message"]}. '
                    f"Update Cancelled.",
                    0,
                    1,
                )
                return False

            self._mark_feed_as_updated("riskiq_domains")
            self.log("Successfully updated RiskIQ domains.")
            return True
        except Exception as e:
            self.log(
                "An error occurred while updating RiskIQ domains. "
                "Updating was aborted."
            )
            self.print("An error occurred while updating RiskIQ feed.", 0, 1)
            self.print(f"Error: {e}", 0, 1)
            return False
