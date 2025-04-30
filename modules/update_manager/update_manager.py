# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import asyncio
import datetime
import json
import os
import sys
import time
import traceback
from asyncio import Task
from typing import (
    IO,
    Optional,
    Tuple,
    Dict,
    List,
)

import requests
from exclusiveprocess import (
    Lock,
    CannotAcquireLock,
)

from modules.update_manager.timer_manager import InfiniteTimer
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.abstracts.module import IModule
from slips_files.common.slips_utils import utils
from slips_files.core.helpers.whitelist.whitelist import Whitelist


class UpdateManager(IModule):
    name = "Update Manager"
    description = "Update Threat Intelligence files"
    authors = ["Kamila Babayeva", "Alya Gomaa"]

    def init(self):
        self.read_configuration()
        # Update file manager
        # Timer to update the ThreatIntelligence files
        self.timer_manager = InfiniteTimer(
            self.update_period, self.update_ti_files
        )
        # Timer to update the MAC db
        # when update_ti_files is called, it decides what exactly to
        # update, the mac db, online whitelist Or online ti files.
        self.mac_db_update_manager = InfiniteTimer(
            self.mac_db_update_period, self.update_ti_files
        )
        self.online_whitelist_update_timer = InfiniteTimer(
            self.online_whitelist_update_period, self.update_ti_files
        )
        self.separator = self.db.get_field_separator()
        self.read_configuration()
        # this will store the number of loaded ti files
        self.loaded_ti_files = 0
        # don't store iocs older than 1 week
        self.interval = 7
        self.whitelist = Whitelist(self.logger, self.db)
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

    def read_configuration(self):
        def read_riskiq_creds(risk_iq_credentials_path):
            self.riskiq_email = None
            self.riskiq_key = None

            if not risk_iq_credentials_path:
                return

            risk_iq_credentials_path = os.path.join(
                os.getcwd(), risk_iq_credentials_path
            )
            if not os.path.exists(risk_iq_credentials_path):
                return

            with open(risk_iq_credentials_path, "r") as f:
                self.riskiq_email = f.readline().replace("\n", "")
                self.riskiq_key = f.readline().replace("\n", "")

        conf = ConfigParser()

        self.update_period = conf.update_period()

        self.path_to_remote_ti_files = conf.remote_ti_data_path()
        if not os.path.exists(self.path_to_remote_ti_files):
            os.mkdir(self.path_to_remote_ti_files)

        self.ti_feeds_path = conf.ti_files()
        self.url_feeds = self.get_feed_details(self.ti_feeds_path)
        self.ja3_feeds_path = conf.ja3_feeds()
        self.ja3_feeds = self.get_feed_details(self.ja3_feeds_path)

        self.ssl_feeds_path = conf.ssl_feeds()
        self.ssl_feeds = self.get_feed_details(self.ssl_feeds_path)

        risk_iq_credentials_path = conf.RiskIQ_credentials_path()
        read_riskiq_creds(risk_iq_credentials_path)
        self.riskiq_update_period = conf.riskiq_update_period()

        self.mac_db_update_period = conf.mac_db_update_period()
        self.mac_db_link = conf.mac_db_link()

        self.online_whitelist_update_period = (
            conf.online_whitelist_update_period()
        )
        self.online_whitelist = conf.online_whitelist()
        self.enable_online_whitelist: bool = conf.enable_online_whitelist()
        self.enable_local_whitelist: bool = conf.enable_local_whitelist()

    def get_feed_details(self, feeds_path):
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

    def log(self, text):
        """
        sends the text to output process to log it to slips.log without
         printing to the cli
        """
        self.print(text, verbose=0, debug=1, log_to_logfiles_only=True)

    def read_ports_info(self, ports_info_filepath) -> int:
        """
        Reads port info from slips_files/ports_info/ports_used_by_specific_orgs.csv
        and store it in the db
        """

        # there are ports that are by default considered unknown to slips,
        # but if it's known to be used by a specific organization, slips won't
        # consider it 'unknown'.
        # in ports_info_filepath  we have a list of organizations range/ip and
        # the port it's known to use
        with open(ports_info_filepath, "r") as f:
            line_number = 0
            while True:
                line = f.readline()
                line_number += 1
                # reached the end of file
                if not line:
                    break
                # skip the header and the comments at the begining
                if line.startswith("#") or line.startswith('"Organization"'):
                    continue

                line = line.split(",")
                try:
                    organization, ip = line[0], line[1]
                    ports_range = line[2]
                    proto = line[3].lower().strip()

                    # is it a range of ports or a single port
                    if "-" in ports_range:
                        # it's a range of ports
                        first_port, last_port = ports_range.split("-")
                        first_port = int(first_port)
                        last_port = int(last_port)

                        for port in range(first_port, last_port + 1):
                            portproto = f"{port}/{proto}"
                            self.db.set_organization_of_port(
                                organization, ip, portproto
                            )
                    else:
                        # it's a single port
                        portproto = f"{ports_range}/{proto}"
                        self.db.set_organization_of_port(
                            organization, ip, portproto
                        )

                except IndexError:
                    self.print(
                        f"Invalid line: {line} line number: "
                        f"{line_number} in {ports_info_filepath}. Skipping.",
                        0,
                        1,
                    )
                    continue
        return line_number

    def update_local_file(self, file_path) -> bool:
        """
        Returns True if update was successful
        """
        try:
            # each file is updated differently
            if "ports_used_by_specific_orgs.csv" in file_path:
                self.read_ports_info(file_path)

            elif "services.csv" in file_path:
                with open(file_path, "r") as f:
                    for line in f:
                        name = line.split(",")[0]
                        port = line.split(",")[1]
                        proto = line.split(",")[2]
                        # descr = line.split(',')[3]
                        self.db.set_port_info(f"{str(port)}/{proto}", name)

            # Store the new hash of file in the database
            file_info = {"hash": self.new_hash}
            self.mark_feed_as_updated(file_path, extra_info=file_info)
            return True

        except OSError:
            return False

    def check_if_update_local_file(self, file_path: str) -> bool:
        """
        Decides whether to update or not based on the file hash.
        Used for local files that are updated if the contents of the file
        hash changed
        for example: files in slips_files/ports_info
        """

        # compute file sha256 hash
        new_hash = utils.get_sha256_hash_of_file_contents(file_path)

        # Get last hash of the file stored in the database
        file_info = self.db.get_ti_feed_info(file_path)
        old_hash = file_info.get("hash", False)

        if not old_hash or old_hash != new_hash:
            # first time seeing the file, OR we should update it
            self.new_hash = new_hash
            return True

        else:
            # The 2 hashes are identical. File is up to date.
            return False

    def should_update_online_whitelist(self) -> bool:
        """
        Decides whether to update or not based on the update period
        Used for online whitelist specified in slips.conf
        """
        if not self.enable_online_whitelist:
            return False

        if not self.did_update_period_pass(
            self.online_whitelist_update_period, "tranco_whitelist"
        ):
            # update period hasnt passed yet
            return False

        # update period passed
        # response will be used to get e-tag, and if the file was updated
        # the same response will be used to update the content in our db
        response = self.download_file(self.online_whitelist)
        if not response:
            return False

        self.responses["tranco_whitelist"] = response
        return True

    def download_file(self, file_to_download):
        # Retry 3 times to get the TI file if an error occured
        for _try in range(5):
            try:
                response = requests.get(file_to_download, timeout=5)
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
            self.print(error, 0, 1)
            return False

    def get_last_modified(self, response) -> str:
        """
        returns Last-Modified field of TI file.
        Called when the file doesn't have an e-tag
        :param response: the output of a request done with requests library
        """
        return response.headers.get("Last-Modified", False)

    def is_mac_db_file_on_disk(self) -> bool:
        """checks if the mac db is present in databases/"""
        return os.path.isfile(self.path_to_mac_db)

    def did_update_period_pass(self, period, file) -> bool:
        """
        checks if the given period passed since the last time we
         updated the given file
        """
        # Get the last time this file was updated
        ti_file_info: dict = self.db.get_ti_feed_info(file)
        last_update = ti_file_info.get("time", float("-inf"))
        return last_update + period <= time.time()

    def mark_feed_as_updated(self, feed, extra_info: dict = {}):
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
        if not self.did_update_period_pass(update_period, file_to_download):
            # Update period hasn't passed yet, but the file is in our db
            self.loaded_ti_files += 1
            return False

        # update period passed
        if "risk" in file_to_download:
            # updating riskiq TI data does not depend on an e-tag
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
                    self.mark_feed_as_updated(file_to_download)
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
                self.mark_feed_as_updated(file_to_download)
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

    def write_file_to_disk(self, response, full_path):
        with open(full_path, "w") as f:
            f.write(response.text)

    def parse_ssl_feed(self, url, full_path):
        """
        Read all ssl fingerprints in full_path and store the info in our db
        :param url: the src feed
        :param full_path: the file path where the SSL feed is downloaded
        """

        malicious_ssl_certs = {}

        with open(full_path) as ssl_feed:
            # Ignore comments and find the description column if possible
            description_column = None
            while True:
                line = ssl_feed.readline()
                if line.startswith("# Listingdate"):
                    # looks like the line that contains column names,
                    # search where is the description column
                    for column in line.split(","):
                        # Listingreason is the description column in
                        # abuse.ch Suricata SSL Fingerprint Blacklist
                        if "Listingreason" in column.lower():
                            description_column = line.split(",").index(column)
                if not line.startswith("#"):
                    # break while statement if it is not a comment (i.e.
                    # does not start with #) or a header line
                    break

            # Find in which column is the ssl fingerprint in this file

            # Store the current position of the TI file
            current_file_position = ssl_feed.tell()
            if "," in line:
                data = line.replace("\n", "").replace('"', "").split(",")
                amount_of_columns = len(line.split(","))

            if description_column is None:
                # assume it's the last column
                description_column = amount_of_columns - 1

            # Search the first column that contains a sha1 hash
            for column in range(amount_of_columns):
                # Check if the ssl fingerprint is valid.
                # assume this column is the sha1 field
                sha1 = data[column]
                # verify
                if len(sha1) != 40:
                    sha1_column = None
                else:
                    # we found the column that has sha1 info
                    sha1_column = column
                    break

            if sha1_column is None:
                # can't find a column that contains an ioc
                self.print(
                    f"Error while reading the ssl file {full_path}. "
                    f"Could not find a column with sha1 info",
                    0,
                    1,
                )
                return False

            # Now that we read the first line, go back so we can process it
            ssl_feed.seek(current_file_position)

            for line in ssl_feed:
                # The format of the file should be
                # 2022-02-06 07:58:29,6cec09bcb575352785d313c7e978f26bfbd528ab,AsyncRAT C&C

                # skip comment lines
                if line.startswith("#"):
                    continue

                # Separate the lines like CSV, either by commas or tabs
                # In the new format the ip is in the second position.
                # And surrounded by "

                # get the hash to store in our db
                if "," in line:
                    sha1 = (
                        line.replace("\n", "")
                        .replace('"', "")
                        .split(",")[sha1_column]
                        .strip()
                    )

                # get the description of this ssl to store in our db
                try:
                    separator = "," if "," in line else "\t"
                    description = (
                        line.replace("\n", "")
                        .replace('"', "")
                        .split(separator)[description_column]
                        .strip()
                    )
                except IndexError:
                    self.print(
                        f"IndexError Description column: "
                        f"{description_column}. Line: {line}"
                    )

                # self.print('\tRead Data {}: {}'.format(sha1, description))

                filename = full_path.split("/")[-1]

                if len(sha1) == 40:
                    # Store the sha1 in our local dict
                    malicious_ssl_certs[sha1] = json.dumps(
                        {
                            "description": description,
                            "source": filename,
                            "threat_level": self.ssl_feeds[url][
                                "threat_level"
                            ],
                            "tags": self.ssl_feeds[url]["tags"],
                        }
                    )
                else:
                    self.log(
                        f"The data {data} is not valid. It was found in "
                        f"{filename}."
                    )
                    continue
        # Add all loaded malicious sha1 to the database
        self.db.add_ssl_sha1_to_ioc(malicious_ssl_certs)
        return True

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
                self.path_to_remote_ti_files, file_name_to_download
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
            self.mark_feed_as_updated(link_to_download, extra_info=file_info)
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

            self.mark_feed_as_updated("riskiq_domains")
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

    def parse_ja3_feed(self, url, ja3_feed_path: str) -> bool:
        """
        Read all ja3 fingerprints in ja3_feed_path and store the info in our db
        :param url: this is the src feed
        :param ja3_feed_path: the file path where a ja3 feed is downloaded
        """

        try:
            malicious_ja3_dict = {}

            with open(ja3_feed_path) as ja3_feed:
                # Ignore comments and find the description column if possible
                description_column = None
                while True:
                    line = ja3_feed.readline()
                    if line.startswith("# ja3_md5"):
                        # looks like the line that contains column names,
                        # search where is the description column
                        for column in line.split(","):
                            # Listingreason is the description column in
                            # abuse.ch Suricata JA3 Fingerprint Blacklist
                            if "Listingreason" in column.lower():
                                description_column = line.split(",").index(
                                    column
                                )
                    if not line.startswith("#"):
                        # break while statement if it is not a comment
                        # (i.e. does not startwith #) or a header line
                        break

                # Find in which column is the ja3 fingerprint in this file

                # Store the current position of the TI file
                current_file_position = ja3_feed.tell()
                if "," in line:
                    data = line.replace("\n", "").replace('"', "").split(",")
                    amount_of_columns = len(line.split(","))

                if description_column is None:
                    # assume it's the last column
                    description_column = amount_of_columns - 1

                # Search the first column that is an IPv4, IPv6 or domain
                for column in range(amount_of_columns):
                    # Check if the ja3 fingerprint is valid.
                    # assume this column is the ja3 field
                    ja3 = data[column]
                    # verify
                    if len(ja3) != 32:
                        ja3_column = None
                    else:
                        # we found the column that has ja3 info
                        ja3_column = column
                        break

                if ja3_column is None:
                    # can't find a column that contains an ioc
                    self.print(
                        f"Error while reading the ja3 file {ja3_feed_path}. "
                        f"Could not find a column with JA3 info",
                        1,
                        1,
                    )
                    return False

                # Now that we read the first line, go back so we can process it
                ja3_feed.seek(current_file_position)

                for line in ja3_feed:
                    # The format of the file should be
                    # 8f52d1ce303fb4a6515836aec3cc16b1,2017-07-15 19:05:11,2019-07-27 20:00:57,TrickBot

                    # skip comment lines
                    if line.startswith("#"):
                        continue

                    # Separate the lines like CSV, either by commas or tabs
                    # In the new format the ip is in the second position.
                    # And surronded by "

                    # get the ja3 to store in our db
                    if "," in line:
                        ja3 = (
                            line.replace("\n", "")
                            .replace('"', "")
                            .split(",")[ja3_column]
                            .strip()
                        )

                    # get the description of this ja3 to store in our db
                    try:
                        if "," in line:
                            description = (
                                line.replace("\n", "")
                                .replace('"', "")
                                .split(",")[description_column]
                                .strip()
                            )
                        else:
                            description = (
                                line.replace("\n", "")
                                .replace('"', "")
                                .split("\t")[description_column]
                                .strip()
                            )
                    except IndexError:
                        self.print(
                            f"IndexError Description column: "
                            f"{description_column}. Line: {line}",
                            0,
                            1,
                        )

                    # self.print('\tRead Data {}: {}'.format(ja3, description))

                    filename = ja3_feed_path.split("/")[-1]

                    # Check if the data is a valid IPv4, IPv6 or domain
                    if len(ja3) == 32:
                        # Store the ja3 in our local dict
                        malicious_ja3_dict[ja3] = json.dumps(
                            {
                                "description": description,
                                "source": filename,
                                "threat_level": self.ja3_feeds[url][
                                    "threat_level"
                                ],
                                "tags": self.ja3_feeds[url]["tags"],
                            }
                        )
                    else:
                        self.print(
                            f"The data {data} is not valid. "
                            f"It was found in {filename}.",
                            3,
                            3,
                        )
                        continue

            # Add all loaded malicious ja3 to the database
            self.db.add_ja3_to_ioc(malicious_ja3_dict)
            return True

        except Exception:
            self.print("Problem in parse_ja3_feed()", 0, 1)
            self.print(traceback.format_exc(), 0, 1)
            return False

    def parse_json_ti_feed(self, link_to_download, ti_file_path: str) -> bool:
        """
        Slips has 2 json TI feeds that are parsed differently. hole.cert.pl
        and rstcloud
        """
        # to support https://hole.cert.pl/domains/domains.json
        tags = self.url_feeds[link_to_download]["tags"]
        # the new threat_level is the max of the 2
        threat_level = self.url_feeds[link_to_download]["threat_level"]
        filename = ti_file_path.split("/")[-1]

        if "rstcloud" in link_to_download:
            malicious_ips_dict = {}
            with open(ti_file_path) as feed:
                self.print(
                    f"Reading next lines in the file "
                    f"{ti_file_path} for IoC",
                    3,
                    0,
                )
                for line in feed.read().splitlines():
                    try:
                        line: dict = json.loads(line)
                    except json.decoder.JSONDecodeError:
                        # invalid json line
                        continue
                    # each ip in this file has it's own source and tag
                    src = line["src"]["name"][0]
                    malicious_ips_dict[line["ip"]["v4"]] = json.dumps(
                        {
                            "description": "",
                            "source": f"{filename}, {src}",
                            "threat_level": threat_level,
                            "tags": f'{line["tags"]["str"]}, {tags}',
                        }
                    )

            self.db.add_ips_to_ioc(malicious_ips_dict)
            return True

        if "hole.cert.pl" in link_to_download:
            malicious_domains_dict = {}
            with open(ti_file_path) as feed:
                self.print(
                    f"Reading next lines in the file {ti_file_path}"
                    f" for IoC",
                    3,
                    0,
                )
                try:
                    file = json.loads(feed.read())
                except json.decoder.JSONDecodeError:
                    # not a json file??
                    return False

                for ioc in file:
                    date = utils.convert_ts_to_tz_aware(ioc["InsertDate"])
                    now = utils.convert_ts_to_tz_aware(time.time())
                    diff = utils.get_time_diff(date, now, return_type="days")

                    if diff > self.interval:
                        continue

                    domain = ioc["DomainAddress"]
                    if not utils.is_valid_domain(domain):
                        continue

                    malicious_domains_dict[domain] = json.dumps(
                        {
                            "description": "",
                            "source": filename,
                            "threat_level": threat_level,
                            "tags": tags,
                        }
                    )
            self.db.add_domains_to_ioc(malicious_domains_dict)
            return True

    def get_description_column_index(self, header):
        """
        Given the first line of a TI file (header line), try to get the index
         of the description column
        """
        description_keywords = (
            "desc",
            "collect",
            "malware",
            "tags_str",
            "source",
        )
        for column in header.split(","):
            for keyword in description_keywords:
                if keyword in column:
                    return header.split(",").index(column)

    def is_ignored_line(self, line) -> bool:
        """
        Returns True if a comment, a header line,  a blank line, or an
        unsupported IoC
        """
        if (
            line.startswith("#")
            or line.startswith(";")
            or line.isspace()
            or len(line) < 3
        ):
            return True

        for keyword in self.header_keywords + self.ignored_IoCs:
            if keyword in line.lower():
                # we should ignore this line
                return True

    def get_feed_fields_and_sep(self, line, file_path) -> tuple:
        """
        :param file_path: path of the ti file that contains the given line
        Parse the given line and return the amount of columns it has,
        a list of the line fields, and the separator it's using
        """
        # Separate the lines like CSV, either by commas or tabs
        separators = ("#", ",", ";", "\t")
        for separator in separators:
            if separator in line and not line.startswith(separator):
                # lines and descriptions in this feed are separated with ','
                # so we get an invalid number of columns
                if "OCD-Datalak" in file_path:
                    # the valid line
                    new_line = line.split("Z,")[0]
                    # replace every ',' from the description
                    description = line.split("Z,", 1)[1].replace(", ", "")
                    line = f"{new_line},{description}"

                # get a list of every field in the line
                # e.g [ioc, description, date]
                line_fields = line.split(separator)
                amount_of_columns = len(line_fields)
                sep = separator
                break
        else:
            # no separator of the above was found
            if "0.0.0.0 " in line:
                sep = " "
                # anudeepND/blacklist file
                line_fields = [line[line.index(" ") + 1 :].replace("\n", "")]
                amount_of_columns = 1
            else:
                sep = "\t"
                line_fields = line.split(sep)
                amount_of_columns = len(line_fields)

        return amount_of_columns, line_fields, sep

    def get_data_column(
        self, amount_of_columns: int, line_fields: list, file_path: str
    ):
        """
        Get the first column that is an IPv4, IPv6 or domain
        :param file_path: path of the ti file that contains the given fields
        """
        # we only have one column, definetely is the data column
        if amount_of_columns == 1:
            return 0

        for column_idx in range(amount_of_columns):
            if utils.detect_ioc_type(line_fields[column_idx]):
                return column_idx
        # Some unknown string and we cant detect the type of it
        # can't find a column that contains an ioc
        self.print(
            f"Error while reading the TI file {file_path}."
            f" Could not find a column with an IP or domain",
            0,
            1,
        )
        return "Error"

    def extract_ioc_from_line(
        self,
        line,
        line_fields,
        separator,
        data_column,
        description_column,
        file_path,
    ) -> tuple:
        """
        Returns the ip/ip range/domain and it's description from the given line
        """
        if "0.0.0.0 " in line:
            # anudeepND/blacklist file
            data = line[line.index(" ") + 1 :].replace("\n", "")
        else:
            line_fields = line.split(separator)
            # get the ioc
            data = line_fields[data_column].strip()

        # get the description of this line
        try:
            description = line_fields[description_column].strip()
        except (IndexError, UnboundLocalError):
            self.print(
                f"IndexError Description column: "
                f"{description_column}. Line: {line} in "
                f"{file_path}",
                0,
                1,
            )
            return False, False

        self.print(f"\tRead Data {data}: {description}", 3, 0)
        return data, description

    def add_to_ip_ctr(self, ip, blacklist):
        """
        keep track of how many times an ip was there in all blacklists
        :param blacklist: t make sure we don't count the ip twice in the
         same blacklist
        """
        blacklist = os.path.basename(blacklist)
        if ip in self.ips_ctr and blacklist not in self.ips_ctr["blacklists"]:
            self.ips_ctr[ip]["times_found"] += 1
            self.ips_ctr[ip]["blacklists"].append(blacklist)
        else:
            self.ips_ctr[ip] = {"times_found": 1, "blacklists": [blacklist]}

    def is_valid_ti_file(self, ti_file_path: str) -> bool:
        # Check if the file has any content
        try:
            filesize = os.path.getsize(ti_file_path)
        except FileNotFoundError:
            # happens in integration tests, another instance of slips
            # deleted the file
            return False

        if filesize == 0:
            return False
        return True

    def is_header_line(self, line) -> bool:
        for keyword in self.header_keywords:
            if line.startswith(keyword):
                return True
        return False

    def get_feed_structure(self, ti_file_path: str) -> Tuple[int]:
        """
        returns a tuple with the index of the column in the feed with the
        description, the data, line_fields, and separator
        """
        with open(ti_file_path) as feed:
            # find the description column if possible
            description_column = None
            header_line_found = False
            while line := feed.readline():
                # Try to find the line that has column names
                if not header_line_found and self.is_header_line(line):
                    # search where is the  description column in this header
                    description_column: Optional[int] = (
                        self.get_description_column_index(line)
                    )
                    header_line_found = True
                # when you find the first line with valid iocs, break so
                # that we can determine the e rest of the structure
                if not self.is_ignored_line(line):
                    break

            # this line now is either the header line, or a line with valid
            # iocs that we should process
            line = line.replace("\n", "").replace('"', "")

            amount_of_columns, line_fields, separator = (
                self.get_feed_fields_and_sep(line, ti_file_path)
            )

            if description_column is None:
                # assume it's the last column
                description_column = amount_of_columns - 1

            data_column: int = self.get_data_column(
                amount_of_columns, line_fields, ti_file_path
            )

            if (
                data_column == "Error"
            ):  # don't use 'if not' because it may be 0
                return False

        return description_column, data_column, line_fields, separator

    def normalize_line(self, ti_file_path: str, line: str) -> str:
        """
        "OCD-Datalak" is a special kinda ti file, it has its own structure,
        this fun extracts a format that slips can understand from this file
        """
        if "OCD-Datalak" in ti_file_path:
            new_line = line.split("Z,")[0]
            # replace every ',' from the description
            description = line.split("Z,", 1)[1].replace(", ", "")
            line = f"{new_line},{description}"
        return line.replace("\n", "").replace('"', "")

    def extract_domain_info(
        self, domain: str, ti_file_name: str, feed_link: str, description: str
    ):
        # if we have info about the ioc, append to it, if we don't
        # add a new entry in the correct dict
        try:
            # we already have info about this domain?
            old_domain_info = json.loads(
                self.malicious_domains_dict[str(domain)]
            )
            # if the domain appeared twice in the same blacklist,  skip it
            if ti_file_name in old_domain_info["source"]:
                return

            # append the new blacklist name to the current one
            source = f'{old_domain_info["source"]}, {ti_file_name}'
            # append the new tag to the current tag
            tags = (
                f'{old_domain_info["tags"]}, '
                f'{self.url_feeds[feed_link]["tags"]}'
            )
            # the new threat_level is the maximum threat_level
            threat_level = str(
                max(
                    float(old_domain_info["threat_level"]),
                    float(self.url_feeds[feed_link]["threat_level"]),
                )
            )
            # Store the ip in our local dict
            self.malicious_domains_dict[str(domain)] = json.dumps(
                {
                    "description": old_domain_info["description"],
                    "source": source,
                    "threat_level": threat_level,
                    "tags": tags,
                }
            )
        except KeyError:
            self.malicious_domains_dict[str(domain)] = json.dumps(
                {
                    "description": description,
                    "source": ti_file_name,
                    "threat_level": self.url_feeds[feed_link]["threat_level"],
                    "tags": self.url_feeds[feed_link]["tags"],
                }
            )

    def extract_ip_info(
        self, ip: str, ti_file_name: str, feed_link: str, description: str
    ):
        # make sure we're not blacklisting a private ip
        if utils.is_ignored_ip(ip):
            return

        try:
            self.add_to_ip_ctr(ip, feed_link)
            # we already have info about this ip?
            old_ip_info = json.loads(self.malicious_ips_dict[str(ip)])
            # if the IP appeared twice in the same blacklist,
            # don't add the blacklist name twice
            # or calculate the max threat_level
            if ti_file_name in old_ip_info["source"]:
                return

            # append the new blacklist name to the current one
            source = f'{old_ip_info["source"]}, {ti_file_name}'
            # append the new tag to the old tag
            tags = (
                f'{old_ip_info["tags"]}, {self.url_feeds[feed_link]["tags"]}'
            )
            # the new threat_level is the max of the 2
            threat_level = str(
                max(
                    int(old_ip_info["threat_level"]),
                    int(self.url_feeds[feed_link]["threat_level"]),
                )
            )
            self.malicious_ips_dict[str(ip)] = json.dumps(
                {
                    "description": old_ip_info["description"],
                    "source": source,
                    "threat_level": threat_level,
                    "tags": tags,
                }
            )
        except KeyError:
            threat_level = self.url_feeds[feed_link]["threat_level"]
            # We don't have info about this IP, Store the ip in our local dict
            self.malicious_ips_dict[str(ip)] = json.dumps(
                {
                    "description": description,
                    "source": ti_file_name,
                    "threat_level": threat_level,
                    "tags": self.url_feeds[feed_link]["tags"],
                }
            )
            # set the score and confidence of this ip in ipsinfo
            # and the profile of this ip to the same as the
            # ones given in slips.conf
            # todo for now the confidence is 1
            self.db.update_threat_level(f"profile_{ip}", threat_level, 1)

    def extract_ip_range_info(
        self,
        ip_range: str,
        ti_file_name: str,
        feed_link: str,
        description: str,
    ):
        # make sure we're not blacklisting a private or multicast ip range
        # get network address from range
        ip = ip_range[: ip_range.index("/")]
        if utils.is_ignored_ip(ip):
            return

        try:
            # we already have info about this range?
            old_range_info = json.loads(self.malicious_ip_ranges[ip_range])
            # if the Range appeared twice in the same blacklist,
            # don't add the blacklist name twice
            # or calculate the max threat_level
            if ti_file_name in old_range_info["source"]:
                return
            # append the new blacklist name to the current one
            source = f'{old_range_info["source"]}, {ti_file_name}'
            # append the new tag to the old tag
            tags = f'{old_range_info["tags"]}, {self.url_feeds[feed_link]["tags"]}'
            # the new threat_level is the max of the 2
            threat_level = str(
                max(
                    int(old_range_info["threat_level"]),
                    int(self.url_feeds[feed_link]["threat_level"]),
                )
            )
            self.malicious_ip_ranges[str(ip_range)] = json.dumps(
                {
                    "description": old_range_info["description"],
                    "source": source,
                    "threat_level": threat_level,
                    "tags": tags,
                }
            )
        except KeyError:
            # We don't have info about this range, Store the ip in our local dict
            self.malicious_ip_ranges[ip_range] = json.dumps(
                {
                    "description": description,
                    "source": ti_file_name,
                    "threat_level": self.url_feeds[feed_link]["threat_level"],
                    "tags": self.url_feeds[feed_link]["tags"],
                }
            )

    def is_valid_ioc_and_description(
        self, ioc, description, ti_file_path: str
    ) -> bool:
        if not ioc and not description:
            return False

        # some ti files have new lines in the middle of
        # the file, ignore them
        if len(ioc) < 3:
            return False

        data_type = utils.detect_ioc_type(ioc)
        if data_type is None:
            self.print(
                f"The data {ioc} is not valid. It "
                f"was found in {ti_file_path}.",
                0,
                1,
            )
            return False
        return True

    def parse_ti_feed(self, feed_link: str, ti_file_path: str) -> bool:
        """
        Read all the files holding IP addresses and a description and put the
        info in a large dict.
        This also helps in having unique ioc across files
        :param feed_link: this link that has the IOCs we're
        currently parsing, used for getting the threat_level
        :param ti_file_path: this is the path where the saved file
        from the link is downloaded
        """
        # try:
        if not self.is_valid_ti_file(ti_file_path):
            return False

        if "json" in ti_file_path:
            return self.parse_json_ti_feed(feed_link, ti_file_path)

        structure: Tuple[int] = self.get_feed_structure(ti_file_path)
        if not structure:
            return False
        description_col, data_col, line_fields, separator = structure

        self.malicious_ips_dict = {}
        self.malicious_domains_dict = {}
        self.malicious_ip_ranges = {}

        feed: IO = open(ti_file_path)
        while line := feed.readline():
            if self.is_ignored_line(line):
                continue

            line = self.normalize_line(ti_file_path, line)
            ioc, description = self.extract_ioc_from_line(
                line,
                line_fields,
                separator,
                data_col,
                description_col,
                ti_file_path,
            )

            if not self.is_valid_ioc_and_description(
                ioc, description, ti_file_path
            ):
                continue

            data_type = utils.detect_ioc_type(ioc)
            handlers = {
                "domain": self.extract_domain_info,
                "ip": self.extract_ip_info,
                "ip_range": self.extract_ip_range_info,
            }

            ti_file_name: str = ti_file_path.split("/")[-1]
            if data_type not in handlers:
                # maybe it's a url, urls as iocs are not supported.
                continue
            handlers[data_type](ioc, ti_file_name, feed_link, description)

        self.db.add_ips_to_ioc(self.malicious_ips_dict)
        self.db.add_domains_to_ioc(self.malicious_domains_dict)
        self.db.add_ip_range_to_ioc(self.malicious_ip_ranges)
        feed.close()
        return True

        # except Exception:
        #     exception_line = sys.exc_info()[2].tb_lineno
        #     self.print(
        #         f"Problem while updating {feed_link} line "
        #         f"{exception_line}",
        #         0,
        #         1,
        #     )
        #     self.print(traceback.format_exc(), 0, 1)
        #     return False

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
        """
        if self.enable_local_whitelist:
            self.whitelist.update()

    def update_org_files(self):
        for org in utils.supported_orgs:
            org_ips = os.path.join(self.org_info_path, org)
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
                self.mark_feed_as_updated(file, info)

    def update_ports_info(self):
        for file in os.listdir("slips_files/ports_info"):
            file = os.path.join("slips_files/ports_info", file)
            if self.check_if_update_local_file(
                file
            ) and not self.update_local_file(file):
                # update failed
                self.print(
                    f"An error occurred while updating {file}. Updating "
                    f"was aborted.",
                    0,
                    1,
                )

    def print_duplicate_ip_summary(self):
        if not self.first_time_reading_files:
            # when we parse ti files for the first time, we have the info to
            # print the summary
            # when the ti files are already updated, from a previous run,
            # we don't
            return

        ips_in_1_bl = 0
        ips_in_2_bl = 0
        ips_in_3_bl = 0
        for ip, ip_info in self.ips_ctr.items():
            blacklists_ip_appeard_in = ip_info["times_found"]
            if blacklists_ip_appeard_in == 1:
                ips_in_1_bl += 1
            elif blacklists_ip_appeard_in == 2:
                ips_in_2_bl += 1
            elif blacklists_ip_appeard_in == 3:
                ips_in_3_bl += 1
        self.print(
            f"Number of repeated IPs in 1 blacklist: {ips_in_1_bl}", 2, 0
        )
        self.print(
            f"Number of repeated IPs in 2 blacklists: {ips_in_2_bl}", 2, 0
        )
        self.print(
            f"Number of repeated IPs in 3 blacklists: {ips_in_3_bl}", 2, 0
        )

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

        self.mark_feed_as_updated(self.mac_db_link)
        return True

    def update_online_whitelist(self):
        """
        Updates online tranco whitelist defined in slips.yaml
         online_whitelist key
        """
        # delete the old ones
        self.db.delete_tranco_whitelist()
        response = self.responses["tranco_whitelist"]
        for line in response.text.splitlines():
            domain = line.split(",")[1]
            domain.strip()
            self.db.store_tranco_whitelisted_domain(domain)

        self.mark_feed_as_updated("tranco_whitelist")

    def download_mac_db(self):
        """
        saves the mac db response to self.responses
        """
        response = self.download_file(self.mac_db_link)
        if not response:
            return False

        self.responses["mac_db"] = response
        return True

    def should_update_mac_db(self) -> bool:
        """
        checks whether or not slips should download the mac db based on
        its availability on disk and the update period

        the response will be stored in self.responses if the file is old
        and needs to be updated
        """
        if not self.is_mac_db_file_on_disk():
            # whether the period passed or not, the db needs to be
            # re-downloaded
            return self.download_mac_db()

        if not self.did_update_period_pass(
            self.mac_db_update_period, self.mac_db_link
        ):
            # Update period hasn't passed yet, the file is on disk and
            # up to date
            self.loaded_ti_files += 1
            return False

        return self.download_mac_db()

    def delete_unused_cached_remote_feeds(self):
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

    def handle_exception(self, task):
        """
        in asyncmodules we use Async.Task to run some of the functions
        If an exception occurs in a coroutine that was wrapped in a Task
        (e.g., asyncio.create_task), the exception does not crash the program
         but remains in the task.
        This function is used to handle the exception in the task
        """
        try:
            # Access task result to raise the exception if it occurred
            task.result()
        except asyncio.exceptions.CancelledError:
            # like pressing ctrl+c
            return
        except Exception as e:
            self.print(e, 0, 1)

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

            if self.should_update_mac_db():
                self.update_mac_db()

            if self.should_update_online_whitelist():
                self.update_online_whitelist()

            ############### Update remote TI files ################
            # Check if the remote file is newer than our own
            # For each file that we should update`
            files_to_download = {}
            files_to_download.update(self.url_feeds)
            files_to_download.update(self.ja3_feeds)
            files_to_download.update(self.ssl_feeds)

            # before updating any feeds, make sure that the cached feeds
            # are not using any feed that is not given in the config of
            # this run (self.url_feeds, self.ja3_feeds, self.ssl_feeds)
            self.delete_unused_cached_remote_feeds()

            for file_to_download in files_to_download:
                if self.should_update(file_to_download, self.update_period):
                    # failed to get the response, either a server problem
                    # or the file is up to date so the response isn't needed
                    # either way __check_if_update handles the error printing

                    # this run wasn't started with existing ti files in the db
                    self.first_time_reading_files = True

                    # every function call to update_TI_file is now running
                    # concurrently instead of serially
                    # so when a server's taking a while to give us the TI
                    # feed, we proceed to download the next file instead of
                    # being idle
                    task = asyncio.create_task(
                        self.update_ti_file(file_to_download)
                    )
                    task.add_done_callback(self.handle_exception)
            #######################################################
            # in case of riskiq files, we don't have a link for them in ti_files, We update these files using their API
            # check if we have a username and api key and a week has passed since we last updated
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
        self.update_finished.add_done_callback(self.handle_exception)

        await self.update_finished
        self.print(
            f"{self.db.get_loaded_ti_feeds_number()} "
            f"TI files successfully loaded."
        )

    def shutdown_gracefully(self):
        # terminating the timer for the process to be killed
        self.timer_manager.cancel()
        self.mac_db_update_manager.cancel()
        self.online_whitelist_update_timer.cancel()
        return True

    def pre_main(self):
        """this method runs only once"""
        utils.drop_root_privs()
        try:
            # only one instance of slips should be able to update TI files at a time
            # so this function will only be allowed to run from 1 slips instance.
            with Lock(name="slips_macdb_and_whitelist_and_TI_files_update"):
                asyncio.run(self.update_ti_files())
                # Starting timer to update files
                self.timer_manager.start()
                self.mac_db_update_manager.start()
                self.online_whitelist_update_timer.start()
                # we have to return 1 for the process to terminate
                return True
        except CannotAcquireLock:
            # another instance of slips is updating TI files, tranco
            # whitelists and mac db
            return 1

    def main(self):
        """
        nothing should run in a loop in this module
        """
        pass
