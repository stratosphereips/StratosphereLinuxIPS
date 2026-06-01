# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>

# SPDX-License-Identifier: GPL-2.0-only


import json
import os
import time
from typing import IO, Optional, Tuple

from slips_files.common.slips_utils import utils


class TIFeedParserMixin:
    """Parse IP, domain, range, and JSON threat intelligence feeds."""

    def parse_tor_nodes_feed(self, feed_path: str) -> bool:
        """
        This feed is a list of IPs, one per line.
        :param feed_path: path of the downloaded tor nodes list
        """
        nodes = set()
        with open(feed_path) as feed:
            for line in feed.read().splitlines():

                if line.startswith("#") or line.isspace():
                    continue

                ip = line.strip()
                if utils.is_ignored_ip(ip):
                    continue

                nodes.add(ip)

        self.db.store_tor_nodes(nodes)
        return True

    def _parse_json_ti_feed(self, link_to_download, ti_file_path: str) -> bool:
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

                    if diff > self.max_days_to_keep_ti_files:
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

    def _is_valid_ti_file(self, ti_file_path: str) -> bool:
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

    def _is_header_line(self, line) -> bool:
        for keyword in self.header_keywords:
            if line.startswith(keyword):
                return True
        return False

    def _get_feed_structure(self, ti_file_path: str) -> Tuple[int]:
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
                if not header_line_found and self._is_header_line(line):
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

    def _normalize_line(self, ti_file_path: str, line: str) -> str:
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

    def _extract_domain_info(
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

    def _extract_ip_info(
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

    def _extract_ip_range_info(
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

    def _is_valid_ioc_and_description(
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
        if not self._is_valid_ti_file(ti_file_path):
            return False

        if "json" in ti_file_path:
            return self._parse_json_ti_feed(feed_link, ti_file_path)

        structure: Tuple[int] = self._get_feed_structure(ti_file_path)
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

            line = self._normalize_line(ti_file_path, line)
            ioc, description = self.extract_ioc_from_line(
                line,
                line_fields,
                separator,
                data_col,
                description_col,
                ti_file_path,
            )

            if not self._is_valid_ioc_and_description(
                ioc, description, ti_file_path
            ):
                continue

            data_type = utils.detect_ioc_type(ioc)
            handlers = {
                "domain": self._extract_domain_info,
                "ip": self._extract_ip_info,
                "ip_range": self._extract_ip_range_info,
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
