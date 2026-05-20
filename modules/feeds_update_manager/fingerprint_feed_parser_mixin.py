# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>

# SPDX-License-Identifier: GPL-2.0-only


import json
import traceback


class FingerprintFeedParserMixin:
    """Parse JA3 and SSL fingerprint feeds."""

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
