# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>

# SPDX-License-Identifier: GPL-2.0-only


import os

from slips_files.common.slips_utils import utils


class LocalFeedUpdaterMixin:
    """Update local feed files and local port metadata."""

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
            self._mark_feed_as_updated(file_path, extra_info=file_info)
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
