# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
import subprocess

# SPDX-License-Identifier: GPL-2.0-only
import psutil
import sys
import os
import shutil
import json
from typing import (
    Tuple,
    Set,
)

from slips_files.common.slips_utils import utils


class MetadataManager:
    def __init__(self, main):
        self.main = main
        self.enable_metadata = self.main.conf.enable_metadata()

    def get_pid_using_port(self, port):
        """
        Returns the PID of the process using the given port or
        False if no process is using it
        """
        port = int(port)
        for conn in psutil.net_connections():
            if conn.laddr.port == port:
                return psutil.Process(conn.pid).pid  # .name()
        return None

    def _add_metadata(self):
        """
        Create a metadata dir output/metadata/ that has a copy of
        slips.yaml, whitelist.conf, current commit and date
        """
        metadata_dir = os.path.join(self.main.args.output, "metadata")
        try:
            os.mkdir(metadata_dir)
        except FileExistsError:
            # if the file exists it will be overwritten
            pass

        config_file = self.main.args.config or "config/slips.yaml"
        shutil.copy(config_file, metadata_dir)

        # Add a copy of whitelist.conf
        whitelist = self.main.conf.local_whitelist_path()
        shutil.copy(whitelist, metadata_dir)

        now = utils.get_human_readable_datetime()

        self.info_path = os.path.join(metadata_dir, "info.txt")
        cmd = " ".join(sys.argv)
        with open(self.info_path, "w") as f:
            f.write(
                f"Slips version: {self.main.version}\n"
                f"File: {self.main.input_information}\n"
                f"Branch: {self.main.db.get_branch()}\n"
                f"Commit: {self.main.db.get_commit()}\n"
                f"Command: {cmd}\n"
                f"Slips start date: {now}\n"
            )
            if hasattr(self.main, "zeek_bro"):
                f.write(f"Zeek version: {self.main.db.get_zeek_version()}\n")

        self.main.print(f"Metadata added to {metadata_dir}")
        return self.info_path

    def set_analysis_end_date(self, end_date):
        """
        Add the analysis end date to the metadata file and
        the db for the web interface to display
        """
        if not self.enable_metadata:
            return

        end_date = utils.convert_format(end_date, utils.alerts_format)
        self.main.db.set_input_metadata({"analysis_end": end_date})

        # add slips end date in the metadata dir
        try:
            with open(self.info_path, "a") as f:
                f.write(f"Slips end date: {end_date}\n")
        except (NameError, AttributeError):
            pass
        return end_date

    def get_zeek_version(self) -> str:
        """
        Get the version of zeek/bro used if zeek is used. (e.g. in pcaps
        and interface)
        """
        if not self.main.zeek_bro:
            return

        cmd = [self.main.zeek_bro, "--version"]
        version = subprocess.check_output(cmd).decode()
        return version.split("version ")[1]

    def set_input_metadata(self):
        """
        save info about name, size, analysis start date in the db
        """
        now = utils.get_human_readable_datetime()
        to_ignore: dict = self.main.conf.get_disabled_modules(
            self.main.input_type
        )
        info = {
            "slips_version": self.main.version,
            "name": self.main.input_information,
            "analysis_start": now,
            "disabled_modules": json.dumps(to_ignore),
            "output_dir": self.main.args.output,
            "input_type": self.main.input_type,
            "evidence_detection_threshold": self.main.conf.evidence_detection_threshold(),
        }

        if hasattr(self.main, "zeek_dir"):
            info.update({"zeek_dir": self.main.zeek_dir})

        if hasattr(self.main, "zeek_bro") and self.main.zeek_bro:
            info.update({"zeek_version": self.get_zeek_version()})

        size_in_mb = "-"
        if self.main.args.filepath not in (False, None) and os.path.exists(
            self.main.args.filepath
        ):
            size = os.stat(self.main.args.filepath).st_size
            size_in_mb = float(size) / (1024 * 1024)
            size_in_mb = format(float(size_in_mb), ".2f")

        info.update(
            {
                "size_in_MB": size_in_mb,
            }
        )
        # analysis end date will be set in shutdown_gracefully
        # file(pcap,netflow, etc.) start date will be set in
        self.main.db.set_input_metadata(info)

    def update_slips_stats_in_the_db(self) -> Tuple[int, Set[str]]:
        """
        updates the number of processed ips, slips internal time,
         and modified tws so far in the db
        """
        slips_internal_time = float(self.main.db.get_slips_internal_time()) + 1

        # Get the amount of modified profiles since we last checked
        # this is the modification time of the last timewindow
        last_modified_tw_time: float
        (
            modified_profiles,
            last_modified_tw_time,
        ) = self.main.db.get_modified_profiles_since(slips_internal_time)
        modified_ips_in_the_last_tw = len(modified_profiles)
        self.main.db.set_input_metadata(
            {"modified_ips_in_the_last_tw": modified_ips_in_the_last_tw}
        )
        # last_modified_tw_time is 0 the moment we start slips
        # or if we don't have modified tw since the last slips_internal_time
        if last_modified_tw_time != 0:
            self.main.db.set_slips_internal_time(last_modified_tw_time)
        return modified_ips_in_the_last_tw, modified_profiles

    def add_metadata_if_enabled(self):
        if not self.enable_metadata:
            return
        self.info_path = self._add_metadata()
