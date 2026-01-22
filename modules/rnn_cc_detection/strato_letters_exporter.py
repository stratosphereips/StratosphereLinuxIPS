# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import csv
import os

from slips_files.common.parsers.config_parser import ConfigParser


class StratoLettersExporter:
    """exports the letters to strato_letters.tsv in the slips output dir
    before slips stops."""

    def __init__(self, db):
        self.db = db
        self.read_configuration()

    def read_configuration(self):
        conf = ConfigParser()
        self.should_export: bool = conf.export_strato_letters()

    def init(self):
        """creates the strato_letters tsv file with the needed headers"""
        if not self.should_export:
            return

        output_dir = self.db.get_output_dir()
        self.starto_letters_file: str = os.path.join(
            output_dir, "strato_letters.tsv"
        )
        open(self.starto_letters_file, "w").close()

        with open(self.starto_letters_file, "w") as f:
            writer = csv.writer(f, delimiter="\t")
            writer.writerow(["Outtuple", "Letters"])

    def export(self, profileid: str, twid: str):
        """
        exports starto letters to the file specified in
        self.starto_letters_file
        """
        if not self.should_export:
            return

        saddr = profileid.split("_")[-1]
        with open(self.starto_letters_file, "a") as f:
            writer = csv.writer(f, delimiter="\t")
            for tupleid, symbols in self.db.get_outtuples_from_profile_tw(
                profileid, twid
            ):
                tupleid: str
                writer.writerow([f"{saddr}-{tupleid}-{twid}", symbols])
