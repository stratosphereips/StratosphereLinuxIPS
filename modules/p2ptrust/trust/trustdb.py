# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import sqlite3
import datetime
import time

from slips_files.common.abstracts.sqlite import ISQLite
from slips_files.common.printer import Printer
from slips_files.core.output import Output
from slips_files.common.slips_utils import utils


class TrustDB(ISQLite):
    name = "P2P Trust DB"

    def __init__(
        self,
        logger: Output,
        db_file: str,
        drop_tables_on_startup: bool = False,
    ):
        """create a database connection to a SQLite database"""
        self.printer = Printer(logger, self.name)
        self.conn = sqlite3.connect(
            db_file, check_same_thread=False, timeout=20
        )
        self.cursor = self.conn.cursor()
        if drop_tables_on_startup:
            self.print("Dropping tables")
            self.delete_tables()

        self.create_tables()
        super().__init__()

    def __del__(self):
        self.conn.close()

    def create_tables(self):
        table_schema = {
            "slips_reputation": (
                "id INTEGER PRIMARY KEY NOT NULL, "
                "ipaddress TEXT NOT NULL, "
                "score REAL NOT NULL, "
                "confidence REAL NOT NULL, "
                "update_time REAL NOT NULL"
            ),
            "go_reliability": (
                "id INTEGER PRIMARY KEY NOT NULL, "
                "peerid TEXT NOT NULL, "
                "reliability REAL NOT NULL, "
                "update_time REAL NOT NULL"
            ),
            "peer_ips": (
                "id INTEGER PRIMARY KEY NOT NULL, "
                "ipaddress TEXT NOT NULL, "
                "peerid TEXT NOT NULL, "
                "update_time REAL NOT NULL"
            ),
            "reports": (
                "id INTEGER PRIMARY KEY NOT NULL, "
                "reporter_peerid TEXT NOT NULL, "
                "key_type TEXT NOT NULL, "
                "reported_key TEXT NOT NULL, "
                "score REAL NOT NULL, "
                "confidence REAL NOT NULL, "
                "update_time REAL NOT NULL"
            ),
            "opinion_cache": (
                "key_type TEXT NOT NULL, "
                "reported_key TEXT NOT NULL PRIMARY KEY, "
                "score REAL NOT NULL, "
                "confidence REAL NOT NULL, "
                "network_score REAL NOT NULL, "
                "update_time DATE NOT NULL"
            ),
        }

        for table, schema in table_schema.items():
            self.create_table(table, schema)

    def delete_tables(self):
        tables = [
            "opinion_cache",
            "slips_reputation",
            "go_reliability",
            "peer_ips",
            "reports",
        ]
        for table in tables:
            self.execute(f"DROP TABLE IF EXISTS {table};")

    def insert_slips_score(
        self, ip: str, score: float, confidence: float, timestamp: int = None
    ):
        if timestamp is None:
            timestamp = time.time()
        parameters = (ip, score, confidence, timestamp)
        self.execute(
            "INSERT INTO slips_reputation "
            "(ipaddress, score, confidence, update_time) "
            "VALUES (?, ?, ?, ?);",
            parameters,
        )

    def insert_go_reliability(
        self, peerid: str, reliability: float, timestamp: int = None
    ):
        if timestamp is None:
            timestamp = datetime.datetime.now()

        parameters = (peerid, reliability, timestamp)
        self.execute(
            "INSERT INTO go_reliability (peerid, reliability, update_time) "
            "VALUES (?, ?, ?);",
            parameters,
        )

    def insert_go_ip_pairing(
        self, peerid: str, ip: str, timestamp: int = None
    ):
        if timestamp is None:
            timestamp = datetime.datetime.now()

        parameters = (ip, peerid, timestamp)
        self.execute(
            "INSERT INTO peer_ips (ipaddress, peerid, update_time) "
            "VALUES (?, ?, ?);",
            parameters,
        )

    def insert_new_go_data(self, reports: list):
        self.executemany(
            "INSERT INTO reports "
            "(reporter_peerid, key_type, reported_key, "
            "score, confidence, update_time) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            reports,
        )

    def insert_new_go_report(
        self,
        reporter_peerid: str,
        key_type: str,
        reported_key: str,
        score: float,
        confidence: float,
        timestamp: int = None,
    ):
        # print(f"*** [debugging p2p] ***  [insert_new_go_report] is called. receieved "
        #       f"from {reporter_peerid} a report about {reported_key} "
        #       f"score: {score} confidence: {confidence} timestamp: {timestamp} ")

        if timestamp is None:
            timestamp = time.time()

        parameters = (
            reporter_peerid,
            key_type,
            reported_key,
            score,
            confidence,
            timestamp,
        )
        self.execute(
            "INSERT INTO reports "
            "(reporter_peerid, key_type, reported_key, "
            "score, confidence, update_time) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            parameters,
        )

    def update_cached_network_opinion(
        self,
        key_type: str,
        reported_key: str,
        score: float,
        confidence: float,
        network_score: float,
    ):
        self.execute(
            "REPLACE INTO"
            " opinion_cache (key_type, reported_key, "
            "score, confidence, network_score, update_time)"
            "VALUES (?, ?, ?, ?, ?, strftime('%s','now'));",
            (key_type, reported_key, score, confidence, network_score),
        )

    def get_cached_network_opinion(self, key_type: str, reported_key: str):
        condition = (
            f'key_type = "{utils.sanitize(key_type)}" '
            f'AND reported_key = "{utils.sanitize(reported_key)}" '
            f"ORDER BY update_time LIMIT 1"
        )
        self.select(
            table_name="opinion_cache",
            columns="score, confidence, network_score, update_time",
            condition=condition,
        )
        result = self.fetchone()
        print(f"@@@@@@@@@@@@@@@@ get_cached_network_opinion result: {result}")
        if result is None:
            result = None, None, None, None
        return result

    def get_ip_of_peer(self, peerid):
        """
        Returns the latest IP seen associated with the given peerid
        :param peerid: the id of the peer we want the ip of
        """
        condition = f'peerid = "{utils.sanitize(peerid)}" '
        self.select(
            table_name="peer_ips",
            columns="MAX(update_time) AS ip_update_time, ipaddress",
            condition=condition,
        )
        if res := self.fetchone():
            last_update_time, ip = res
            return last_update_time, ip
        return False, False

    def get_reports_for_ip(self, ipaddress):
        """
        Returns a list of all reports for the given IP address.
        """
        # get all reports made about this ip
        ipaddress = utils.sanitize(ipaddress)
        condition = f"reported_key = \"{ipaddress}\" AND key_type = 'ip'"
        self.select(
            table_name="reports",
            columns="reporter_peerid, update_time,"
            " score, confidence, reported_key",
            condition=condition,
        )
        return self.fetchall()

    def get_reporter_ip(self, reporter_peerid, report_timestamp):
        """
        Returns the IP address of the reporter at the time of the report.
        """
        reporter_peerid = utils.sanitize(reporter_peerid)
        report_timestamp = utils.sanitize(report_timestamp)
        condition = (
            f'update_time <= "{report_timestamp}" AND '
            f'peerid = "{reporter_peerid}"'
        )
        self.select(
            table_name="peer_ips",
            columns="MAX(update_time), ipaddress",
            condition=condition,
        )
        if res := self.fetchone():
            return res[1]
        return None

    def get_reporter_reliability(self, reporter_peerid):
        """
        Returns the latest reliability score for the given peer.
        """
        reporter_peerid = utils.sanitize(reporter_peerid)
        condition = f'peerid = "{reporter_peerid}"'
        self.select(
            table_name="go_reliability",
            columns="reliability",
            condition=condition,
        )
        if res := self.fetchone():
            return res[0]
        return None

    def get_reporter_reputation(self, reporter_ipaddress):
        """
        Returns the latest reputation score and confidence for the given IP address.
        """
        reporter_ipaddress = utils.sanitize(reporter_ipaddress)
        condition = (
            f'ipaddress = "{reporter_ipaddress}" '
            f"ORDER BY update_time DESC "
            f"LIMIT 1;"
        )
        self.select(
            table_name="slips_reputation",
            columns="score, confidence",
            condition=condition,
        )
        if res := self.fetchone():
            return res
        return None, None

    def get_opinion_on_ip(self, ipaddress):
        """
        Returns a list of tuples, where each tuple contains the report score, report confidence,
        reporter reliability, reporter score, and reporter confidence for a given IP address.
        """
        reports = self.get_reports_for_ip(ipaddress)
        print(f"@@@@@@@@@@@@@@@@ trustdb.py. .. reports: {reports}")
        reporters_scores = []

        for (
            reporter_peerid,
            report_timestamp,
            report_score,
            report_confidence,
            reported_ip,
        ) in reports:
            reporter_ipaddress = self.get_reporter_ip(
                reporter_peerid, report_timestamp
            )
            if reporter_ipaddress == ipaddress:
                print(
                    f"@@@@@@@@@@@@@@@@ reporter is the same as the ip "
                    f"were getting opinion for: {reporter_ipaddress}, "
                    f"skipping"
                )
                continue

            reporter_reliability = self.get_reporter_reliability(
                reporter_peerid
            )
            if reporter_reliability is None:
                print(
                    f"@@@@@@@@@@@@@@@@ no reliability, skipping reporter: {reporter_peerid}"
                )
                continue

            reporter_score, reporter_confidence = self.get_reporter_reputation(
                reporter_ipaddress
            )
            if reporter_score is None or reporter_confidence is None:
                print(
                    f"@@@@@@@@@@@@@@@@ reporter_score is None: "
                    f"{reporter_score is None}, OR reporter_confidence is "
                    f"None {reporter_confidence is None} "
                    f"skipping"
                )
                continue

            # TODO update the docs in assemble_peer_opinion() when the
            #  format of this list changes:D
            reporters_scores.append(
                (
                    report_score,
                    report_confidence,
                    reporter_reliability,
                    reporter_score,  # what does slips think about the reporter's ip
                    # how confident slips is about the reporter's ip's score
                    reporter_confidence,
                    reporter_ipaddress,
                )
            )
        print(
            f"@@@@@@@@@@@@@@@@ ok returning reporters_scores: {reporters_scores}"
        )
        return reporters_scores


if __name__ == "__main__":
    trustDB = TrustDB("trustdb.db")
