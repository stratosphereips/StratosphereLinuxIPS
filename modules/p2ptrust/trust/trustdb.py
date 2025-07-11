# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import datetime
import time

from slips_files.common.abstracts.isqlite import ISQLite
from slips_files.common.printer import Printer
from slips_files.core.output import Output


class TrustDB(ISQLite):
    name = "P2P Trust DB"

    def __init__(
        self,
        logger: Output,
        db_file: str,
        main_pid: int,
        drop_tables_on_startup: bool = False,
    ):
        """create a database connection to a SQLite database"""
        self.printer = Printer(logger, self.name)
        self.connect(db_file)
        super().__init__(self.name.replace(" ", "_").lower(), main_pid)
        if drop_tables_on_startup:
            self.print("Dropping tables")
            self.delete_tables()

        self.create_tables()

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

        query = """
            INSERT OR REPLACE INTO slips_reputation
            (ipaddress, score, confidence, update_time)
            VALUES (?, ?, ?, ?)
        """
        self.execute(query, (ip, score, confidence, timestamp))

    def insert_go_reliability(
        self, peerid: str, reliability: float, timestamp: int = None
    ):
        if timestamp is None:
            timestamp = datetime.datetime.now()

        values = (peerid, reliability, timestamp)
        self.insert(
            "go_reliability", values, "peerid, reliability, update_time"
        )

    def insert_go_ip_pairing(
        self, peerid: str, ip: str, timestamp: int = None
    ):
        if timestamp is None:
            timestamp = datetime.datetime.now()

        values = (ip, peerid, timestamp)
        self.insert("peer_ips", values, "ipaddress, peerid, update_time")

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
        self.insert(
            "reports",
            parameters,
            "reporter_peerid, key_type, reported_key, score, "
            "confidence, update_time",
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
        res = self.select(
            table_name="opinion_cache",
            columns="score, confidence, network_score, update_time",
            condition="key_type = ? AND reported_key = ?",
            params=(key_type, reported_key),
            order_by="update_time",
            limit=1,
        )

        if res is None:
            return None, None, None, None
        return res

    def get_ip_of_peer(self, peerid):
        """
        Returns the latest IP seen associated with the given peerid
        :param peerid: the id of the peer we want the ip of
        returns a tuple with  (last_update_time, ip)
        """
        res = self.select(
            table_name="peer_ips",
            columns="MAX(update_time) AS ip_update_time, ipaddress",
            condition="peerid = ?",
            params=(peerid,),
            limit=1,
        )
        return res if res else (False, False)

    def get_reports_for_ip(self, ipaddress):
        """
        Returns a list of all reports for the given IP address.
        """
        return self.select(
            table_name="reports",
            columns="reporter_peerid, update_time, score, confidence, reported_key",
            condition="reported_key = ? AND key_type = ?",
            params=(ipaddress, "ip"),
        )

    def get_reporter_ip(self, reporter_peerid, report_timestamp) -> str:
        """
        Returns the IP address of the reporter at the time of the report.
        """
        res = self.select(
            table_name="peer_ips",
            columns="MAX(update_time), ipaddress",
            condition="update_time <= ? AND peerid = ?",
            params=(report_timestamp, reporter_peerid),
            limit=1,
        )

        if res:
            return res[1]  # Return the IP address
        return None

    def get_reporter_reliability(self, reporter_peerid):
        """
        Returns the latest reliability score for the given peer.
        """
        res = self.select(
            table_name="go_reliability",
            columns="reliability",
            condition="peerid = ?",
            params=(reporter_peerid,),
            limit=1,
        )

        try:
            return res[0]
        except IndexError:
            return None

    def get_reporter_reputation(self, reporter_ipaddress):
        """
        returns the latest reputation score and confidence for the given IP address.
        """
        res = self.select(
            table_name="slips_reputation",
            columns="score, confidence",
            condition="ipaddress = ?",
            params=(reporter_ipaddress,),
            order_by="update_time DESC",
            limit=1,
        )

        return res or (None, None)

    def get_opinion_on_ip(self, ipaddress):
        """
        Returns a list of tuples, where each tuple contains the report score, report confidence,
        reporter reliability, reporter score, and reporter confidence for a given IP address.
        """
        reports = self.get_reports_for_ip(ipaddress)

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
                continue

            reporter_reliability = self.get_reporter_reliability(
                reporter_peerid
            )
            if reporter_reliability is None:
                continue

            reporter_score, reporter_confidence = self.get_reporter_reputation(
                reporter_ipaddress
            )
            if reporter_score is None or reporter_confidence is None:
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
        return reporters_scores


if __name__ == "__main__":
    trustDB = TrustDB("trustdb.db")
