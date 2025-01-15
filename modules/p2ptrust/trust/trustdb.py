# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import sqlite3
import datetime
import time
from slips_files.common.printer import Printer
from slips_files.core.output import Output


class TrustDB:
    name = "P2P Trust DB"

    def __init__(
        self,
        logger: Output,
        db_file: str,
        drop_tables_on_startup: bool = False,
    ):
        """create a database connection to a SQLite database"""
        self.printer = Printer(logger, self.name)
        self.conn = sqlite3.connect(db_file)
        if drop_tables_on_startup:
            self.print("Dropping tables")
            self.delete_tables()

        self.create_tables()
        # self.insert_slips_score("8.8.8.8", 0.0, 0.9)
        # self.get_opinion_on_ip("zzz")

    def __del__(self):
        self.conn.close()

    def print(self, *args, **kwargs):
        return self.printer.print(*args, **kwargs)

    def create_tables(self):
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS slips_reputation ("
            "id INTEGER PRIMARY KEY NOT NULL, "
            "ipaddress TEXT NOT NULL, "
            "score REAL NOT NULL, "
            "confidence REAL NOT NULL, "
            "update_time REAL NOT NULL);"
        )

        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS go_reliability ("
            "id INTEGER PRIMARY KEY NOT NULL, "
            "peerid TEXT NOT NULL, "
            "reliability REAL NOT NULL, "
            "update_time REAL NOT NULL);"
        )

        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS peer_ips ("
            "id INTEGER PRIMARY KEY NOT NULL, "
            "ipaddress TEXT NOT NULL, "
            "peerid TEXT NOT NULL, "
            "update_time REAL NOT NULL);"
        )

        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS reports ("
            "id INTEGER PRIMARY KEY NOT NULL, "
            "reporter_peerid TEXT NOT NULL, "
            "key_type TEXT NOT NULL, "
            "reported_key TEXT NOT NULL, "
            "score REAL NOT NULL, "
            "confidence REAL NOT NULL, "
            "update_time REAL NOT NULL);"
        )

        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS opinion_cache ("
            "key_type TEXT NOT NULL, "
            "reported_key TEXT NOT NULL PRIMARY KEY, "
            "score REAL NOT NULL, "
            "confidence REAL NOT NULL, "
            "network_score REAL NOT NULL, "
            "update_time DATE NOT NULL);"
        )

    def delete_tables(self):
        self.conn.execute("DROP TABLE IF EXISTS opinion_cache;")
        self.conn.execute("DROP TABLE IF EXISTS slips_reputation;")
        self.conn.execute("DROP TABLE IF EXISTS go_reliability;")
        self.conn.execute("DROP TABLE IF EXISTS peer_ips;")
        self.conn.execute("DROP TABLE IF EXISTS reports;")

    def insert_slips_score(
        self, ip: str, score: float, confidence: float, timestamp: int = None
    ):
        if timestamp is None:
            timestamp = time.time()
        parameters = (ip, score, confidence, timestamp)
        self.conn.execute(
            "INSERT INTO slips_reputation (ipaddress, score, confidence, update_time) "
            "VALUES (?, ?, ?, ?);",
            parameters,
        )
        self.conn.commit()

    def insert_go_reliability(
        self, peerid: str, reliability: float, timestamp: int = None
    ):
        if timestamp is None:
            timestamp = datetime.datetime.now()

        parameters = (peerid, reliability, timestamp)
        self.conn.execute(
            "INSERT INTO go_reliability (peerid, reliability, update_time) "
            "VALUES (?, ?, ?);",
            parameters,
        )
        self.conn.commit()

    def insert_go_ip_pairing(
        self, peerid: str, ip: str, timestamp: int = None
    ):
        if timestamp is None:
            timestamp = datetime.datetime.now()

        parameters = (ip, peerid, timestamp)
        self.conn.execute(
            "INSERT INTO peer_ips (ipaddress, peerid, update_time) "
            "VALUES (?, ?, ?);",
            parameters,
        )
        self.conn.commit()

    def insert_new_go_data(self, reports: list):
        self.conn.executemany(
            "INSERT INTO reports "
            "(reporter_peerid, key_type, reported_key, score, confidence, update_time) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            reports,
        )
        self.conn.commit()

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
            timestamp = datetime.datetime.now()
        timestamp = time.time()

        parameters = (
            reporter_peerid,
            key_type,
            reported_key,
            score,
            confidence,
            timestamp,
        )
        self.conn.execute(
            "INSERT INTO reports "
            "(reporter_peerid, key_type, reported_key, score, confidence, update_time) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            parameters,
        )
        self.conn.commit()

    def update_cached_network_opinion(
        self,
        key_type: str,
        reported_key: str,
        score: float,
        confidence: float,
        network_score: float,
    ):
        self.conn.execute(
            "REPLACE INTO"
            " opinion_cache (key_type, reported_key, score, confidence, network_score, update_time)"
            "VALUES (?, ?, ?, ?, ?, strftime('%s','now'));",
            (key_type, reported_key, score, confidence, network_score),
        )
        self.conn.commit()

    def get_cached_network_opinion(self, key_type: str, reported_key: str):
        cache_cur = self.conn.execute(
            "SELECT score, confidence, network_score, update_time "
            "FROM opinion_cache "
            "WHERE key_type = ? "
            "  AND reported_key = ? "
            "ORDER BY update_time LIMIT 1;",
            (key_type, reported_key),
        )

        result = cache_cur.fetchone()
        if result is None:
            result = None, None, None, None
        return result

    def get_ip_of_peer(self, peerid):
        """
        Returns the latest IP seen associated with the given peerid
        :param peerid: the id of the peer we want the ip of
        """
        cache_cur = self.conn.execute(
            "SELECT MAX(update_time) AS ip_update_time, ipaddress FROM peer_ips WHERE peerid = ?;",
            ((peerid),),
        )
        if res := cache_cur.fetchone():
            last_update_time, ip = res
            return last_update_time, ip
        return False, False

    def get_reports_for_ip(self, ipaddress):
        """
        Returns a list of all reports for the given IP address.
        """
        reports_cur = self.conn.execute(
            "SELECT reports.reporter_peerid, reports.update_time, reports.score, "
            "       reports.confidence, reports.reported_key "
            "FROM reports "
            "WHERE reports.reported_key = ? AND reports.key_type = 'ip'"
            "ORDER BY reports.update_time DESC;",
            (ipaddress,),
        )
        return reports_cur.fetchall()

    def get_reporter_ip(self, reporter_peerid, report_timestamp):
        """
        Returns the IP address of the reporter at the time of the report.
        """
        ip_cur = self.conn.execute(
            "SELECT MAX(update_time), ipaddress "
            "FROM peer_ips "
            "WHERE update_time <= ? AND peerid = ? "
            "ORDER BY update_time DESC "
            "LIMIT 1;",
            (report_timestamp, reporter_peerid),
        )
        if res := ip_cur.fetchone():
            return res[1]
        return None

    def get_reporter_reliability(self, reporter_peerid):
        """
        Returns the latest reliability score for the given peer.
        """
        go_reliability_cur = self.conn.execute(
            "SELECT reliability "
            "FROM go_reliability "
            "WHERE peerid = ? "
            "ORDER BY update_time DESC "
            "LIMIT 1;"
        )
        if res := go_reliability_cur.fetchone():
            return res[0]
        return None

    def get_reporter_reputation(self, reporter_ipaddress):
        """
        Returns the latest reputation score and confidence for the given IP address.
        """
        slips_reputation_cur = self.conn.execute(
            "SELECT score, confidence "
            "FROM slips_reputation "
            "WHERE ipaddress = ? "
            "ORDER BY update_time DESC "
            "LIMIT 1;",
            (reporter_ipaddress,),
        )
        if res := slips_reputation_cur.fetchone():
            return res
        return None, None

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

            reporters_scores.append(
                (
                    report_score,
                    report_confidence,
                    reporter_reliability,
                    reporter_score,
                    reporter_confidence,
                )
            )

        return reporters_scores


if __name__ == "__main__":
    trustDB = TrustDB(r"trustdb.db")
