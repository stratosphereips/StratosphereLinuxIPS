# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import datetime
import sqlite3
import time

from slips_files.common.abstracts.isqlite import ISQLite
from slips_files.common.printer import Printer
from slips_files.core.output import Output


class TrustDB(ISQLite):
    name = "p2p_trust_db"

    def __init__(
        self,
        logger: Output,
        db_file: str,
        main_pid: int,
        drop_tables_on_startup: bool = False,
    ):
        """create a database connection to a SQLite database"""
        self.printer = Printer(logger, self.name)
        # connects to the db
        super().__init__(
            self.name.replace(" ", "_").lower(), main_pid, db_file
        )
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
            "report_aggregates": (
                "key_type TEXT NOT NULL, "
                "reported_key TEXT NOT NULL, "
                "reporter_peerid TEXT NOT NULL, "
                "reporter_ip TEXT NOT NULL, "
                "report_count INTEGER NOT NULL, "
                "score_sum REAL NOT NULL, "
                "confidence_sum REAL NOT NULL, "
                "PRIMARY KEY (key_type, reported_key, reporter_peerid, "
                "reporter_ip)"
            ),
            "report_compaction_state": (
                "id INTEGER PRIMARY KEY CHECK (id = 1), "
                "last_report_id INTEGER NOT NULL, "
                "database_vacuumed INTEGER NOT NULL DEFAULT 0"
            ),
        }

        for table, schema in table_schema.items():
            self.create_table(table, schema)

        # These tables are persistent and their row counts grow over time.
        # Opinion calculation looks up reports and peer metadata for every
        # previously unseen IP, so keep those lookups indexed.
        indexes = (
            "CREATE INDEX IF NOT EXISTS reports_key_type_idx "
            "ON reports(reported_key, key_type)",
            "CREATE INDEX IF NOT EXISTS peer_ips_peer_time_idx "
            "ON peer_ips(peerid, update_time DESC)",
            "CREATE INDEX IF NOT EXISTS go_reliability_peer_idx "
            "ON go_reliability(peerid)",
            "CREATE INDEX IF NOT EXISTS slips_reputation_ip_time_idx "
            "ON slips_reputation(ipaddress, update_time DESC)",
        )
        for index in indexes:
            self.execute(index)
        self.execute(
            "CREATE INDEX IF NOT EXISTS report_aggregates_key_idx "
            "ON report_aggregates(reported_key, key_type)"
        )
        self.execute(
            "INSERT OR IGNORE INTO report_compaction_state "
            "(id, last_report_id, database_vacuumed) VALUES (1, 0, 0)"
        )

    def delete_tables(self):
        tables = [
            "opinion_cache",
            "slips_reputation",
            "go_reliability",
            "peer_ips",
            "reports",
            "report_aggregates",
            "report_compaction_state",
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

    def get_reporter_peerids_for_ip(self, ipaddress: str) -> set[str]:
        """Return the peer IDs represented by raw or compacted IP reports.

        Parameters:
            ipaddress: The reported IP address.

        Returns:
            The peer IDs whose reports contributed to this IP.
        """
        raw_reporters = self.select(
            table_name="reports",
            columns="DISTINCT reporter_peerid",
            condition="reported_key = ? AND key_type = ?",
            params=(ipaddress, "ip"),
        ) or []
        compact_reporters = self.select(
            table_name="report_aggregates",
            columns="DISTINCT reporter_peerid",
            condition="reported_key = ? AND key_type = ?",
            params=(ipaddress, "ip"),
        ) or []
        return {row[0] for row in raw_reporters + compact_reporters if row[0]}

    def compact_reports(self, batch_size: int = 500) -> bool:
        """Fold mapped raw IP reports into per-peer totals in a small batch.

        Reports without a peer IP mapping at the report timestamp stay raw,
        preserving their ability to contribute if the mapping arrives later.

        Parameters:
            batch_size: Maximum raw report rows to inspect per call.

        Returns:
            True when no more raw report rows remain after the saved cursor.
        """
        if batch_size <= 0:
            raise ValueError("batch_size must be positive")

        compaction_complete = False
        should_vacuum = False
        with self.conn_lock:
            with self._acquire_flock():
                cursor = self.conn.cursor()
                cursor.execute("BEGIN")
                try:
                    last_id, database_vacuumed = cursor.execute(
                        "SELECT last_report_id, database_vacuumed "
                        "FROM report_compaction_state WHERE id = 1"
                    ).fetchone()
                    reports = cursor.execute(
                        "SELECT id, reporter_peerid, key_type, reported_key, "
                        "score, confidence, update_time FROM reports "
                        "WHERE id > ? ORDER BY id LIMIT ?",
                        (last_id, batch_size),
                    ).fetchall()
                    if not reports:
                        self.conn.commit()
                        compaction_complete = True
                        should_vacuum = database_vacuumed == 0
                    else:
                        for (
                            report_id,
                            reporter_peerid,
                            key_type,
                            reported_key,
                            score,
                            confidence,
                            report_time,
                        ) in reports:
                            if key_type != "ip":
                                continue
                            mapping = cursor.execute(
                                "SELECT MAX(update_time), ipaddress "
                                "FROM peer_ips WHERE update_time <= ? "
                                "AND peerid = ?",
                                (report_time, reporter_peerid),
                            ).fetchone()
                            if not mapping or not mapping[1]:
                                continue

                            cursor.execute(
                                "INSERT INTO report_aggregates "
                                "(key_type, reported_key, reporter_peerid, "
                                "reporter_ip, report_count, score_sum, "
                                "confidence_sum) VALUES (?, ?, ?, ?, 1, ?, ?) "
                                "ON CONFLICT (key_type, reported_key, "
                                "reporter_peerid, reporter_ip) DO UPDATE SET "
                                "report_count = report_count + 1, "
                                "score_sum = score_sum + excluded.score_sum, "
                                "confidence_sum = confidence_sum + "
                                "excluded.confidence_sum",
                                (
                                    key_type,
                                    reported_key,
                                    reporter_peerid,
                                    mapping[1],
                                    score,
                                    confidence,
                                ),
                            )
                            cursor.execute(
                                "DELETE FROM reports WHERE id = ?",
                                (report_id,),
                            )

                        cursor.execute(
                            "UPDATE report_compaction_state "
                            "SET last_report_id = ? WHERE id = 1",
                            (reports[-1][0],),
                        )
                        self.conn.commit()
                except Exception:
                    self.conn.rollback()
                    raise
        if should_vacuum:
            self.shrink_compacted_database()
        return compaction_complete

    def shrink_compacted_database(self) -> bool:
        """Reclaim SQLite pages freed by report compaction.

        Returns:
            True if VACUUM completed successfully, otherwise False.
        """
        try:
            with self.conn_lock:
                with self._acquire_flock():
                    self.conn.execute("VACUUM")
            self.execute(
                "UPDATE report_compaction_state SET database_vacuumed = 1 "
                "WHERE id = 1"
            )
            return True
        except sqlite3.Error as error:
            self.print(
                f"Could not reclaim compacted P2P database space: {error}",
                0,
                1,
            )
            self.execute(
                "UPDATE report_compaction_state SET database_vacuumed = 2 "
                "WHERE id = 1"
            )
            return False

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
        grouped_reports = {}
        compact_reports = self.select(
            table_name="report_aggregates",
            columns=(
                "reporter_peerid, reporter_ip, report_count, score_sum, "
                "confidence_sum"
            ),
            condition="reported_key = ? AND key_type = ?",
            params=(ipaddress, "ip"),
        ) or []
        for reporter_peerid, reporter_ip, count, score_sum, confidence_sum in compact_reports:
            grouped_reports[(reporter_peerid, reporter_ip)] = [
                count,
                score_sum,
                confidence_sum,
            ]

        for (
            reporter_peerid,
            report_timestamp,
            report_score,
            report_confidence,
            _reported_ip,
        ) in self.get_reports_for_ip(ipaddress) or []:
            reporter_ip = self.get_reporter_ip(
                reporter_peerid, report_timestamp
            )
            if not reporter_ip or reporter_ip == ipaddress:
                continue
            key = (reporter_peerid, reporter_ip)
            totals = grouped_reports.setdefault(key, [0, 0.0, 0.0])
            totals[0] += 1
            totals[1] += report_score
            totals[2] += report_confidence

        reporters_scores = []
        for (reporter_peerid, reporter_ip), (
            report_count,
            report_score_sum,
            report_confidence_sum,
        ) in grouped_reports.items():
            if reporter_ip == ipaddress:
                continue
            reporter_reliability = self.get_reporter_reliability(
                reporter_peerid
            )
            if reporter_reliability is None:
                continue
            reporter_score, reporter_confidence = self.get_reporter_reputation(
                reporter_ip
            )
            if reporter_score is None or reporter_confidence is None:
                continue
            reporters_scores.append(
                (
                    report_score_sum,
                    report_confidence_sum,
                    reporter_reliability,
                    reporter_score,
                    reporter_confidence,
                    reporter_ip,
                    report_count,
                )
            )
        return reporters_scores


if __name__ == "__main__":
    trustDB = TrustDB("trustdb.db")
