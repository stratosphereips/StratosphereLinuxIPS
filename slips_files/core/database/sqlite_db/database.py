# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from datetime import datetime
from typing import List, Dict
import os.path
import json
import csv
import math
import time
import sqlite3
from dataclasses import asdict
from types import SimpleNamespace
from modules.supported_module_names import Modules

from slips_files.common.abstracts.isqlite import ISQLite
from slips_files.common.output_paths import get_this_db_path_inside_output_dir
from slips_files.common.printer import Printer
from slips_files.common.p2p_reports import evidence_display_type
from slips_files.common.slips_utils import utils
from slips_files.common.network_context import (
    NETWORK_POLL_GRACE_SECONDS,
    network_state_at,
)
from slips_files.core.structures.alerts import Alert
from slips_files.core.structures.evidence import Evidence
from slips_files.core.output import Output
from slips_files.core.database.sqlite_db.detection_history import (
    DetectionHistory,
    initialize_detection_history,
)


class SQLiteDB(ISQLite):
    """
    Stores all the flows slips reads and handles labeling them
    Creates a new db and connects to it if there's none in the given output_dir
    """

    name = "sqlite_db"
    _valid_table_names = frozenset(
        {
            "flows",
            "altflows",
            "alerts",
            "evidence",
            "evidence_flows",
            "alert_evidence",
            "alert_reviews",
            "evidence_reviews",
        }
    )

    def __init__(self, logger: Output, output_dir: str, main_pid: int):
        self.printer = Printer(logger, self.name)
        self.output_dir = output_dir
        self._flows_db = get_this_db_path_inside_output_dir(
            output_dir, "flows.sqlite"
        )

        db_newly_created = False
        if not os.path.exists(self._flows_db):
            # db not created, mark it as first time accessing it so we can
            # init tables once we connect
            db_newly_created = True
            self._init_db()
        # connects to the db
        super().__init__(self.name.lower(), main_pid, self._flows_db)

        if db_newly_created:
            self._enable_incremental_vacuum()
            self.init_tables()
        else:
            self._ensure_history_schema()
        self._ensure_retention_schema()
        self._ensure_review_schema()
        with self.conn_lock:
            with self._acquire_flock():
                initialize_detection_history(self.conn)

    def maintain_detection_history(
        self, policy: dict[str, int | bool], now: float | None = None
    ) -> dict:
        """Maintain detection summaries and rotated archives under writer locks.

        Parameters:
            policy: Validated detection history configuration.
            now: Optional Unix time for retention and archive rotation.

        Returns:
            Maintenance health and bounded progress statistics.
        """
        now = time.time() if now is None else now
        deferred = {
            "last_run": now,
            "units": 0,
            "interrupted": False,
            "deferred": True,
            "phase": "connection_lock",
        }
        if not self.conn_lock.acquire(blocking=False):
            return deferred
        try:
            with self.sqlite_flock.try_acquire() as acquired:
                if not acquired:
                    deferred["phase"] = "writer_lock"
                    return deferred
                previous_timeout = self.conn.execute(
                    "PRAGMA busy_timeout"
                ).fetchone()[0]
                self.conn.execute("PRAGMA busy_timeout=0")
                try:
                    return DetectionHistory(
                        self.conn, self.output_dir
                    ).maintain(policy, now)
                finally:
                    self.conn.set_progress_handler(None, 0)
                    self.conn.rollback()
                    self.conn.execute(
                        f"PRAGMA busy_timeout={int(previous_timeout)}"
                    )
        finally:
            self.conn_lock.release()

    def _ensure_review_schema(self) -> None:
        """Keep analyst decisions in the durable run database."""
        self.create_table(
            "alert_reviews",
            "alert_id TEXT PRIMARY KEY, status TEXT NOT NULL, "
            "note TEXT NOT NULL DEFAULT '', updated_at REAL NOT NULL, "
            "verdict TEXT NOT NULL DEFAULT ''",
        )
        if "verdict" not in self.get_columns("alert_reviews"):
            self.execute(
                "ALTER TABLE alert_reviews ADD COLUMN verdict TEXT NOT NULL DEFAULT ''"
            )
        self.create_table(
            "evidence_reviews",
            "evidence_id TEXT PRIMARY KEY, status TEXT NOT NULL, "
            "note TEXT NOT NULL DEFAULT '', updated_at REAL NOT NULL",
        )
        self.execute(
            "CREATE INDEX IF NOT EXISTS alert_reviews_status_idx "
            "ON alert_reviews(status, alert_id)"
        )
        self.execute(
            "CREATE INDEX IF NOT EXISTS evidence_reviews_status_idx "
            "ON evidence_reviews(status, evidence_id)"
        )

    def _enable_incremental_vacuum(self) -> None:
        """Let new run databases return freed pages without full VACUUM."""
        with self.conn_lock:
            with self._acquire_flock():
                self.conn.execute("PRAGMA auto_vacuum=INCREMENTAL")
                self.conn.execute("VACUUM")

    def _ensure_retention_schema(self) -> None:
        """Add indexed flow age and retention class to old and new runs."""
        for table in ("flows", "altflows"):
            columns = set(self.get_columns(table))
            if "event_time" not in columns:
                self.execute(f"ALTER TABLE {table} ADD COLUMN event_time REAL")
            if "retention_class" not in columns:
                self.execute(
                    f"ALTER TABLE {table} ADD COLUMN retention_class "
                    "INTEGER NOT NULL DEFAULT 0"
                )
            if "retention_priority" not in columns:
                self.execute(
                    f"ALTER TABLE {table} ADD COLUMN retention_priority REAL"
                )
                if self.get_count(
                    "sqlite_master",
                    "type='table' AND name='flow_retention_state'",
                ):
                    self.execute(
                        "DELETE FROM flow_retention_state WHERE table_name=?",
                        (table,),
                    )
            self.execute(
                f"CREATE INDEX IF NOT EXISTS {table}_retention_idx "
                f"ON {table}(retention_class, event_time) "
                "WHERE event_time IS NOT NULL"
            )
            self.execute(
                f"CREATE INDEX IF NOT EXISTS {table}_priority_idx "
                f"ON {table}(retention_class,retention_priority,event_time)"
            )
            priority = (
                "(SELECT MAX(e.evidence_time) FROM evidence_flows ef "
                "JOIN evidence e ON e.evidence_id=ef.evidence_id "
                "WHERE ef.uid=NEW.uid AND COALESCE(e.whitelisted,0)=0)"
            )
            self.execute(
                f"CREATE TRIGGER IF NOT EXISTS {table}_initial_priority AFTER INSERT ON {table} BEGIN "
                f"UPDATE {table} SET retention_priority=MAX(COALESCE(NEW.event_time,0),COALESCE({priority},NEW.event_time,0)),"
                "retention_class=CASE WHEN EXISTS (SELECT 1 FROM evidence_flows ef JOIN evidence e "
                "ON e.evidence_id=ef.evidence_id WHERE ef.uid=NEW.uid AND COALESCE(e.whitelisted,0)=0) "
                "THEN 1 ELSE 0 END WHERE uid=NEW.uid; END"
            )
            self.execute(
                f"CREATE TRIGGER IF NOT EXISTS {table}_linked_priority AFTER INSERT ON evidence_flows BEGIN "
                f"UPDATE {table} SET retention_class=1,retention_priority=MAX(COALESCE(retention_priority,event_time,0),"
                "COALESCE((SELECT evidence_time FROM evidence WHERE evidence_id=NEW.evidence_id),event_time,0)) "
                "WHERE uid=NEW.uid AND EXISTS (SELECT 1 FROM evidence WHERE evidence_id=NEW.evidence_id "
                "AND COALESCE(whitelisted,0)=0); END"
            )
            self.execute(
                f"CREATE TRIGGER IF NOT EXISTS {table}_updated_evidence_priority AFTER UPDATE OF evidence_time,whitelisted "
                "ON evidence WHEN COALESCE(NEW.whitelisted,0)=0 AND "
                "(NEW.evidence_time IS NOT OLD.evidence_time OR NEW.whitelisted IS NOT OLD.whitelisted) BEGIN "
                f"UPDATE {table} SET retention_class=1,retention_priority=MAX(COALESCE(retention_priority,event_time,0),"
                "COALESCE(NEW.evidence_time,event_time,0)) WHERE uid IN "
                "(SELECT uid FROM evidence_flows WHERE evidence_id=NEW.evidence_id); END"
            )
            remaining = (
                "SELECT MAX(e.evidence_time) FROM evidence_flows ef JOIN evidence e "
                f"ON e.evidence_id=ef.evidence_id WHERE ef.uid={table}.uid AND COALESCE(e.whitelisted,0)=0"
            )
            self.execute(
                f"CREATE TRIGGER IF NOT EXISTS {table}_excluded_evidence_priority AFTER UPDATE OF whitelisted "
                "ON evidence WHEN NEW.whitelisted=1 AND COALESCE(OLD.whitelisted,0)=0 BEGIN "
                f"UPDATE {table} SET retention_priority=MAX(COALESCE(event_time,0),COALESCE(({remaining}),event_time,0)),"
                "retention_class=CASE WHEN EXISTS (SELECT 1 FROM evidence_flows ef JOIN evidence e "
                f"ON e.evidence_id=ef.evidence_id WHERE ef.uid={table}.uid AND COALESCE(e.whitelisted,0)=0) "
                "THEN 1 ELSE 0 END WHERE uid IN (SELECT uid FROM evidence_flows WHERE evidence_id=NEW.evidence_id); END"
            )
        self.create_table(
            "flow_retention_state",
            "table_name TEXT PRIMARY KEY, backfill_rowid INTEGER NOT NULL, "
            "backfill_max_rowid INTEGER NOT NULL",
        )
        self.create_table(
            "flow_retention_jobs",
            "table_name TEXT PRIMARY KEY, flow_rowid INTEGER NOT NULL, uid TEXT NOT NULL, "
            "event_time REAL NOT NULL, link_rowid INTEGER NOT NULL DEFAULT 0, "
            "latest_evidence_time REAL, linked INTEGER NOT NULL DEFAULT 0",
        )

    def _ensure_history_schema(self) -> None:
        """Add durable detection tables when opening an older run database."""
        table_schema = {
            "evidence": "evidence_id TEXT PRIMARY KEY, evidence_time REAL, "
            "profile_ip TEXT, timewindow TEXT, threat_level TEXT, "
            "evidence_type TEXT, source_module TEXT, description TEXT, "
            "confidence REAL, data TEXT, "
            "whitelisted INTEGER DEFAULT 0",
            "evidence_flows": "evidence_id TEXT, uid TEXT, "
            "PRIMARY KEY (evidence_id, uid)",
            "alert_evidence": "alert_id TEXT, evidence_id TEXT, "
            "PRIMARY KEY (alert_id, evidence_id)",
        }
        for table_name, schema in table_schema.items():
            self.create_table(table_name, schema)
        self._ensure_detection_score_columns()
        self._create_history_indexes()

    def init_tables(self):
        """creates the tables we're gonna use"""
        table_schema = {
            "flows": "uid TEXT PRIMARY KEY, flow TEXT, label TEXT, profileid "
            "TEXT, twid TEXT, aid TEXT",
            "altflows": "uid TEXT PRIMARY KEY, flow TEXT, label TEXT, "
            "profileid TEXT, twid TEXT, flow_type TEXT",
            "alerts": "alert_id TEXT PRIMARY KEY, alert_time REAL, ip_alerted "
            "TEXT, timewindow TEXT, tw_start TEXT, tw_end TEXT, "
            "label TEXT, accumulated_threat_level REAL, "
            "accumulated_ratl REAL, risk_weight REAL",
            "evidence": "evidence_id TEXT PRIMARY KEY, evidence_time REAL, "
            "profile_ip TEXT, timewindow TEXT, threat_level TEXT, "
            "evidence_type TEXT, source_module TEXT, description TEXT, "
            "confidence REAL, data TEXT, "
            "accumulated_threat_level REAL, accumulated_ratl REAL, "
            "whitelisted INTEGER DEFAULT 0",
            "evidence_flows": "evidence_id TEXT, uid TEXT, "
            "PRIMARY KEY (evidence_id, uid)",
            "alert_evidence": "alert_id TEXT, evidence_id TEXT, "
            "PRIMARY KEY (alert_id, evidence_id)",
        }
        for table_name, schema in table_schema.items():
            self.create_table(table_name, schema)
        self._create_history_indexes()

    def _ensure_detection_score_columns(self) -> None:
        """Add Slips detector-score columns to older run databases."""
        columns = {
            "alerts": {
                "accumulated_threat_level": "REAL",
                "accumulated_ratl": "REAL",
                "risk_weight": "REAL",
            },
            "evidence": {
                "accumulated_threat_level": "REAL",
                "accumulated_ratl": "REAL",
                "whitelisted": "INTEGER DEFAULT 0",
                "source_module": "TEXT",
            },
        }
        for table_name, additions in columns.items():
            existing = set(self.get_columns(table_name))
            for column_name, column_type in additions.items():
                if column_name not in existing:
                    self.execute(
                        f"ALTER TABLE {table_name} "
                        f"ADD COLUMN {column_name} {column_type}"
                    )

    def _create_history_indexes(self) -> None:
        """Index detector lookups and bounded historical web queries."""
        indexes = (
            "CREATE INDEX IF NOT EXISTS flows_profile_tw_idx "
            "ON flows(profileid, twid)",
            "CREATE INDEX IF NOT EXISTS altflows_profile_tw_idx "
            "ON altflows(profileid, twid)",
            "CREATE INDEX IF NOT EXISTS alerts_time_idx "
            "ON alerts(alert_time DESC, alert_id)",
            "CREATE INDEX IF NOT EXISTS alerts_ip_time_idx "
            "ON alerts(ip_alerted, alert_time DESC, alert_id)",
            "CREATE INDEX IF NOT EXISTS evidence_time_idx "
            "ON evidence(evidence_time DESC, evidence_id)",
            "CREATE INDEX IF NOT EXISTS evidence_profile_time_idx "
            "ON evidence(profile_ip, evidence_time DESC, evidence_id)",
            "CREATE INDEX IF NOT EXISTS evidence_group_cover_idx "
            "ON evidence(profile_ip, evidence_type, evidence_time, "
            "threat_level, source_module, whitelisted, "
            "accumulated_ratl, accumulated_threat_level)",
            "CREATE INDEX IF NOT EXISTS evidence_type_group_cover_idx "
            "ON evidence(evidence_type, evidence_time, threat_level, "
            "source_module, whitelisted, accumulated_ratl, "
            "accumulated_threat_level, profile_ip)",
            "CREATE INDEX IF NOT EXISTS evidence_profile_ratl_idx "
            "ON evidence(profile_ip, accumulated_ratl DESC)",
            "CREATE INDEX IF NOT EXISTS evidence_profile_threat_score_idx "
            "ON evidence(profile_ip, accumulated_threat_level DESC)",
            "CREATE INDEX IF NOT EXISTS evidence_whitelisted_tw_idx "
            "ON evidence(profile_ip, timewindow, whitelisted)",
            "CREATE INDEX IF NOT EXISTS evidence_type_idx "
            "ON evidence(evidence_type, evidence_time DESC)",
            "CREATE INDEX IF NOT EXISTS evidence_alert_group_idx "
            "ON evidence(evidence_id, evidence_type, profile_ip, "
            "evidence_time, whitelisted)",
            "CREATE INDEX IF NOT EXISTS evidence_threat_idx "
            "ON evidence(threat_level, evidence_time DESC)",
            "CREATE INDEX IF NOT EXISTS evidence_flows_uid_idx "
            "ON evidence_flows(uid)",
            "CREATE INDEX IF NOT EXISTS alert_evidence_evidence_idx "
            "ON alert_evidence(evidence_id)",
        )
        for statement in indexes:
            self.execute(statement)

    def _init_db(self):
        """
        creates the db if it doesn't exist and clears it if it exists
        """
        # make it accessible to root and non-root users, because when
        # slips is started using sudo, it drops privs from modules that
        # don't need them, and without this line, these modules wont be
        # able to access the path_to_remote_ti_files
        open(self._flows_db, "w").close()
        os.chmod(self._flows_db, 0o777)

    def get_db_path(self) -> str:
        """
        returns the path of the sqlite flows db placed in the output dir
        """
        return self._flows_db

    def get_altflow_from_uid(self, uid) -> dict:
        """Given a uid, get the alternative flow associated with it"""
        altflow = self.select("altflows", condition="uid = ?", params=(uid,))
        if altflow:
            flow: str = altflow[0][1]
            return json.loads(flow)
        return False

    def get_all_contacted_ips_in_profileid_twid(self, profileid, twid) -> dict:
        all_flows: dict = self.get_all_flows_in_profileid_twid(profileid, twid)

        if not all_flows:
            return {}

        contacted_ips = {}
        for uid, flow in all_flows.items():
            # get the daddr of this flow
            daddr = flow["daddr"]
            contacted_ips[daddr] = uid
        return contacted_ips

    def get_all_flows_in_profileid_twid(self, profileid, twid):
        all_flows: list = self.select(
            "flows",
            condition="profileid = ? AND twid = ?",
            params=(profileid, twid),
        )
        if not all_flows:
            return False
        res = {}
        for flow in all_flows:
            uid = flow[0]
            flow = flow[1]
            res[uid] = json.loads(flow)
        return res

    def get_all_altflows_in_profileid_twid(self, profileid, twid):
        condition = f'profileid = "{profileid}" ' f'AND twid = "{twid}"'
        altflows: list = self.select("altflows", condition=condition)
        if not altflows:
            return []

        rows = []
        for altflow in altflows:
            rows.append(
                {
                    "uid": altflow[0],
                    "flow": json.loads(altflow[1]),
                    "label": altflow[2],
                    "profileid": altflow[3],
                    "twid": altflow[4],
                    "flow_type": altflow[5],
                }
            )
        return rows

    def get_all_flows_in_profileid(self, profileid) -> Dict[str, dict]:
        """
        Return a list of all the flows in this profileid
        [{'uid':flow},...]
        """
        flows = self.select(
            "flows", condition="profileid = ?", params=(profileid,)
        )
        all_flows: Dict[str, dict] = {}
        if flows:
            for flow in flows:
                uid = flow[0]
                flow: str = flow[1]
                all_flows[uid] = json.loads(flow)

        return all_flows

    def get_all_flows(self):
        """
        Returns a list with all the flows in all profileids and twids
        Each element in the list is a flow
        """
        flows = self.select("flows")
        flow_list = []
        if flows:
            for flow in flows:
                flow_list.append(json.loads(flow[1]))
        return flow_list

    def set_flow_label(self, uids: List[str], new_label: str):
        """
        sets the given new_label to each flow in the uids list
        """
        for uid in uids:
            # add the label to the flow (conn.log flow)
            self.update(
                "flows",
                "label = ?",
                "uid = ?",
                params=(new_label, uid),
            )
            # add the label to the altflow (dns, http, whatever it is)
            self.update(
                "altflows",
                "label = ?",
                "uid = ?",
                params=(new_label, uid),
            )

    def export_labeled_flows(self, output_dir, format):
        if "tsv" in format:
            csv_output_file = os.path.join(output_dir, "labeled_flows.tsv")
            header: list = self.get_columns("flows")

            with open(csv_output_file, "w", newline="") as tsv_file:
                writer = csv.writer(tsv_file, delimiter="\t")

                # write the header
                writer.writerow(header)

                # Fetch rows one by one and write them to the file
                for row in self.iterate_flows():
                    writer.writerow(row)

        if "json" in format:
            json_output_file = os.path.join(output_dir, "labeled_flows.json")

            with open(json_output_file, "w", newline="") as json_file:
                # Fetch rows one by one and write them to the file
                for row in self.iterate_flows():
                    json_labeled_flow = {
                        "uid": row[0],
                        "flow": row[1],
                        "label": row[2],
                        "profileid": row[3],
                        "twid": row[4],
                    }
                    json.dump(json_labeled_flow, json_file)
                    json_file.write("\n")

    def get_columns(self, table) -> list:
        """returns a list with column names in the given table"""
        table = self._validate_table_name(table)
        cursor = self.execute(f"PRAGMA table_info({table})")
        columns = self.fetchall(cursor)
        return [column[1] for column in columns]

    def iterate_flows(self):
        """returns an iterator"""

        # generator function to iterate over the rows
        def row_generator():
            # select all flows and altflows
            cursor = self.execute(
                "SELECT uid, flow, label, profileid, twid, aid, "
                "event_time, retention_class FROM flows UNION "
                "SELECT uid, flow, label, profileid, twid, NULL, "
                "event_time, retention_class FROM altflows"
            )

            while True:
                row = self.fetchone(cursor)
                if row is None:
                    break
                yield row

        # Return the combined iterator
        return iter(row_generator())

    def get_flow(self, uid: str, twid=False) -> dict:
        """
        Returns the flow with the given uid
        the flow returned is read from conn.log
        """
        params = [uid]
        condition = "uid = ?"
        if twid:
            condition += " AND twid = ?"
            params.append(twid)

        res = self.select("flows", condition=condition, params=tuple(params))
        res = res[0][1] if res else {}
        return {uid: res}

    def evidence_network_state(
        self, state: dict | None, observed_at: float, uids: list[str]
    ) -> dict | None:
        """Resolve local evidence context, reading one frame only near a poll.

        Parameters:
            state: Interface settings loaded by the submitting module worker.
            observed_at: Evidence observation timestamp.
            uids: Linked connection identifiers; at most the first is read.

        Returns:
            Capture-time settings, or None if the network is unknown.
        """
        active = network_state_at(state, observed_at)
        after_poll = network_state_at(
            state, observed_at + NETWORK_POLL_GRACE_SECONDS
        )
        if active is after_poll or not uids:
            return active
        row = self.get_flow(uids[0]).get(uids[0])
        try:
            flow = json.loads(row) if isinstance(row, str) else row
            if not isinstance(flow, dict) or not math.isclose(
                float(flow.get("starttime", -1)),
                observed_at,
                rel_tol=0,
                abs_tol=0.001,
            ):
                return active
        except (TypeError, ValueError):
            return active
        return network_state_at(state, observed_at, SimpleNamespace(**flow))

    @staticmethod
    def _flow_event_time(flow) -> float:
        """Read a flow timestamp, falling back to insertion time if invalid.

        Parameters:
            flow: Parsed traffic record.

        Returns:
            Finite Unix timestamp used for retention ordering.
        """
        try:
            timestamp = float(flow.starttime)
        except (AttributeError, TypeError, ValueError):
            return time.time()
        return timestamp if math.isfinite(timestamp) else time.time()

    def add_flow(self, flow, profileid: str, twid: str, label="benign"):
        parameters = (
            profileid,
            twid,
            flow.uid,
            json.dumps(asdict(flow)),
            label,
            getattr(flow, "aid", None),
            self._flow_event_time(flow),
        )
        self.execute(
            "INSERT INTO flows (profileid, twid, uid, flow, label, aid, "
            "event_time) VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(uid) DO UPDATE SET "
            "profileid=excluded.profileid, twid=excluded.twid, "
            "flow=excluded.flow, label=excluded.label, aid=excluded.aid, "
            "event_time=excluded.event_time",
            parameters,
        )

    def get_flows_count(self, profileid=None, twid=None) -> int:
        """
        returns the total number of flows
         in the db for this profileid and twid if given
        """
        condition_parts = []
        params = []
        if profileid:
            condition_parts.append("profileid = ?")
            params.append(profileid)
        if twid:
            condition_parts.append("twid = ?")
            params.append(twid)

        condition = " AND ".join(condition_parts) if condition_parts else None

        flows = self.get_count(
            "flows", condition=condition, params=tuple(params)
        )
        # flows += self.get_count('altflows', condition=condition)
        return flows

    def _validate_table_name(self, table: str) -> str:
        """
        Validate table names used in SQLiteDB metadata queries.

        :param table: Table name to validate.
        :return: The validated table name.
        """
        if table not in self._valid_table_names:
            raise ValueError(f"Invalid SQLiteDB table name: {table}")
        return table

    def add_altflow(self, flow, profileid: str, twid: str, label="benign"):
        parameters = (
            profileid,
            twid,
            (
                flow.record_id
                if isinstance(getattr(flow, "record_id", None), str)
                and flow.record_id
                else flow.uid
            ),
            json.dumps(asdict(flow)),
            label,
            flow.type_,
            self._flow_event_time(flow),
        )
        self.execute(
            "INSERT INTO altflows (profileid, twid, uid, "
            "flow, label, flow_type, event_time) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(uid) DO UPDATE SET "
            "profileid=excluded.profileid, twid=excluded.twid, "
            "flow=excluded.flow, label=excluded.label, "
            "flow_type=excluded.flow_type, event_time=excluded.event_time",
            parameters,
        )

    @staticmethod
    def _stored_flow_event_time(raw_flow: str) -> float:
        """Recover a legacy row's timestamp from its serialized flow.

        Parameters:
            raw_flow: Flow JSON stored before the indexed timestamp existed.

        Returns:
            Finite Unix timestamp, or the current time for invalid data.
        """
        try:
            value = float(json.loads(raw_flow)["starttime"])
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            return time.time()
        return value if math.isfinite(value) else time.time()

    def _backfill_retention_times(
        self, cursor: sqlite3.Cursor, table: str, batch_size: int
    ) -> int:
        """Resume a bounded batch of legacy timestamps and linked priorities.

        Parameters:
            cursor: Cursor in the retention transaction.
            table: The flows or altflows table.
            batch_size: Maximum legacy rows and evidence links to inspect.

        Returns:
            Number of flow records examined, including partial link scans.
        """
        state = cursor.execute(
            "SELECT backfill_rowid, backfill_max_rowid "
            "FROM flow_retention_state WHERE table_name = ?",
            (table,),
        ).fetchone()
        if state is None:
            max_rowid = cursor.execute(
                f"SELECT COALESCE(MAX(rowid), 0) FROM {table}"
            ).fetchone()[0]
            cursor.execute(
                "INSERT INTO flow_retention_state "
                "(table_name, backfill_rowid, backfill_max_rowid) "
                "VALUES (?, 0, ?)",
                (table, max_rowid),
            )
            last_rowid = 0
        else:
            last_rowid, max_rowid = state
        if last_rowid < 0:
            return 0
        rows = cursor.execute(
            f"SELECT rowid,uid,CASE WHEN event_time IS NULL OR retention_priority IS NULL THEN flow END,"
            f"event_time,retention_priority FROM {table} WHERE rowid>? AND rowid<=? ORDER BY rowid LIMIT ?",
            (last_rowid, max_rowid, min(batch_size, 16)),
        ).fetchall()
        if not rows:
            cursor.execute(
                "DELETE FROM flow_retention_jobs WHERE table_name=?", (table,)
            )
            cursor.execute(
                "UPDATE flow_retention_state SET backfill_rowid = -1 "
                "WHERE table_name = ?",
                (table,),
            )
            return 0
        remaining = batch_size
        scanned = 0
        for rowid, uid, raw, timestamp, priority in rows:
            scanned += 1
            if timestamp is not None and priority is not None:
                cursor.execute(
                    "DELETE FROM flow_retention_jobs WHERE table_name=?",
                    (table,),
                )
                cursor.execute(
                    "UPDATE flow_retention_state SET backfill_rowid=? WHERE table_name=?",
                    (rowid, table),
                )
                continue
            timestamp = (
                timestamp
                if timestamp is not None
                else self._stored_flow_event_time(raw)
            )
            job = cursor.execute(
                "SELECT flow_rowid,link_rowid,latest_evidence_time,linked FROM flow_retention_jobs WHERE table_name=?",
                (table,),
            ).fetchone()
            if job is None or job[0] != rowid:
                cursor.execute(
                    "INSERT OR REPLACE INTO flow_retention_jobs VALUES (?,?,?,?,0,NULL,0)",
                    (table, rowid, uid, timestamp),
                )
                link_rowid, latest, linked = 0, timestamp, False
            else:
                _, link_rowid, latest, linked = job
                latest = max(timestamp, latest or timestamp)
            links = cursor.execute(
                "SELECT ef.rowid,e.evidence_id,e.evidence_time,COALESCE(e.whitelisted,0) "
                "FROM evidence_flows ef INDEXED BY evidence_flows_uid_idx LEFT JOIN evidence e "
                "INDEXED BY evidence_alert_group_idx ON e.evidence_id=ef.evidence_id "
                "WHERE ef.uid=? AND ef.rowid>? ORDER BY ef.rowid LIMIT ?",
                (uid, link_rowid, remaining),
            ).fetchall()
            for _, evidence_id, evidence_time, excluded in links:
                if evidence_id is not None and not excluded:
                    linked = True
                    latest = max(latest, evidence_time or timestamp)
            if len(links) == remaining:
                cursor.execute(
                    "UPDATE flow_retention_jobs SET link_rowid=?,latest_evidence_time=?,linked=? WHERE table_name=?",
                    (links[-1][0], latest, int(linked), table),
                )
                return scanned
            cursor.execute(
                f"UPDATE {table} SET event_time=?,retention_class=CASE WHEN retention_priority IS NULL "
                "THEN ? ELSE retention_class END,retention_priority=MAX(COALESCE(retention_priority,0),?) "
                "WHERE rowid=? AND (event_time IS NULL OR retention_priority IS NULL)",
                (timestamp, int(linked), latest, rowid),
            )
            cursor.execute(
                "DELETE FROM flow_retention_jobs WHERE table_name=?", (table,)
            )
            cursor.execute(
                "UPDATE flow_retention_state SET backfill_rowid=? WHERE table_name=?",
                (rowid, table),
            )
            remaining -= len(links)
        return scanned

    def _prune_flow_table(
        self,
        cursor,
        table: str,
        ordinary_cutoff: float,
        linked_cutoff: float,
        batch_size: int,
    ) -> list[str]:
        """Classify old flows by evidence and delete expired rows.

        Parameters:
            cursor: Cursor in the retention transaction.
            table: The flows or altflows table.
            ordinary_cutoff: Oldest age allowed for ordinary flow rows.
            linked_cutoff: Oldest age allowed for evidence-linked rows.
            batch_size: Maximum rows per retention class to inspect.

        Returns:
            UIDs deleted from this table.
        """
        deleted: list[str] = []
        for retention_class, cutoff in (
            (0, ordinary_cutoff),
            (1, linked_cutoff),
        ):
            candidates = [
                row[0]
                for row in cursor.execute(
                    f"SELECT uid FROM {table} INDEXED BY {table}_priority_idx "
                    "WHERE retention_class=? AND retention_priority<? "
                    "ORDER BY retention_priority,event_time LIMIT ?",
                    (retention_class, cutoff, batch_size),
                ).fetchall()
            ]
            if candidates:
                placeholders = ",".join("?" for _ in candidates)
                cursor.execute(
                    f"DELETE FROM {table} WHERE uid IN ({placeholders})",
                    candidates,
                )
                deleted.extend(candidates)
        return deleted

    def maintain_flow_retention(
        self,
        ordinary_cutoff: float,
        linked_cutoff: float,
        batch_size: int = 500,
        max_size_bytes: int = 512 * 1024 * 1024,
        unlinked_size_cutoff: float | None = None,
        work_budget_ms: int = 250,
    ) -> list[str]:
        """Prune bounded flow batches while retaining recent evidence flows.

        Parameters:
            ordinary_cutoff: Unix time before which ordinary flows expire.
            linked_cutoff: Unix time before which linked flows expire.
            batch_size: Maximum rows per table and class per pass.
            max_size_bytes: Logical database size target; zero disables it.
            unlinked_size_cutoff: Oldest age eligible for unlinked size
                pruning. Defaults to ordinary_cutoff.
            work_budget_ms: Maximum SQLite execution time per cleanup pass.

        Returns:
            Connection UIDs removed, for the web's compact index cleanup.
        """
        if not 1 <= batch_size <= 800:
            raise ValueError("batch_size must be between 1 and 800")
        if linked_cutoff > ordinary_cutoff:
            raise ValueError(
                "linked flows cannot expire before ordinary flows"
            )
        if max_size_bytes < 0:
            raise ValueError("max_size_bytes cannot be negative")
        if unlinked_size_cutoff is None:
            unlinked_size_cutoff = ordinary_cutoff
        with self.conn_lock:
            with self._acquire_flock():
                deadline = time.monotonic() + work_budget_ms / 1000
                self.conn.execute("PRAGMA busy_timeout=100")
                self.conn.set_progress_handler(
                    lambda: int(time.monotonic() >= deadline), 1000
                )
                cursor = self.conn.cursor()
                removed: list[str] = []
                any_removed = False
                try:
                    cursor.execute("BEGIN IMMEDIATE")
                    migration_deadline = (
                        time.monotonic() + work_budget_ms / 2000
                    )
                    while time.monotonic() < migration_deadline:
                        progress = 0
                        for table in ("flows", "altflows"):
                            progress += self._backfill_retention_times(
                                cursor, table, min(batch_size * 4, 50)
                            )
                            self.conn.commit()
                            cursor.execute("BEGIN IMMEDIATE")
                        if not progress:
                            break
                    for table in ("flows", "altflows"):
                        deleted = self._prune_flow_table(
                            cursor,
                            table,
                            ordinary_cutoff,
                            linked_cutoff,
                            batch_size,
                        )
                        self.conn.commit()
                        any_removed = any_removed or bool(deleted)
                        if table == "flows":
                            removed.extend(deleted)
                        cursor.execute("BEGIN IMMEDIATE")
                    if (
                        max_size_bytes
                        and self._logical_size_bytes(cursor) > max_size_bytes
                    ):
                        for linked_only in (False, True):
                            deleted = self._prune_for_size(
                                cursor,
                                batch_size,
                                linked_only,
                                (
                                    ordinary_cutoff
                                    if linked_only
                                    else unlinked_size_cutoff
                                ),
                            )
                            self.conn.commit()
                            any_removed = any_removed or any(deleted.values())
                            removed.extend(deleted["flows"])
                            cursor.execute("BEGIN IMMEDIATE")
                            if (
                                self._logical_size_bytes(cursor)
                                <= max_size_bytes
                            ):
                                break
                    self.conn.commit()
                except sqlite3.OperationalError as error:
                    self.conn.set_progress_handler(None, 0)
                    self.conn.rollback()
                    if (
                        "interrupt" in str(error).lower()
                        or "locked" in str(error).lower()
                    ):
                        return removed
                    raise
                except Exception:
                    self.conn.set_progress_handler(None, 0)
                    self.conn.rollback()
                    raise
                finally:
                    self.conn.set_progress_handler(None, 0)
                    self.conn.execute("PRAGMA busy_timeout=20000")
                if any_removed:
                    cursor.execute("PRAGMA incremental_vacuum(32)")
                cursor.execute("PRAGMA wal_checkpoint(PASSIVE)")
        return removed

    def _logical_size_bytes(self, cursor) -> int:
        """Return the SQLite database size excluding reusable free pages."""
        page_count = cursor.execute("PRAGMA page_count").fetchone()[0]
        free_pages = cursor.execute("PRAGMA freelist_count").fetchone()[0]
        page_size = cursor.execute("PRAGMA page_size").fetchone()[0]
        return (page_count - free_pages) * page_size

    @staticmethod
    def _linked_priority_time(alias: str) -> str:
        """Use the newest linked evidence time when deciding flow retention.

        Parameters:
            alias: SQL alias of a flows or altflows row.

        Returns:
            SQL expression for the latest flow or non-excluded evidence time.
        """
        return (
            f"MAX({alias}.event_time, COALESCE(("
            "SELECT MAX(e.evidence_time) FROM evidence_flows ef "
            "JOIN evidence e ON e.evidence_id = ef.evidence_id "
            f"WHERE ef.uid = {alias}.uid "
            "AND COALESCE(e.whitelisted, 0) = 0), "
            f"{alias}.event_time))"
        )

    def _prune_for_size(
        self,
        cursor,
        batch_size: int,
        linked_only: bool,
        linked_size_cutoff: float,
    ) -> dict[str, list[str]]:
        """Delete the oldest cross-table batch of a requested evidence class.

        Parameters:
            cursor: Cursor in the active retention transaction.
            batch_size: Maximum rows to delete in this pass.
            linked_only: Select evidence-linked rows when true, otherwise
                select rows without non-excluded evidence.
            linked_size_cutoff: Oldest age eligible for linked size pruning.

        Returns:
            Deleted UIDs grouped by raw flow table.
        """
        candidates = []
        for table in ("flows", "altflows"):
            candidates.extend(
                (table, *row)
                for row in cursor.execute(
                    f"SELECT uid,retention_priority,event_time,rowid FROM {table} INDEXED BY {table}_priority_idx "
                    "WHERE retention_class=? AND retention_priority<? "
                    "ORDER BY retention_priority,event_time LIMIT ?",
                    (int(linked_only), linked_size_cutoff, batch_size),
                ).fetchall()
            )
        candidates.sort(key=lambda row: (row[2], row[3], row[0], row[4]))
        deleted: dict[str, list[str]] = {"flows": [], "altflows": []}
        for table, uid, *_ in candidates[:batch_size]:
            deleted[table].append(uid)
        for table, uids in deleted.items():
            if not uids:
                continue
            placeholders = ",".join("?" for _ in uids)
            cursor.execute(
                f"DELETE FROM {table} WHERE uid IN ({placeholders})", uids
            )
        return deleted

    def remove_flow_index_uids(self, uids: list[str]) -> int:
        """Drop compact web index rows after their raw flows are pruned.

        Parameters:
            uids: Deleted connection flow identifiers.

        Returns:
            Number of removed index rows, or zero when history is absent.
        """
        history_path = os.path.join(
            self.output_dir, "web_interface", "history.sqlite"
        )
        if not uids or not os.path.exists(history_path):
            return 0
        deleted = 0
        try:
            with sqlite3.connect(history_path, timeout=3) as history:
                for start in range(0, len(uids), 500):
                    batch = uids[start : start + 500]
                    placeholders = ",".join("?" for _ in batch)
                    cursor = history.execute(
                        f"DELETE FROM flow_index WHERE uid IN "
                        f"({placeholders})",
                        batch,
                    )
                    deleted += cursor.rowcount
        except sqlite3.Error:
            # The web collector reconciles orphaned index rows later.
            return 0
        return deleted

    def _execute_detection_transaction(
        self, statements: List[tuple[str, tuple]]
    ) -> None:
        """
        Execute one atomic group of durable detection writes.

        Parameters:
            statements: SQL statements and their bound parameters.
        """
        with self.conn_lock:
            with self._acquire_flock():
                try:
                    cursor = self.conn.cursor()
                    cursor.execute("BEGIN")
                    for query, parameters in statements:
                        cursor.execute(query, parameters)
                    self.conn.commit()
                except Exception:
                    self.conn.rollback()
                    raise

    def set_evidence_score(
        self,
        evidence_id: str,
        accumulated_threat_level: float,
        accumulated_ratl: float,
    ) -> None:
        """Persist the host score returned while processing one evidence.

        Parameters:
            evidence_id: Existing evidence to annotate, never recreate.
            accumulated_threat_level: Raw accumulator before any alert reset.
            accumulated_ratl: Risk-adjusted accumulator at the same instant.
        """
        self._execute_detection_transaction(
            [
                (
                    "UPDATE evidence SET accumulated_threat_level = ?, "
                    "accumulated_ratl = ? WHERE evidence_id = ?",
                    (accumulated_threat_level, accumulated_ratl, evidence_id),
                ),
            ]
        )

    def add_evidence(self, evidence: Evidence) -> None:
        """
        Persist evidence and its triggering flow identifiers.

        Parameters:
            evidence: Canonical evidence generated by Slips.
        """
        serialized = json.dumps(utils.to_dict(evidence))
        evidence_time = utils.convert_ts_format(
            evidence.timestamp, "unixtimestamp"
        )
        statements = [
            (
                "INSERT INTO evidence "
                "(evidence_id, evidence_time, profile_ip, timewindow, "
                "threat_level, evidence_type, source_module, description, "
                "confidence, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(evidence_id) DO UPDATE SET evidence_time=excluded.evidence_time,"
                "profile_ip=excluded.profile_ip,timewindow=excluded.timewindow,threat_level=excluded.threat_level,"
                "evidence_type=excluded.evidence_type,source_module=excluded.source_module,"
                "description=excluded.description,confidence=excluded.confidence,data=excluded.data",
                (
                    evidence.id,
                    evidence_time,
                    evidence.profile.ip,
                    str(evidence.timewindow),
                    str(evidence.threat_level),
                    evidence_display_type(
                        str(evidence.evidence_type),
                        getattr(evidence, "peer_report", {}),
                    ),
                    (
                        Modules.P2P_TRUST.value
                        if str(evidence.evidence_type) == "P2P_REPORT"
                        else getattr(evidence, "source_module", "")
                    ),
                    evidence.description,
                    evidence.confidence,
                    serialized,
                ),
            ),
            (
                "DELETE FROM evidence_flows WHERE evidence_id = ?",
                (evidence.id,),
            ),
        ]
        statements.extend(
            (
                "INSERT OR IGNORE INTO evidence_flows "
                "(evidence_id, uid) VALUES (?, ?)",
                (evidence.id, uid),
            )
            for uid in evidence.uid
        )
        self._execute_detection_transaction(statements)

    def mark_evidence_whitelisted(self, evidence_id: str) -> None:
        """
        Persist that Evidence Handler excluded an evidence by whitelist.

        Parameters:
            evidence_id: Canonical evidence identifier.
        """
        self.execute(
            "UPDATE evidence SET whitelisted = 1 WHERE evidence_id = ?",
            (evidence_id,),
        )

    def is_evidence_whitelisted(self, evidence_id: str) -> bool:
        """
        Returns True if the given evidence_id was marked as whitelisted.
        """
        res = self.select(
            "evidence",
            columns="whitelisted",
            condition="evidence_id = ?",
            params=(evidence_id,),
            limit=1,
        )
        return bool(res) and res[0] == 1

    def get_whitelisted_evidence_ids_in_tw(
        self, profile_ip: str, twid: str
    ) -> set:
        """
        Returns the IDs of all evidence marked as whitelisted for the given
        profile IP and timewindow, in a single indexed query.
        """
        res = self.select(
            "evidence",
            columns="evidence_id",
            condition="profile_ip = ? AND timewindow = ? AND whitelisted = 1",
            params=(profile_ip, twid),
        )
        return {row[0] for row in res} if res else set()

    def alert_evidence_records(self, alert_id: str) -> list[dict]:
        """Read a bounded set of distinct detector sources for a local alert.

        Parameters:
            alert_id: Durable alert identifier.

        Returns:
            Up to 100 associated evidence snapshots, newest first.
        """
        rows = self.select(
            "evidence",
            columns="data",
            condition="evidence_id IN (SELECT evidence_id FROM alert_evidence WHERE alert_id = ?)",
            params=(alert_id,),
            order_by="evidence_time DESC",
            limit=100,
        )
        return [json.loads(row[0]) for row in (rows or [])]

    def add_alert(self, alert: Alert) -> None:
        """
        Persist an alert and its evidence relationships.

        Parameters:
            alert: Canonical alert generated by Slips.
        """
        now = utils.convert_ts_format(datetime.now(), "unixtimestamp")
        statements = [
            (
                "INSERT INTO alerts "
                "(alert_id, ip_alerted, timewindow, tw_start, tw_end, "
                "label, alert_time, accumulated_threat_level, "
                "accumulated_ratl, risk_weight) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(alert_id) DO UPDATE SET ip_alerted=excluded.ip_alerted,timewindow=excluded.timewindow,"
                "tw_start=excluded.tw_start,tw_end=excluded.tw_end,label=excluded.label,alert_time=excluded.alert_time,"
                "accumulated_threat_level=excluded.accumulated_threat_level,accumulated_ratl=excluded.accumulated_ratl,"
                "risk_weight=excluded.risk_weight",
                (
                    alert.id,
                    alert.profile.ip,
                    str(alert.timewindow),
                    alert.timewindow.start_time,
                    alert.timewindow.end_time,
                    "malicious",
                    now,
                    getattr(alert, "accumulated_threat_level", None),
                    getattr(alert, "accumulated_ratl", None),
                    (
                        alert.risk_level.weight
                        if getattr(alert, "risk_level", None)
                        else None
                    ),
                ),
            ),
            (
                "DELETE FROM alert_evidence WHERE alert_id = ?",
                (alert.id,),
            ),
        ]
        statements.extend(
            (
                "INSERT OR IGNORE INTO alert_evidence "
                "(alert_id, evidence_id) VALUES (?, ?)",
                (alert.id, evidence_id),
            )
            for evidence_id in alert.correl_id
        )
        self._execute_detection_transaction(statements)

    def get_malicious_profiles(self) -> List[str]:
        """
        returns a list with unique ip_alerted values from alerts table
        """
        results = self.select("alerts", columns="DISTINCT ip_alerted")
        if not results:
            return []
        return [row[0] for row in results if row and row[0] is not None]
