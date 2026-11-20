"""Maintain bounded detection history, hourly summaries and monthly archives."""

import json
import shutil
import re
import sqlite3
import time
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NamedTuple

# Internal tuning values, intentionally not user-configurable.
# Detections processed per maintenance step.
MAINTENANCE_BATCH_SIZE = 200
# Seconds between maintenance passes.
MAINTENANCE_INTERVAL_SECONDS = 10
# Maximum milliseconds one maintenance pass may run before SQLite is told
# to stop the running query.
MAX_MAINTENANCE_PASS_DURATION_MS = 250

SECONDS_PER_HOUR = 3600
SECONDS_PER_DAY = 86400
BYTES_PER_MB = 1024 * 1024


class ArchivableTable(NamedTuple):
    """Column and table names needed to archive one kind of detection."""

    # primary key column of the detection table, e.g. evidence_id
    id_column: str
    # column holding the detection's unix time, used for the age cutoff
    time_column: str
    # table linking each detection to its many children
    # (evidence -> flows, alert -> evidence)
    links_table: str
    # column in links_table that holds the child's id
    linked_id_column: str
    # table holding analyst reviews of this detection
    reviews_table: str


# the detection tables that get moved into archive files, keyed by table name
ARCHIVABLE_TABLES = {
    "evidence": ArchivableTable(
        id_column="evidence_id",
        time_column="evidence_time",
        links_table="evidence_flows",
        linked_id_column="uid",
        reviews_table="evidence_reviews",
    ),
    "alerts": ArchivableTable(
        id_column="alert_id",
        time_column="alert_time",
        links_table="alert_evidence",
        linked_id_column="evidence_id",
        reviews_table="alert_reviews",
    ),
}
# tables whose schema is copied from flows.sqlite into every archive file
TABLES_CREATED_IN_EACH_ARCHIVE = (
    "evidence",
    "alerts",
    "evidence_flows",
    "alert_evidence",
    "evidence_reviews",
    "alert_reviews",
    "flows",
    "altflows",
)
ARCHIVE_FILENAME_GLOB = "detections-*.sqlite"
# detections-YYYY-MM.sqlite or detections-YYYY-MM-NNNN.sqlite,
# NNNN is the part number inside that month
ARCHIVE_FILENAME_PATTERN = re.compile(
    r"detections-\d{4}-\d{2}(?:-\d{4,10})?\.sqlite"
)
EVIDENCE_HOURLY_COLUMNS = (
    "hour,profile_ip,evidence_type,threat_level,source_module,whitelisted,"
    "record_count,first_time,last_time,max_atl,max_ratl,alert_count"
)
# history_state key marking that the one-time rebuild of hourly summaries
# whose max_atl/max_ratl were stored as 0 instead of NULL already ran
NULLABLE_SCORE_SUMMARIES_MIGRATION_KEY = "nullable_score_summaries_v1"
# {alias} is replaced with a table alias followed by a dot (e.g. "e."),
# or with "" when the query has no alias
EVIDENCE_NETWORK_ID_SQL = (
    "CASE WHEN json_valid({alias}data) THEN "
    "COALESCE(json_extract({alias}data,'$.detection_provenance.network_id'),'') ELSE '' END"
)
EVIDENCE_INTERFACE_SQL = (
    "CASE WHEN json_valid({alias}data) THEN "
    "COALESCE(NULLIF(json_extract({alias}data,'$.interface'),'default'),'') ELSE '' END"
)
EVIDENCE_NETWORK_INDEX_SQL = (
    "CREATE INDEX IF NOT EXISTS evidence_network_time_idx ON evidence("
    "evidence_time,evidence_id,profile_ip,evidence_type,threat_level,source_module,"
    "whitelisted,accumulated_threat_level,accumulated_ratl,"
    + EVIDENCE_NETWORK_ID_SQL.format(alias="")
    + ","
    + EVIDENCE_INTERFACE_SQL.format(alias="")
    + ")"
)


def _create_history_tables(connection: sqlite3.Connection) -> None:
    """Create the maintenance tables and the indexes maintenance reads by.

    Parameters:
        connection: Run database connection under its writer locks.
    """
    # Table glossary:
    # - history_totals: exact row count per detection table.
    # - history_state: key/value checkpoints that survive restarts.
    # - history_dirty_hours: hours whose evidence_hourly rows are out of date.
    #   "generation" is bumped on every change to that hour, so a rebuild
    #   that started before the change knows it must start over.
    # - history_summary_jobs: where an unfinished hour rebuild stopped.
    # - history_archive_queue: the one record per table being archived now.
    #   "phase" is 'copy' (copying to the archive file) or 'purge'
    #   (deleting leftover links from flows.sqlite). "cursor" is the last
    #   link id handled. "restart" is set to 1 by a trigger when links
    #   change during the copy, so the copy starts over.
    # - history_archived_ids: ids already moved to an archive.
    connection.executescript(
        "CREATE TABLE IF NOT EXISTS history_totals(entity TEXT PRIMARY KEY, count INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS history_state(key TEXT PRIMARY KEY,value TEXT NOT NULL);"
        "CREATE TABLE IF NOT EXISTS history_dirty_hours(hour INTEGER PRIMARY KEY,generation INTEGER NOT NULL DEFAULT 1);"
        "CREATE TABLE IF NOT EXISTS history_summary_jobs(hour INTEGER PRIMARY KEY,generation INTEGER NOT NULL,"
        "cursor_time REAL NOT NULL,cursor_id TEXT NOT NULL);"
        "CREATE TABLE IF NOT EXISTS evidence_hourly(hour INTEGER NOT NULL,profile_ip TEXT,"
        "evidence_type TEXT,threat_level TEXT,source_module TEXT,"
        "whitelisted INTEGER NOT NULL,record_count INTEGER NOT NULL,first_time REAL NOT NULL,last_time REAL NOT NULL,"
        "max_atl REAL,max_ratl REAL,alert_count INTEGER NOT NULL,"
        "PRIMARY KEY(hour,profile_ip,evidence_type,threat_level,source_module,whitelisted));"
        "CREATE UNIQUE INDEX IF NOT EXISTS evidence_hourly_key_idx ON evidence_hourly("
        "hour,json_array(profile_ip,evidence_type,threat_level,source_module,whitelisted));"
        "CREATE TABLE IF NOT EXISTS history_archive_queue(entity TEXT PRIMARY KEY,record_id TEXT NOT NULL,"
        "filename TEXT NOT NULL,phase TEXT NOT NULL DEFAULT 'copy',cursor TEXT NOT NULL DEFAULT '',"
        "restart INTEGER NOT NULL DEFAULT 0);"
        "CREATE TABLE IF NOT EXISTS history_archived_ids(entity TEXT NOT NULL,record_id TEXT NOT NULL,"
        "archived_at REAL NOT NULL,PRIMARY KEY(entity,record_id));"
        "CREATE INDEX IF NOT EXISTS history_archived_age_idx ON history_archived_ids(archived_at);"
        "CREATE INDEX IF NOT EXISTS evidence_time_cover_idx ON evidence(evidence_time,evidence_id,"
        "profile_ip,evidence_type,threat_level,source_module,whitelisted,accumulated_threat_level,accumulated_ratl);"
        "CREATE INDEX IF NOT EXISTS alert_evidence_lookup_idx ON alert_evidence(evidence_id,alert_id);"
    )
    connection.execute(EVIDENCE_NETWORK_INDEX_SQL)


def _install_row_count_triggers(
    connection: sqlite3.Connection, table: str
) -> None:
    """Seed history_totals for a detection table and keep it exact with
    triggers, so readers never need a slow COUNT(*).

    Parameters:
        connection: Run database connection under its writer locks.
        table: Internal evidence or alerts table name.
    """
    # seed the counter once, from the rows that existed before the triggers
    if (
        connection.execute(
            "SELECT 1 FROM history_totals WHERE entity=?", (table,)
        ).fetchone()
        is None
    ):
        existing_row_count = connection.execute(
            f"SELECT COUNT(*) FROM {table}"
        ).fetchone()[0]
        connection.execute(
            "INSERT INTO history_totals VALUES (?,?)",
            (table, existing_row_count),
        )
    for sql_operation, count_change in (("INSERT", "+1"), ("DELETE", "-1")):
        connection.execute(
            f"CREATE TRIGGER IF NOT EXISTS history_{table}_{sql_operation.lower()} "
            f"AFTER {sql_operation} ON {table} "
            f"BEGIN UPDATE history_totals SET count=count{count_change} "
            f"WHERE entity='{table}'; END"
        )


def _install_archive_restart_triggers(
    connection: sqlite3.Connection, table: str, columns: ArchivableTable
) -> None:
    """Restart the archive copy of a record when its links change mid-copy,
    so the archive never ends up with a stale set of links.

    Parameters:
        connection: Run database connection under its writer locks.
        table: Internal evidence or alerts table name.
        columns: Column and table names of that detection table.
    """
    for sql_operation in ("INSERT", "UPDATE", "DELETE"):
        # OLD is the row before a DELETE, NEW is the row after an
        # INSERT/UPDATE
        changed_row = "OLD" if sql_operation == "DELETE" else "NEW"
        connection.execute(
            f"CREATE TRIGGER IF NOT EXISTS archive_{columns.links_table}_{sql_operation.lower()} "
            f"AFTER {sql_operation} ON {columns.links_table} "
            "BEGIN UPDATE history_archive_queue SET restart=1 WHERE "
            f"entity='{table}' AND record_id={changed_row}.{columns.id_column} "
            "AND phase='copy'; END"
        )


def _install_hourly_summary_triggers(connection: sqlite3.Connection) -> None:
    """Mark an hour dirty in history_dirty_hours whenever its evidence or
    the alert links of its evidence change, so its summary gets rebuilt.

    Parameters:
        connection: Run database connection under its writer locks.
    """
    for sql_operation in ("INSERT", "UPDATE", "DELETE"):
        # OLD/NEW names the row versions a trigger can see. An UPDATE can
        # move evidence between hours, so both its old and new hour are
        # marked dirty.
        changed_row_versions = (
            ("OLD", "NEW")
            if sql_operation == "UPDATE"
            else ("OLD" if sql_operation == "DELETE" else "NEW",)
        )
        mark_evidence_hour_dirty_sql = "".join(
            "INSERT INTO history_dirty_hours(hour) SELECT CAST("
            f"{row_version}.evidence_time/3600 AS INTEGER)*3600 "
            f"WHERE {row_version}.evidence_time IS NOT NULL "
            "ON CONFLICT(hour) DO UPDATE SET generation=generation+1;"
            for row_version in changed_row_versions
        )
        connection.execute(
            f"CREATE TRIGGER IF NOT EXISTS summary_evidence_{sql_operation.lower()} "
            f"AFTER {sql_operation} ON evidence "
            f"BEGIN {mark_evidence_hour_dirty_sql} END"
        )
        # alert_count in evidence_hourly depends on alert_evidence links,
        # so a link change dirties the hour of the linked evidence
        mark_linked_evidence_hour_dirty_sql = "".join(
            "INSERT INTO history_dirty_hours(hour) SELECT CAST(evidence_time/3600 AS INTEGER)*3600 "
            f"FROM evidence WHERE evidence_id={row_version}.evidence_id "
            "AND evidence_time IS NOT NULL "
            "ON CONFLICT(hour) DO UPDATE SET generation=generation+1;"
            for row_version in changed_row_versions
        )
        connection.execute(
            f"CREATE TRIGGER IF NOT EXISTS summary_links_{sql_operation.lower()} "
            f"AFTER {sql_operation} ON alert_evidence "
            f"BEGIN {mark_linked_evidence_hour_dirty_sql} END"
        )


def _rebuild_summaries_with_zero_scores(
    connection: sqlite3.Connection,
) -> None:
    """One-time migration: older versions stored a missing max_atl/max_ratl
    as 0 instead of NULL. Mark those hours dirty so they get rebuilt.

    Parameters:
        connection: Run database connection under its writer locks.
    """
    if connection.execute(
        "SELECT 1 FROM history_state WHERE key=?",
        (NULLABLE_SCORE_SUMMARIES_MIGRATION_KEY,),
    ).fetchone():
        return
    connection.execute(
        "INSERT INTO history_dirty_hours(hour) "
        "SELECT DISTINCT hour FROM evidence_hourly WHERE max_atl=0 OR max_ratl=0 "
        "ON CONFLICT(hour) DO UPDATE SET generation=generation+1"
    )
    connection.execute(
        "INSERT INTO history_state VALUES (?, '1')",
        (NULLABLE_SCORE_SUMMARIES_MIGRATION_KEY,),
    )


def initialize_detection_history(connection: sqlite3.Connection) -> None:
    """Install counters, change tracking and restartable maintenance state.

    Every step is safe to run again on every slips start.

    Parameters:
        connection: Run database connection under its writer locks.
    """
    _create_history_tables(connection)
    for table, columns in ARCHIVABLE_TABLES.items():
        _install_row_count_triggers(connection, table)
        _install_archive_restart_triggers(connection, table, columns)
    _install_hourly_summary_triggers(connection)
    migrate_peer_report_types(connection)
    _rebuild_summaries_with_zero_scores(connection)
    connection.commit()


# history_state key recording that migrate_peer_report_types() already ran
# on this db, so it runs only once per db and not on every slips start
PEER_REPORT_MIGRATION_DONE_KEY = "peer_report_display_types_v1"
# evidence_type older Slips versions gave every evidence received from peers
OLD_PEER_REPORT_TYPE = "P2P_REPORT"
# peer reports loaded into memory at once during the migration
PEER_REPORT_MIGRATION_BATCH_SIZE = 256


def _is_peer_report_migration_done(connection: sqlite3.Connection) -> bool:
    """Check whether migrate_peer_report_types() already ran on this db.

    Parameters:
        connection: Run database connection.

    Returns:
        True when the migration marker exists in history_state.
    """
    return (
        connection.execute(
            "SELECT 1 FROM history_state WHERE key=?",
            (PEER_REPORT_MIGRATION_DONE_KEY,),
        ).fetchone()
        is not None
    )


def _find_peer_report_type(evidence_json: str | None) -> str | None:
    """Get the type of the first detection inside a stored peer report.

    Parameters:
        evidence_json: The evidence's data column.

    Returns:
        The detection type, or None when the JSON is broken or the peer
        report has no detections, so the row keeps its old type.
    """
    # imported here instead of at the top of the file so it is only
    # loaded when the migration actually runs
    from slips_files.common.p2p_reports import (
        get_first_evidence_in_peer_report,
    )

    try:
        evidence_data = json.loads(evidence_json)
    except (TypeError, ValueError):
        return None
    if not isinstance(evidence_data, dict):
        return None
    # returns OLD_PEER_REPORT_TYPE if the report contains no detections
    evidence_type = get_first_evidence_in_peer_report(
        OLD_PEER_REPORT_TYPE, evidence_data.get("peer_report")
    )
    if evidence_type == OLD_PEER_REPORT_TYPE:
        return None
    return evidence_type


def _migrate_peer_reports_batch(
    connection: sqlite3.Connection,
    peer_reports_batch: list[tuple[str, str | None]],
) -> int:
    """Rewrite the type of one batch of old peer reports.

    Parameters:
        connection: Writable run database connection.
        peer_reports_batch: (evidence_id, data JSON) pairs.

    Returns:
        Number of evidence rows whose type was changed.
    """
    from modules.supported_module_names import Modules

    type_updates = []
    for evidence_id, evidence_json in peer_reports_batch:
        evidence_type = _find_peer_report_type(evidence_json)
        if evidence_type is not None:
            type_updates.append(
                (evidence_type, Modules.P2P_TRUST.value, evidence_id)
            )
    # note: this UPDATE fires the summary_evidence_update trigger,
    # so the affected hours get rebuilt in evidence_hourly with
    # the new types
    connection.executemany(
        "UPDATE evidence SET evidence_type=?,source_module=? WHERE evidence_id=?",
        type_updates,
    )
    return len(type_updates)


def migrate_peer_report_types(connection: sqlite3.Connection) -> int:
    """Make older p2p reports compatible with newer versions of slips

    Why this exists:
        Older Slips versions stored every evidence received from other
        peers with evidence_type='P2P_REPORT'.
        That type says nothing about what was actually detected, and the
        web interface and the db expect one meaningful type per evidence.
        Newer versions store the type of the first detection inside the
        peer report instead (see get_first_evidence_in_peer_report()).
        This func is a one-time migration that rewrites the old 'P2P_REPORT'
        rows in an existing db so they match what newer versions store.

    What it changes:
        - Only the evidence_type and source_module columns
         (source_module is set to the P2P trust module).
        - The data JSON column is never touched, so the full original
         peer report is still available.
        - Rows whose JSON can't be parsed, or whose peer report has no
         detections, are left as 'P2P_REPORT'.

    Parameters:
        connection: Writable detection database protected by its writer lock.

    Returns:
        Number of indexed report types updated for display and search.
    """
    if _is_peer_report_migration_done(connection):
        return 0

    # a temporary to-do list of evidence ids that still need checking.
    # TEMP tables live only for this connection and are never written to
    # flows.sqlite itself.
    # a failed earlier attempt can leave it behind: CREATE TEMP TABLE is
    # saved right away, but the DROP in the finally below is undone when
    # the caller rolls back, so drop any leftover first
    connection.execute("DROP TABLE IF EXISTS temp.peer_type_upgrade")
    connection.execute(
        "CREATE TEMP TABLE peer_type_upgrade(id TEXT PRIMARY KEY)"
    )
    updated_rows_count = 0
    try:
        # fill the to-do list with every old-style peer report
        connection.execute(
            "INSERT INTO peer_type_upgrade SELECT evidence_id FROM evidence "
            "WHERE evidence_type=?",
            (OLD_PEER_REPORT_TYPE,),
        )
        # work in batches so a large db doesn't load all peer reports into
        # memory at once. ordering by id lets us remove each finished batch
        # with one "id <= last id" delete below.
        while peer_reports_batch := connection.execute(
            "SELECT pending.id,e.data FROM peer_type_upgrade pending "
            "JOIN evidence e ON e.evidence_id=pending.id "
            "ORDER BY pending.id LIMIT ?",
            (PEER_REPORT_MIGRATION_BATCH_SIZE,),
        ).fetchall():
            updated_rows_count += _migrate_peer_reports_batch(
                connection, peer_reports_batch
            )
            # remove this whole batch from the to-do list (including the
            # skipped rows) so the loop moves on to the next batch
            connection.execute(
                "DELETE FROM peer_type_upgrade WHERE id<=?",
                (peer_reports_batch[-1][0],),
            )
    finally:
        # always drop the to-do list, even if something above failed
        connection.execute("DROP TABLE peer_type_upgrade")

    # mark the migration as done. the caller commits this together with
    # the updates, so either both are saved or neither is
    connection.execute(
        "INSERT INTO history_state VALUES (?, '1')",
        (PEER_REPORT_MIGRATION_DONE_KEY,),
    )
    return updated_rows_count


class DetectionHistory:
    """
    A class that keeps flows.sqlite from growing forever
    with evidence and alerts.

    It does 3 jobs, all in small timed chunks:
        - Hourly summaries: squashes evidence into one row per hour/IP/type
        in evidence_hourly,
        so old data can still be counted after the detailed rows are cleaned up.
        - Archiving: moves old evidence/alerts (plus their links and reviews)
        out of the active db into monthly files output/databases/archives/detections-YYYY-MM-NNNN.sqlite.
        - Expiry: deletes old archive files.

    slips.yaml params that control each job: (detection_history section)
    - enabled: false turns all 3 jobs off (history keeps growing).
    - Hourly summaries:
        No params. Runs whenever maintenance runs.
    - Archiving:
        active_days: evidence/alerts older than this are archived.
        max_active_size_mb: when the active db is bigger than this, archive
            earlier than active_days. 0 = no size limit.
        min_active_hours: during that early archiving, never archive
            anything younger than this.
        archive_file_size_mb: start a new archive file once the current one
            reaches this size.
        min_free_disk_mb: pause archiving while free disk space is below this.
    - Expiry:
        archive_retention_days: delete archive files this many days after
            their last write.
        max_archive_size_mb: when all archives together are bigger than this,
            delete the oldest ones early. 0 = no size limit.
        active_days: also used here to forget the ids of archived records
            older than this.
    """

    def __init__(
        self, connection: sqlite3.Connection, output_dir: str
    ) -> None:
        """Bind maintenance to one run database.

        Parameters:
            connection: Run connection protected by its process and thread locks.
            output_dir: Relative run output directory.
        """
        self.connection = connection
        self.archives_dir = Path(output_dir) / "databases" / "archives"
        # name of the archive file this pass started writing to, if any
        self.new_archive_filename: str | None = None

    def _get_checkpoint(self, key: str, default: str = "0") -> str:
        """Read a persistent maintenance checkpoint from history_state.

        Parameters:
            key: Checkpoint name.
            default: Value returned before the first checkpoint.

        Returns:
            Stored checkpoint text.
        """
        row = self.connection.execute(
            "SELECT value FROM history_state WHERE key=?", (key,)
        ).fetchone()
        return str(row[0]) if row else default

    def _set_checkpoint(self, key: str, value: Any) -> None:
        """Write a maintenance checkpoint to history_state in the current
        transaction.

        Parameters:
            key: Checkpoint name.
            value: JSON-compatible checkpoint value.
        """
        self.connection.execute(
            "INSERT INTO history_state VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, str(value)),
        )

    def update_hourly_summaries_batch(self, batch_size: int) -> int:
        """Backfill or rebuild a bounded piece of one dirty hourly summary.

        Parameters:
            batch_size: Maximum evidence records examined in this step.

        Returns:
            Number of records processed, or zero when summaries are current.
        """
        connection = self.connection
        connection.execute("BEGIN IMMEDIATE")
        # Backfill: evidence stored before the triggers existed never marked
        # its hour dirty, so walk the whole evidence table once by rowid
        # and mark every hour found.
        if self._get_checkpoint("summary_complete") != "1":
            last_backfilled_rowid = int(self._get_checkpoint("summary_cursor"))
            evidence_batch = connection.execute(
                "SELECT rowid,evidence_time FROM evidence WHERE rowid>? ORDER BY rowid LIMIT ?",
                (last_backfilled_rowid, batch_size),
            ).fetchall()
            if evidence_batch:
                connection.executemany(
                    "INSERT OR IGNORE INTO history_dirty_hours(hour) VALUES (?)",
                    [
                        (
                            int(evidence_time // SECONDS_PER_HOUR)
                            * SECONDS_PER_HOUR,
                        )
                        for _, evidence_time in evidence_batch
                        if evidence_time is not None
                    ],
                )
                self._set_checkpoint("summary_cursor", evidence_batch[-1][0])
                connection.commit()
                return len(evidence_batch)
            self._set_checkpoint("summary_complete", 1)

        # Rebuild the oldest dirty hour
        oldest_dirty_hour = connection.execute(
            "SELECT hour,generation FROM history_dirty_hours ORDER BY hour LIMIT 1"
        ).fetchone()
        if oldest_dirty_hour is None:
            connection.commit()
            return 0
        hour, generation = oldest_dirty_hour
        saved_rebuild_progress = connection.execute(
            "SELECT generation,cursor_time,cursor_id FROM history_summary_jobs WHERE hour=?",
            (hour,),
        ).fetchone()
        # a different generation means the hour changed after the saved
        # rebuild started, so its partial sums are wrong; start over
        if (
            saved_rebuild_progress is None
            or saved_rebuild_progress[0] != generation
        ):
            connection.execute(
                "DELETE FROM evidence_hourly WHERE hour=?", (hour,)
            )
            connection.execute(
                "INSERT OR REPLACE INTO history_summary_jobs VALUES (?,?,?,?)",
                (hour, generation, hour, ""),
            )
            resume_after_time, resume_after_evidence_id = hour, ""
        else:
            _, resume_after_time, resume_after_evidence_id = (
                saved_rebuild_progress
            )
        evidence_batch = connection.execute(
            "SELECT evidence_id,evidence_time,profile_ip,evidence_type,"
            "threat_level,source_module,COALESCE(whitelisted,0),"
            "accumulated_threat_level,accumulated_ratl,"
            "(SELECT COUNT(*) FROM alert_evidence ae WHERE ae.evidence_id=e.evidence_id) "
            "FROM evidence e INDEXED BY evidence_time_cover_idx WHERE evidence_time>=? AND evidence_time<? "
            "AND (evidence_time,evidence_id)>(?,?) ORDER BY evidence_time,evidence_id LIMIT ?",
            (
                hour,
                hour + SECONDS_PER_HOUR,
                resume_after_time,
                resume_after_evidence_id,
                batch_size,
            ),
        ).fetchall()
        for (
            evidence_id,
            evidence_time,
            profile_ip,
            evidence_type,
            threat_level,
            source_module,
            whitelisted,
            accumulated_threat_level,
            accumulated_ratl,
            linked_alerts_count,
        ) in evidence_batch:
            # "excluded" in the SQL below is SQLite's name for the row
            # that failed to insert because of the conflict
            connection.execute(
                f"INSERT INTO evidence_hourly({EVIDENCE_HOURLY_COLUMNS}) VALUES (?,?,?,?,?,?,1,?,?,?,?,?) "
                "ON CONFLICT DO UPDATE SET "
                "record_count=record_count+1,first_time=MIN(first_time,excluded.first_time),"
                "last_time=MAX(last_time,excluded.last_time),max_atl=COALESCE(MAX(max_atl,excluded.max_atl),max_atl,excluded.max_atl),"
                "max_ratl=COALESCE(MAX(max_ratl,excluded.max_ratl),max_ratl,excluded.max_ratl),alert_count=alert_count+excluded.alert_count",
                (
                    hour,
                    profile_ip,
                    evidence_type,
                    threat_level,
                    source_module,
                    whitelisted,
                    evidence_time,
                    evidence_time,
                    accumulated_threat_level,
                    accumulated_ratl,
                    linked_alerts_count,
                ),
            )
        if evidence_batch:
            last_evidence_id, last_evidence_time = evidence_batch[-1][:2]
            connection.execute(
                "UPDATE history_summary_jobs SET cursor_time=?,cursor_id=? WHERE hour=?",
                (last_evidence_time, last_evidence_id, hour),
            )
        # a short batch means this hour has no more evidence to add
        if len(evidence_batch) < batch_size:
            connection.execute(
                "DELETE FROM history_dirty_hours WHERE hour=?", (hour,)
            )
            connection.execute(
                "DELETE FROM history_summary_jobs WHERE hour=?", (hour,)
            )
        connection.commit()
        return max(len(evidence_batch), 1)

    def _open_archive_db(self, filename: str) -> sqlite3.Connection:
        """Open a monthly archive with durable commits and compatible tables.

        Parameters:
            filename: Internally generated monthly archive filename.

        Returns:
            Writable archive connection with no pending transaction.
        """
        self.archives_dir.mkdir(parents=True, exist_ok=True)
        if (self.archives_dir / filename).is_symlink():
            raise OSError("Archive destination must not be a symbolic link")
        archive_db = sqlite3.connect(self.archives_dir / filename, timeout=0)
        try:
            # FULL = every commit is flushed to disk before returning, so
            # rows are never deleted from flows.sqlite before they're safe
            archive_db.execute("PRAGMA synchronous=FULL")
            archive_db.execute("BEGIN IMMEDIATE")
            for table in TABLES_CREATED_IN_EACH_ARCHIVE:
                create_table_sql = self.connection.execute(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
                    (table,),
                ).fetchone()
                if create_table_sql:
                    archive_db.execute(
                        create_table_sql[0].replace(
                            "CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1
                        )
                    )
            archive_only_schema = (
                "CREATE TABLE IF NOT EXISTS archive_metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL)",
                "CREATE INDEX IF NOT EXISTS evidence_time_cover_idx ON evidence(evidence_time,evidence_id,"
                "profile_ip,evidence_type,threat_level,source_module,whitelisted,accumulated_threat_level,accumulated_ratl)",
                "CREATE INDEX IF NOT EXISTS archive_alert_time_idx ON alerts(alert_time,alert_id)",
                "CREATE INDEX IF NOT EXISTS alert_evidence_lookup_idx ON alert_evidence(evidence_id,alert_id)",
                "CREATE INDEX IF NOT EXISTS evidence_flows_uid_idx ON evidence_flows(uid)",
            )
            for statement in archive_only_schema:
                archive_db.execute(statement)
            archive_db.commit()
            return archive_db
        except Exception:
            archive_db.close()
            raise

    def _copy_row_to_archive(
        self,
        archive_db: sqlite3.Connection,
        table: str,
        id_column: str,
        record_id: str,
    ) -> bool:
        """Replace one archive row with its current source value.

        Parameters:
            archive_db: Destination connection.
            table: Internal table name.
            id_column: Internal identifier column.
            record_id: Detection identifier.

        Returns:
            Whether the source row exists.
        """
        cursor = self.connection.execute(
            f"SELECT * FROM {table} WHERE {id_column}=?", (record_id,)
        )
        row = cursor.fetchone()
        if row is None:
            return False
        column_names = ",".join(column[0] for column in cursor.description)
        placeholders = ",".join("?" for _ in row)
        archive_db.execute(
            f"INSERT OR REPLACE INTO {table}({column_names}) VALUES ({placeholders})",
            tuple(row),
        )
        return True

    def _pick_archive_filename(
        self, now: float, max_archive_file_size_mb: int
    ) -> str:
        """Choose the monthly archive part that the next record goes into.

        Parameters:
            now: Current Unix time, decides the month in the filename.
            max_archive_file_size_mb: Start a new part once the current one
                reaches this size.

        Returns:
            Filename like detections-YYYY-MM-NNNN.sqlite.
        """
        current_month_prefix = datetime.fromtimestamp(
            now, timezone.utc
        ).strftime("detections-%Y-%m")

        def part_number(path: Path) -> int:
            return int(path.stem.rsplit("-", 1)[1])

        this_month_archives = sorted(
            (
                path
                for path in self.archives_dir.glob(
                    f"{current_month_prefix}-*.sqlite"
                )
                if ARCHIVE_FILENAME_PATTERN.fullmatch(path.name)
            ),
            key=part_number,
        )
        last_used_filename = self._get_checkpoint("archive_filename", "")
        archive_part = (
            part_number(this_month_archives[-1]) if this_month_archives else 1
        )
        if last_used_filename.startswith(current_month_prefix + "-"):
            # if the last used part was deleted (expired), never reuse its
            # number, move to the next one
            last_used_was_deleted = not (
                self.archives_dir / last_used_filename
            ).exists()
            archive_part = max(
                archive_part,
                part_number(Path(last_used_filename))
                + (1 if last_used_was_deleted else 0),
            )
        current_part_path = (
            self.archives_dir
            / f"{current_month_prefix}-{archive_part:04d}.sqlite"
        )
        if (
            current_part_path.exists()
            and current_part_path.stat().st_size
            >= max_archive_file_size_mb * BYTES_PER_MB
        ):
            archive_part += 1
        return f"{current_month_prefix}-{archive_part:04d}.sqlite"

    def archive_next_batch(
        self,
        table: str,
        archive_older_than: float,
        batch_size: int,
        now: float,
        max_archive_file_size_mb: int = 256,
    ) -> int:
        """Copy or purge one restartable, bounded batch of links of the
        record currently being archived.

        Parameters:
            table: Internal evidence or alerts table name.
            archive_older_than: Records with a time before this Unix time
                are archived.
            batch_size: Maximum links copied or removed.
            now: Current Unix time used for the archive month.
            max_archive_file_size_mb: Target size of a completed monthly part.

        Returns:
            Number of maintenance steps done (0 = nothing left to archive).
        """
        connection = self.connection
        columns = ARCHIVABLE_TABLES[table]
        id_column = columns.id_column
        links_table = columns.links_table
        linked_id_column = columns.linked_id_column
        connection.execute("BEGIN IMMEDIATE")
        in_progress = connection.execute(
            "SELECT record_id,filename,phase,cursor,restart FROM history_archive_queue WHERE entity=?",
            (table,),
        ).fetchone()
        if in_progress is None:
            # evidence that belongs to a still-active alert must stay, or
            # that alert would lose its evidence
            skip_evidence_of_recent_alerts_sql = (
                " AND NOT EXISTS (SELECT 1 FROM alert_evidence ae JOIN alerts a ON a.alert_id=ae.alert_id "
                "WHERE ae.evidence_id=evidence.evidence_id AND a.alert_time>=?)"
                if table == "evidence"
                else ""
            )
            oldest_expired_record = connection.execute(
                f"SELECT {id_column} FROM {table} "
                f"WHERE {columns.time_column}<?{skip_evidence_of_recent_alerts_sql} "
                f"ORDER BY {columns.time_column},{id_column} LIMIT 1",
                (
                    (archive_older_than, archive_older_than)
                    if skip_evidence_of_recent_alerts_sql
                    else (archive_older_than,)
                ),
            ).fetchone()
            if oldest_expired_record is None:
                connection.commit()
                return 0
            record_id = oldest_expired_record[0]
            archive_filename = self._pick_archive_filename(
                now, max_archive_file_size_mb
            )
            if archive_filename != self._get_checkpoint(
                "archive_filename", ""
            ):
                self.new_archive_filename = archive_filename
            self._set_checkpoint("archive_filename", archive_filename)
            connection.execute(
                "INSERT INTO history_archive_queue(entity,record_id,filename) VALUES (?,?,?)",
                (table, record_id, archive_filename),
            )
            phase, last_handled_link_id, links_changed_during_copy = (
                "copy",
                "",
                0,
            )
        else:
            (
                record_id,
                archive_filename,
                phase,
                last_handled_link_id,
                links_changed_during_copy,
            ) = in_progress
        with closing(self._open_archive_db(archive_filename)) as archive_db:
            try:
                if phase == "purge":
                    self._purge_links_batch(
                        archive_db, table, record_id, batch_size, now
                    )
                elif links_changed_during_copy:
                    # undo the partly copied links, the copy starts over
                    # once they're all removed from the archive
                    links_batch = archive_db.execute(
                        f"SELECT {linked_id_column} FROM {links_table} "
                        f"WHERE {id_column}=? ORDER BY {linked_id_column} LIMIT ?",
                        (record_id, batch_size),
                    ).fetchall()
                    archive_db.executemany(
                        f"DELETE FROM {links_table} WHERE {id_column}=? AND {linked_id_column}=?",
                        [(record_id, link[0]) for link in links_batch],
                    )
                    archive_db.execute(
                        "INSERT OR REPLACE INTO archive_metadata VALUES ('updated_at',?)",
                        (str(now),),
                    )
                    archive_db.commit()
                    if len(links_batch) < batch_size:
                        connection.execute(
                            "UPDATE history_archive_queue SET restart=0,cursor='' WHERE entity=?",
                            (table,),
                        )
                else:
                    self._copy_links_batch(
                        archive_db,
                        table,
                        record_id,
                        archive_older_than,
                        last_handled_link_id,
                        batch_size,
                        now,
                    )
                # a no-op when a helper above already committed
                connection.commit()
            finally:
                archive_db.rollback()
        return 1

    def _purge_links_batch(
        self,
        archive_db: sqlite3.Connection,
        table: str,
        record_id: str,
        batch_size: int,
        now: float,
    ) -> None:
        """Delete one batch of leftover links of an already archived record
        from flows.sqlite, after saving them in the archive.

        Commits and ends the transaction itself only when the record is
        back in flows.sqlite and the purge is cancelled.

        Parameters:
            archive_db: Open archive the record was moved to.
            table: Internal evidence or alerts table name.
            record_id: Id of the archived record.
            batch_size: Maximum links handled.
            now: Current Unix time stored as the archive's last write.
        """
        connection = self.connection
        columns = ARCHIVABLE_TABLES[table]
        id_column = columns.id_column
        links_table = columns.links_table
        linked_id_column = columns.linked_id_column
        if connection.execute(
            f"SELECT 1 FROM {table} WHERE {id_column}=?", (record_id,)
        ).fetchone():
            connection.execute(
                "DELETE FROM history_archive_queue WHERE entity=?",
                (table,),
            )
            connection.commit()
            return
        links_batch = connection.execute(
            f"SELECT {linked_id_column} FROM {links_table} "
            f"WHERE {id_column}=? ORDER BY {linked_id_column} LIMIT ?",
            (record_id, batch_size),
        ).fetchall()
        # Also preserve links that arrived after the parent was archived.
        archive_db.executemany(
            f"INSERT OR IGNORE INTO {links_table}({id_column},{linked_id_column}) VALUES (?,?)",
            [(record_id, link[0]) for link in links_batch],
        )
        archive_db.execute(
            "INSERT OR REPLACE INTO archive_metadata VALUES ('updated_at',?)",
            (str(now),),
        )
        archive_db.commit()
        connection.executemany(
            f"DELETE FROM {links_table} WHERE {id_column}=? AND {linked_id_column}=?",
            [(record_id, link[0]) for link in links_batch],
        )
        if len(links_batch) < batch_size:
            connection.execute(
                "DELETE FROM history_archive_queue WHERE entity=?",
                (table,),
            )

    def _copy_links_batch(
        self,
        archive_db: sqlite3.Connection,
        table: str,
        record_id: str,
        archive_older_than: float,
        last_handled_link_id: str,
        batch_size: int,
        now: float,
    ) -> None:
        """Copy one batch of a record's links to the archive. After the last
        batch, copy the record and its review too, then delete both from
        flows.sqlite.

        Commits and ends the transaction itself only when the record no
        longer needs archiving and is dropped from the queue.

        Parameters:
            archive_db: Open archive the record is moved to.
            table: Internal evidence or alerts table name.
            record_id: Id of the record being archived.
            archive_older_than: Archive cutoff Unix time.
            last_handled_link_id: Last link id copied in a previous batch.
            batch_size: Maximum links copied.
            now: Current Unix time stored as the archive's last write.
        """
        connection = self.connection
        columns = ARCHIVABLE_TABLES[table]
        id_column = columns.id_column
        links_table = columns.links_table
        linked_id_column = columns.linked_id_column
        record_time = connection.execute(
            f"SELECT {columns.time_column} FROM {table} WHERE {id_column}=?",
            (record_id,),
        ).fetchone()
        linked_to_recent_alert = (
            table == "evidence"
            and connection.execute(
                "SELECT 1 FROM alert_evidence ae JOIN alerts a ON a.alert_id=ae.alert_id "
                "WHERE ae.evidence_id=? AND a.alert_time>=? LIMIT 1",
                (record_id, archive_older_than),
            ).fetchone()
        )
        # the record was deleted, got a newer time, or got linked to a
        # recent alert since it was queued: drop it from the queue
        if (
            record_time is None
            or record_time[0] is None
            or float(record_time[0]) >= archive_older_than
            or linked_to_recent_alert
        ):
            connection.execute(
                "DELETE FROM history_archive_queue WHERE entity=?",
                (table,),
            )
            connection.commit()
            return
        links_batch = connection.execute(
            f"SELECT {linked_id_column} FROM {links_table} "
            f"WHERE {id_column}=? AND {linked_id_column}>? "
            f"ORDER BY {linked_id_column} LIMIT ?",
            (record_id, last_handled_link_id, batch_size),
        ).fetchall()
        archive_db.executemany(
            f"INSERT OR IGNORE INTO {links_table}({id_column},{linked_id_column}) VALUES (?,?)",
            [(record_id, link[0]) for link in links_batch],
        )
        all_links_copied = len(links_batch) < batch_size
        if all_links_copied:
            self._copy_row_to_archive(archive_db, table, id_column, record_id)
            self._copy_row_to_archive(
                archive_db, columns.reviews_table, id_column, record_id
            )
            archive_db.execute(
                "INSERT OR REPLACE INTO archive_metadata VALUES ('ready','1')"
            )
        archive_db.execute(
            "INSERT OR REPLACE INTO archive_metadata VALUES ('updated_at',?)",
            (str(now),),
        )
        # the archive is committed (and flushed to disk) before anything
        # is deleted from flows.sqlite, so a crash never loses a record
        archive_db.commit()
        if all_links_copied:
            connection.execute(
                "INSERT OR REPLACE INTO history_archived_ids VALUES (?,?,?)",
                (table, record_id, now),
            )
            connection.execute(
                f"DELETE FROM {table} WHERE {id_column}=?",
                (record_id,),
            )
            connection.execute(
                f"DELETE FROM {columns.reviews_table} WHERE {id_column}=?",
                (record_id,),
            )
            connection.execute(
                "UPDATE history_archive_queue SET phase='purge',cursor='' WHERE entity=?",
                (table,),
            )
        elif links_batch:
            connection.execute(
                "UPDATE history_archive_queue SET cursor=? WHERE entity=?",
                (links_batch[-1][0], table),
            )

    def delete_one_expired_archive(
        self,
        now: float,
        retention_days: int,
        max_total_archives_size_mb: int = 0,
    ) -> int:
        """Remove at most one expired, unused monthly archive per pass.

        Parameters:
            now: Current Unix time.
            retention_days: Days to retain an archive after its last write.
            max_total_archives_size_mb: Optional cap for all archives
                together. 0 = no cap.

        Returns:
            Number of removed archive files.
        """
        archives_in_use = {
            str(row[0])
            for row in self.connection.execute(
                "SELECT filename FROM history_archive_queue"
            )
        }
        archive_paths = sorted(
            (
                path
                for path in self.archives_dir.glob(ARCHIVE_FILENAME_GLOB)
                if ARCHIVE_FILENAME_PATTERN.fullmatch(path.name)
                and not path.is_symlink()
            ),
            key=lambda path: path.stat().st_mtime,
        )
        total_archives_size = sum(
            path.stat().st_size for path in archive_paths
        )
        oldest_allowed_write_time = now - retention_days * SECONDS_PER_DAY
        for archive_path in archive_paths:
            total_size_over_limit = bool(
                max_total_archives_size_mb
                and total_archives_size
                > max_total_archives_size_mb * BYTES_PER_MB
            )
            last_write_time = archive_path.stat().st_mtime
            try:
                with sqlite3.connect(
                    f"file:{archive_path}?mode=ro", uri=True, timeout=0.1
                ) as archive_db:
                    updated_at = archive_db.execute(
                        "SELECT value FROM archive_metadata WHERE key='updated_at'"
                    ).fetchone()
                    if updated_at:
                        last_write_time = float(updated_at[0])
            except sqlite3.OperationalError:
                pass
            if archive_path.name in archives_in_use or (
                not total_size_over_limit
                and last_write_time >= oldest_allowed_write_time
            ):
                continue
            archive_path.unlink()
            return 1
        return 0

    @staticmethod
    def _handle_maintenance_sqlite_error(
        error: sqlite3.OperationalError, status: dict[str, Any]
    ) -> None:
        """Record a busy database or a used-up time budget in the status,
        and raise any other SQLite error.

        Parameters:
            error: SQLite operation failure.
            status: Current pass statistics, including its operation phase.
        """
        error_code = getattr(error, "sqlite_errorcode", None)
        # the low byte of an extended SQLite error code is its main code
        # (e.g. SQLITE_BUSY_SNAPSHOT -> SQLITE_BUSY)
        primary_error_code = (
            error_code & 0xFF if isinstance(error_code, int) else None
        )
        database_is_busy = primary_error_code == getattr(
            sqlite3, "SQLITE_BUSY", 5
        ) or (
            error_code is None
            and str(error).lower()
            in {"database is locked", "database is busy"}
        )
        time_budget_ran_out = primary_error_code == getattr(
            sqlite3, "SQLITE_INTERRUPT", 9
        ) or (error_code is None and str(error).lower() == "interrupted")
        if not database_is_busy and not time_budget_ran_out:
            # read by the profiler to say where maintenance failed
            error.history_phase = status["phase"]
            raise error
        status["interrupted"] = True
        status["deferred"] = database_is_busy
        status["sqlite_errorcode"] = error_code
        status["sqlite_errorname"] = getattr(error, "sqlite_errorname", "")

    def run_maintenance_pass(
        self, policy: dict[str, int | bool], now: float
    ) -> dict[str, Any]:
        """Share a short time budget between hourly summaries, archiving
        and archive expiry.

        Parameters:
            policy: Validated detection_history configuration.
            now: Current Unix time.

        Returns:
            Persistent maintenance health and progress statistics.
            "new_archive_file" is the name of an archive file this pass
            started writing to (only set when it is a new file),
            "units" is the number of maintenance steps done in this pass,
            "deferred" means the pass gave up because the db was busy.
        """
        pass_started_at = time.monotonic()
        pass_deadline = (
            pass_started_at + MAX_MAINTENANCE_PASS_DURATION_MS / 1000
        )
        self.new_archive_filename = None
        batch_size = MAINTENANCE_BATCH_SIZE
        status: dict[str, Any] = {
            "last_run": now,
            "units": 0,
            "interrupted": False,
            "deferred": False,
            "phase": "expiration",
        }
        max_active_size_bytes = (
            int(policy.get("max_active_size_mb", 2048)) * BYTES_PER_MB
        )
        # SQLite calls this every 1000 internal instructions; returning 1
        # stops the running query with SQLITE_INTERRUPT
        self.connection.set_progress_handler(
            lambda: int(time.monotonic() >= pass_deadline), 1000
        )
        try:
            status["expired_archives"] = self.delete_one_expired_archive(
                now,
                int(policy["archive_retention_days"]),
                int(policy.get("max_archive_size_mb", 4096)),
            )
            status["phase"] = "cleanup"
            self.connection.execute(
                "DELETE FROM history_archived_ids WHERE rowid IN "
                "(SELECT rowid FROM history_archived_ids WHERE archived_at<? LIMIT ?)",
                (
                    now - int(policy["active_days"]) * SECONDS_PER_DAY,
                    batch_size,
                ),
            )
            self.connection.commit()
            status["phase"] = "storage"
            free_disk_bytes = shutil.disk_usage(self.archives_dir.parent).free
            status["disk_pressure"] = (
                free_disk_bytes
                < int(policy["min_free_disk_mb"]) * BYTES_PER_MB
            )
            page_size = self.connection.execute("PRAGMA page_size").fetchone()[
                0
            ]
            page_count = self.connection.execute(
                "PRAGMA page_count"
            ).fetchone()[0]
            # pages freed by deletes but still inside the file
            free_page_count = self.connection.execute(
                "PRAGMA freelist_count"
            ).fetchone()[0]
            status["active_size_bytes"] = (
                page_count - free_page_count
            ) * page_size
            status["size_pressure"] = bool(
                max_active_size_bytes
                and status["active_size_bytes"] > max_active_size_bytes
            )
            archive_after_seconds = (
                int(policy["active_days"]) * SECONDS_PER_DAY
            )
            if status["size_pressure"]:
                archive_after_seconds = min(
                    archive_after_seconds,
                    int(policy.get("min_active_hours", 24)) * SECONDS_PER_HOUR,
                )
            while time.monotonic() < pass_deadline:
                status["phase"] = "summary"
                steps_done_this_round = self.update_hourly_summaries_batch(
                    batch_size
                )
                status["units"] += steps_done_this_round
                if not status["disk_pressure"]:
                    for table in ARCHIVABLE_TABLES:
                        if time.monotonic() >= pass_deadline:
                            break
                        status["phase"] = f"archive_{table}"
                        archive_steps_done = self.archive_next_batch(
                            table,
                            now - archive_after_seconds,
                            batch_size,
                            now,
                            int(policy.get("archive_file_size_mb", 256)),
                        )
                        steps_done_this_round += archive_steps_done
                        status["units"] += archive_steps_done
                if not steps_done_this_round:
                    break
        except sqlite3.OperationalError as error:
            self._handle_maintenance_sqlite_error(error, status)
        finally:
            self.connection.set_progress_handler(None, 0)
            self.connection.rollback()
        status["elapsed_ms"] = round(
            (time.monotonic() - pass_started_at) * 1000, 1
        )
        if self.new_archive_filename:
            status["new_archive_file"] = self.new_archive_filename
        if status["deferred"]:
            return status
        try:
            status["phase"] = "health"
            status["pending_hours"] = self.connection.execute(
                "SELECT COUNT(*) FROM history_dirty_hours"
            ).fetchone()[0]
            status["pending_archives"] = self.connection.execute(
                "SELECT COUNT(*) FROM history_archive_queue"
            ).fetchone()[0]
            status["oldest_detection_at"] = self.connection.execute(
                "SELECT MIN(evidence_time) FROM evidence"
            ).fetchone()[0]
            status["active_target_bytes"] = max_active_size_bytes
            status["archive_target_bytes"] = (
                int(policy.get("max_archive_size_mb", 4096)) * BYTES_PER_MB
            )
            status["phase"] = "checkpoint"
            self._set_checkpoint("maintenance", json.dumps(status))
            self.connection.commit()
        except sqlite3.OperationalError as error:
            self._handle_maintenance_sqlite_error(error, status)
        finally:
            self.connection.rollback()
        return status
