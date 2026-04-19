# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
import os
from pathlib import Path
from time import time

from slips_files.common.abstracts.isqlite import ISQLite
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.printer import Printer
from slips_files.core.output import Output

DEFAULT_T_CELL_STORE_DIR = "output/t_cell"


class _BaseTCellSQLiteDB(ISQLite):
    name = "BaseTCellSQLiteDB"

    def __init__(self, logger: Output, db_path: str, main_pid: int):
        self.printer = Printer(logger, self.name)
        self.db_path = db_path
        self._init_db_file()
        super().__init__(self.name.lower(), main_pid, db_path)
        self.init_tables()

    def _init_db_file(self):
        db_file = Path(self.db_path)
        db_file.parent.mkdir(parents=True, exist_ok=True)
        if not db_file.exists():
            db_file.touch()
        os.chmod(db_file, 0o777)

    @staticmethod
    def _loads(value: str, fallback):
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return fallback


class TCellSQLiteDB(_BaseTCellSQLiteDB):
    name = "TCellSQLiteDB"

    def init_tables(self):
        self.create_table(
            "observations",
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "evidence_id TEXT NOT NULL, "
            "evidence_type TEXT NOT NULL, "
            "evidence_signal TEXT NOT NULL, "
            "profile_ip TEXT NOT NULL, "
            "timewindow_number INTEGER NOT NULL, "
            "timestamp TEXT NOT NULL, "
            "observed_at REAL NOT NULL, "
            "confidence REAL NOT NULL, "
            "threat_level TEXT NOT NULL, "
            "threat_level_value REAL NOT NULL, "
            "interface TEXT, "
            "uid_json TEXT NOT NULL, "
            "antigen_count INTEGER NOT NULL, "
            "antigens_json TEXT NOT NULL, "
            "matched_regexes_json TEXT NOT NULL, "
            "raw_evidence_json TEXT NOT NULL",
        )
        self.create_table(
            "cells",
            "cell_key TEXT PRIMARY KEY, "
            "profile_ip TEXT NOT NULL, "
            "regex_type TEXT NOT NULL, "
            "antigen_value TEXT NOT NULL, "
            "state INTEGER NOT NULL, "
            "state_name TEXT NOT NULL, "
            "matched_regex_hash TEXT, "
            "matched_regex TEXT, "
            "matched_value TEXT, "
            "anergic_until REAL, "
            "effector_cooldown_until REAL, "
            "last_observation_id INTEGER, "
            "last_evidence_id TEXT, "
            "last_transition_at REAL, "
            "last_co_stimulation REAL, "
            "last_effector_score REAL, "
            "last_memory_score REAL, "
            "context_json TEXT NOT NULL, "
            "created_at REAL NOT NULL, "
            "updated_at REAL NOT NULL",
        )
        self.create_table(
            "transitions",
            "id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "cell_key TEXT NOT NULL, "
            "profile_ip TEXT NOT NULL, "
            "regex_type TEXT NOT NULL, "
            "antigen_value TEXT NOT NULL, "
            "evidence_id TEXT NOT NULL, "
            "observation_id INTEGER, "
            "from_state INTEGER, "
            "to_state INTEGER, "
            "reason TEXT NOT NULL, "
            "matched_regex_hash TEXT, "
            "matched_regex TEXT, "
            "matched_value TEXT, "
            "scores_json TEXT NOT NULL, "
            "created_at REAL NOT NULL",
        )
        self.create_table(
            "memories",
            "cell_key TEXT PRIMARY KEY, "
            "profile_ip TEXT NOT NULL, "
            "regex_type TEXT NOT NULL, "
            "antigen_value TEXT NOT NULL, "
            "regex_hash TEXT NOT NULL, "
            "regex TEXT NOT NULL, "
            "matched_value TEXT NOT NULL, "
            "context_json TEXT NOT NULL, "
            "created_at REAL NOT NULL, "
            "updated_at REAL NOT NULL",
        )
        self.execute(
            "CREATE INDEX IF NOT EXISTS idx_tcell_observations_profile_time "
            "ON observations (profile_ip, observed_at)"
        )
        self.execute(
            "CREATE INDEX IF NOT EXISTS idx_tcell_observations_signal_time "
            "ON observations (evidence_signal, observed_at)"
        )
        self.execute(
            "CREATE INDEX IF NOT EXISTS idx_tcell_cells_profile_type "
            "ON cells (profile_ip, regex_type)"
        )
        self.execute(
            "CREATE INDEX IF NOT EXISTS idx_tcell_cells_regex_hash "
            "ON cells (matched_regex_hash)"
        )
        self.execute(
            "CREATE INDEX IF NOT EXISTS idx_tcell_transitions_cell_time "
            "ON transitions (cell_key, created_at)"
        )
        self.execute(
            "CREATE INDEX IF NOT EXISTS idx_tcell_transitions_regex_time "
            "ON transitions (matched_regex_hash, profile_ip, created_at)"
        )
        self.execute(
            "CREATE INDEX IF NOT EXISTS idx_tcell_memories_regex_hash "
            "ON memories (regex_hash)"
        )

    def insert_observation(self, record: dict) -> int:
        cursor = self.execute(
            "INSERT INTO observations ("
            "evidence_id, evidence_type, evidence_signal, profile_ip, "
            "timewindow_number, timestamp, observed_at, confidence, "
            "threat_level, threat_level_value, interface, uid_json, "
            "antigen_count, antigens_json, matched_regexes_json, raw_evidence_json"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                record["evidence_id"],
                record["evidence_type"],
                record["evidence_signal"],
                record["profile_ip"],
                record["timewindow_number"],
                record["timestamp"],
                record["observed_at"],
                record["confidence"],
                record["threat_level"],
                record["threat_level_value"],
                record.get("interface"),
                json.dumps(record.get("uids", [])),
                int(record.get("antigen_count", 0)),
                json.dumps(record.get("antigens", [])),
                json.dumps(record.get("matched_regexes", [])),
                json.dumps(record.get("raw_evidence", {})),
            ),
        )
        return cursor.lastrowid if cursor else 0

    def update_observation_matches(
        self, observation_id: int, matched_regexes: list[dict]
    ):
        self.execute(
            "UPDATE observations SET matched_regexes_json = ? WHERE id = ?",
            (json.dumps(matched_regexes or []), observation_id),
        )

    @staticmethod
    def _row_to_observation(row) -> dict:
        return {
            "id": row[0],
            "evidence_id": row[1],
            "evidence_type": row[2],
            "evidence_signal": row[3],
            "profile_ip": row[4],
            "timewindow_number": row[5],
            "timestamp": row[6],
            "observed_at": row[7],
            "confidence": row[8],
            "threat_level": row[9],
            "threat_level_value": row[10],
            "interface": row[11],
            "uids": _BaseTCellSQLiteDB._loads(row[12], []),
            "antigen_count": row[13],
            "antigens": _BaseTCellSQLiteDB._loads(row[14], []),
            "matched_regexes": _BaseTCellSQLiteDB._loads(row[15], []),
            "raw_evidence": _BaseTCellSQLiteDB._loads(row[16], {}),
        }

    def get_observation(self, observation_id: int) -> dict | None:
        row = self.select(
            "observations",
            condition="id = ?",
            params=(observation_id,),
            limit=1,
        )
        if not row:
            return None
        return self._row_to_observation(row)

    def get_recent_observations(
        self,
        profile_ip: str,
        since_ts: float,
        until_ts: float | None = None,
        evidence_signal: str | None = None,
    ) -> list[dict]:
        condition_parts = ["profile_ip = ?", "observed_at >= ?"]
        params = [profile_ip, since_ts]
        if until_ts is not None:
            condition_parts.append("observed_at < ?")
            params.append(until_ts)
        if evidence_signal:
            condition_parts.append("evidence_signal = ?")
            params.append(evidence_signal)

        rows = self.select(
            "observations",
            condition=" AND ".join(condition_parts),
            params=tuple(params),
            order_by="observed_at DESC, id DESC",
        )
        rows = rows or []
        return [self._row_to_observation(row) for row in rows]

    def prune_observations(self, created_before: float):
        self.execute(
            "DELETE FROM observations WHERE observed_at < ?", (created_before,)
        )

    @staticmethod
    def _row_to_cell(row) -> dict:
        return {
            "cell_key": row[0],
            "profile_ip": row[1],
            "regex_type": row[2],
            "antigen_value": row[3],
            "state": row[4],
            "state_name": row[5],
            "matched_regex_hash": row[6],
            "matched_regex": row[7],
            "matched_value": row[8],
            "anergic_until": row[9],
            "effector_cooldown_until": row[10],
            "last_observation_id": row[11],
            "last_evidence_id": row[12],
            "last_transition_at": row[13],
            "last_co_stimulation": row[14],
            "last_effector_score": row[15],
            "last_memory_score": row[16],
            "context": _BaseTCellSQLiteDB._loads(row[17], {}),
            "created_at": row[18],
            "updated_at": row[19],
        }

    def get_cell(self, cell_key: str) -> dict | None:
        row = self.select(
            "cells",
            condition="cell_key = ?",
            params=(cell_key,),
            limit=1,
        )
        if not row:
            return None
        return self._row_to_cell(row)

    def get_all_cells(self) -> list[dict]:
        rows = self.select("cells", order_by="updated_at DESC") or []
        return [self._row_to_cell(row) for row in rows]

    def get_cells_for_profile_states(
        self, profile_ip: str, states: list[int] | tuple[int, ...]
    ) -> list[dict]:
        normalized_states = [
            int(state) for state in (states or []) if state is not None
        ]
        if not normalized_states:
            return []

        placeholders = ", ".join("?" for _ in normalized_states)
        rows = self.select(
            "cells",
            condition=(
                f"profile_ip = ? AND state IN ({placeholders})"
            ),
            params=(profile_ip, *normalized_states),
            order_by="updated_at DESC, created_at DESC",
        )
        rows = rows or []
        return [self._row_to_cell(row) for row in rows]

    def upsert_cell(self, record: dict):
        self.execute(
            "INSERT OR REPLACE INTO cells ("
            "cell_key, profile_ip, regex_type, antigen_value, state, state_name, "
            "matched_regex_hash, matched_regex, matched_value, anergic_until, "
            "effector_cooldown_until, last_observation_id, last_evidence_id, "
            "last_transition_at, last_co_stimulation, last_effector_score, "
            "last_memory_score, context_json, created_at, updated_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                record["cell_key"],
                record["profile_ip"],
                record["regex_type"],
                record["antigen_value"],
                record["state"],
                record["state_name"],
                record.get("matched_regex_hash"),
                record.get("matched_regex"),
                record.get("matched_value"),
                record.get("anergic_until"),
                record.get("effector_cooldown_until"),
                record.get("last_observation_id"),
                record.get("last_evidence_id"),
                record.get("last_transition_at"),
                record.get("last_co_stimulation"),
                record.get("last_effector_score"),
                record.get("last_memory_score"),
                json.dumps(record.get("context", {})),
                record["created_at"],
                record["updated_at"],
            ),
        )

    @staticmethod
    def _row_to_transition(row) -> dict:
        return {
            "id": row[0],
            "cell_key": row[1],
            "profile_ip": row[2],
            "regex_type": row[3],
            "antigen_value": row[4],
            "evidence_id": row[5],
            "observation_id": row[6],
            "from_state": row[7],
            "to_state": row[8],
            "reason": row[9],
            "matched_regex_hash": row[10],
            "matched_regex": row[11],
            "matched_value": row[12],
            "scores": _BaseTCellSQLiteDB._loads(row[13], {}),
            "created_at": row[14],
        }

    def insert_transition(self, record: dict) -> int:
        cursor = self.execute(
            "INSERT INTO transitions ("
            "cell_key, profile_ip, regex_type, antigen_value, evidence_id, "
            "observation_id, from_state, to_state, reason, matched_regex_hash, "
            "matched_regex, matched_value, scores_json, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                record["cell_key"],
                record["profile_ip"],
                record["regex_type"],
                record["antigen_value"],
                record["evidence_id"],
                record.get("observation_id"),
                record.get("from_state"),
                record.get("to_state"),
                record["reason"],
                record.get("matched_regex_hash"),
                record.get("matched_regex"),
                record.get("matched_value"),
                json.dumps(record.get("scores", {})),
                record.get("created_at") or time(),
            ),
        )
        return cursor.lastrowid if cursor else 0

    def get_transitions(self, cell_key: str | None = None) -> list[dict]:
        condition = None
        params = ()
        if cell_key:
            condition = "cell_key = ?"
            params = (cell_key,)
        rows = self.select(
            "transitions",
            condition=condition,
            params=params,
            order_by="created_at ASC, id ASC",
        )
        rows = rows or []
        return [self._row_to_transition(row) for row in rows]

    def has_recent_regex_activity(
        self,
        profile_ip: str,
        regex_hash: str,
        since_ts: float,
        exclude_observation_ids: list[int] | tuple[int, ...] | set[int] | None = None,
        exclude_observation_id: int | None = None,
    ) -> bool:
        condition = (
            "profile_ip = ? AND matched_regex_hash = ? AND created_at >= ?"
        )
        params = [profile_ip, regex_hash, since_ts]
        excluded_ids = set()
        for value in exclude_observation_ids or []:
            try:
                excluded_ids.add(int(value))
            except (TypeError, ValueError):
                continue
        if exclude_observation_id is not None:
            try:
                excluded_ids.add(int(exclude_observation_id))
            except (TypeError, ValueError):
                pass
        if excluded_ids:
            placeholders = ",".join("?" for _ in excluded_ids)
            condition += (
                " AND (observation_id IS NULL OR observation_id NOT IN ("
                + placeholders
                + "))"
            )
            params.extend(sorted(excluded_ids))
        row = self.select(
            "transitions",
            columns="id",
            condition=condition,
            params=tuple(params),
            limit=1,
        )
        return bool(row)

    @staticmethod
    def _row_to_memory(row) -> dict:
        return {
            "cell_key": row[0],
            "profile_ip": row[1],
            "regex_type": row[2],
            "antigen_value": row[3],
            "regex_hash": row[4],
            "regex": row[5],
            "matched_value": row[6],
            "context": _BaseTCellSQLiteDB._loads(row[7], {}),
            "created_at": row[8],
            "updated_at": row[9],
        }

    def upsert_memory(self, record: dict):
        self.execute(
            "INSERT OR REPLACE INTO memories ("
            "cell_key, profile_ip, regex_type, antigen_value, regex_hash, regex, "
            "matched_value, context_json, created_at, updated_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                record["cell_key"],
                record["profile_ip"],
                record["regex_type"],
                record["antigen_value"],
                record["regex_hash"],
                record["regex"],
                record["matched_value"],
                json.dumps(record.get("context", {})),
                record["created_at"],
                record["updated_at"],
            ),
        )

    def has_memory_for_regex(self, regex_hash: str) -> bool:
        row = self.select(
            "memories",
            columns="cell_key",
            condition="regex_hash = ?",
            params=(regex_hash,),
            limit=1,
        )
        return bool(row)

    def get_memories(self) -> list[dict]:
        rows = self.select("memories", order_by="updated_at DESC") or []
        return [self._row_to_memory(row) for row in rows]


class TCellStorage:
    def __init__(
        self,
        logger: Output,
        conf,
        output_dir: str,
        main_pid: int,
    ):
        self.logger = logger
        self.conf = conf
        self.output_dir = output_dir
        self.main_pid = main_pid
        self.store_dir = self._resolve_store_dir()
        self.db = TCellSQLiteDB(
            self.logger,
            str(Path(self.store_dir) / "t_cell.sqlite"),
            self.main_pid,
        )

    def _resolve_store_dir(self) -> str:
        raw_store_dir = self._read_store_dir()
        store_dir = self._normalize_store_dir(raw_store_dir)
        store_dir.mkdir(parents=True, exist_ok=True)
        return str(store_dir)

    def _normalize_store_dir(self, raw_store_dir: str) -> Path:
        store_dir = Path(raw_store_dir).expanduser()
        if store_dir.is_absolute():
            return store_dir

        relative_parts = list(store_dir.parts)
        while relative_parts and relative_parts[0] == ".":
            relative_parts = relative_parts[1:]
        if relative_parts and relative_parts[0] == "output":
            relative_parts = relative_parts[1:]
        if not relative_parts:
            relative_parts = ["t_cell"]
        return Path(self.output_dir).expanduser().joinpath(*relative_parts)

    def _read_store_dir(self) -> str:
        persistent_value = self._read_string_config(
            "t_cell_persistent_store_dir"
        )
        if persistent_value:
            return persistent_value

        value = self._read_string_config("t_cell_store_dir")
        if value:
            return value

        parser = ConfigParser()
        persistent_getter = getattr(parser, "t_cell_persistent_store_dir", None)
        if callable(persistent_getter):
            try:
                persistent_value = persistent_getter()
            except TypeError:
                persistent_value = None
            if isinstance(persistent_value, str) and persistent_value.strip():
                return persistent_value.strip()

        parser_getter = getattr(parser, "t_cell_store_dir", None)
        if callable(parser_getter):
            try:
                value = parser_getter()
            except TypeError:
                value = None
            if isinstance(value, str) and value.strip():
                return value.strip()
        return DEFAULT_T_CELL_STORE_DIR

    def _read_string_config(self, method_name: str) -> str | None:
        getter = getattr(self.conf, method_name, None)
        if not callable(getter):
            return None
        try:
            value = getter()
        except TypeError:
            return None
        if isinstance(value, str) and value.strip():
            return value.strip()
        return None

    def insert_observation(self, record: dict) -> int:
        return self.db.insert_observation(record)

    def get_observation(self, observation_id: int) -> dict | None:
        return self.db.get_observation(observation_id)

    def update_observation_matches(
        self, observation_id: int, matched_regexes: list[dict]
    ):
        self.db.update_observation_matches(observation_id, matched_regexes)

    def get_recent_observations(
        self,
        profile_ip: str,
        since_ts: float,
        until_ts: float | None = None,
        evidence_signal: str | None = None,
    ) -> list[dict]:
        return self.db.get_recent_observations(
            profile_ip,
            since_ts,
            until_ts=until_ts,
            evidence_signal=evidence_signal,
        )

    def prune_observations(self, created_before: float):
        self.db.prune_observations(created_before)

    def get_cell(self, cell_key: str) -> dict | None:
        return self.db.get_cell(cell_key)

    def get_all_cells(self) -> list[dict]:
        return self.db.get_all_cells()

    def get_cells_for_profile_states(
        self, profile_ip: str, states: list[int] | tuple[int, ...]
    ) -> list[dict]:
        return self.db.get_cells_for_profile_states(profile_ip, states)

    def upsert_cell(self, record: dict):
        self.db.upsert_cell(record)

    def insert_transition(self, record: dict) -> int:
        return self.db.insert_transition(record)

    def get_transitions(self, cell_key: str | None = None) -> list[dict]:
        return self.db.get_transitions(cell_key)

    def has_recent_regex_activity(
        self,
        profile_ip: str,
        regex_hash: str,
        since_ts: float,
        exclude_observation_ids: list[int] | tuple[int, ...] | set[int] | None = None,
        exclude_observation_id: int | None = None,
    ) -> bool:
        return self.db.has_recent_regex_activity(
            profile_ip,
            regex_hash,
            since_ts,
            exclude_observation_ids=exclude_observation_ids,
            exclude_observation_id=exclude_observation_id,
        )

    def upsert_memory(self, record: dict):
        self.db.upsert_memory(record)

    def has_memory_for_regex(self, regex_hash: str) -> bool:
        return self.db.has_memory_for_regex(regex_hash)

    def get_memories(self) -> list[dict]:
        return self.db.get_memories()

    def close(self):
        self.db.close()
