# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import hashlib
import os
from pathlib import Path
from time import time
from typing import Dict, Iterable, List

from pybloom_live import ScalableBloomFilter

from slips_files.common.abstracts.isqlite import ISQLite
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.printer import Printer
from slips_files.common.slips_utils import utils
from slips_files.core.output import Output

REGEX_TYPES = (
    "dns_domain",
    "uri",
    "filename",
    "tls_sni",
    "certificate_cn",
)
DEFAULT_REGEX_GENERATOR_STORE_DIR = "output/regex_generator"
DEFAULT_BENIGN_SEED_SAMPLES = {
    "dns_domain": [
        "google.com",
        "microsoft.com",
        "github.com",
        "cloudflare.com",
        "ubuntu.com",
    ],
    "uri": [
        "/",
        "/index.html",
        "/favicon.ico",
        "/api/v1/health",
        "/login",
    ],
    "filename": [
        "document.pdf",
        "invoice-2024.xlsx",
        "photo.jpg",
        "notes.txt",
        "setup.exe",
    ],
    "tls_sni": [
        "www.google.com",
        "api.github.com",
        "login.microsoftonline.com",
        "cdn.cloudflare.com",
        "packages.ubuntu.com",
    ],
    "certificate_cn": [
        "www.google.com",
        "github.com",
        "login.microsoftonline.com",
        "letsencrypt.org",
        "updates.ubuntu.com",
    ],
}
WHITELIST_COMPATIBLE_REGEX_TYPES = (
    "dns_domain",
    "tls_sni",
    "certificate_cn",
)


def _make_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class _BaseRegexSQLiteDB(ISQLite):
    name = "BaseRegexSQLiteDB"

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


class BenignCorpusSQLiteDB(_BaseRegexSQLiteDB):
    name = "BenignCorpusSQLiteDB"

    def init_tables(self):
        self.create_table(
            "benign_strings",
            "id INTEGER PRIMARY KEY, regex_type TEXT NOT NULL, value TEXT NOT NULL, "
            "value_hash TEXT NOT NULL UNIQUE, source TEXT NOT NULL, created_at REAL NOT NULL",
        )
        self.execute(
            "CREATE INDEX IF NOT EXISTS idx_benign_strings_type_hash "
            "ON benign_strings (regex_type, value_hash)"
        )

    def is_empty(self) -> bool:
        return self.get_count("benign_strings") == 0

    def insert_benign_string(
        self,
        regex_type: str,
        value: str,
        source: str,
        created_at: float | None = None,
    ) -> bool:
        created_at = created_at or time()
        value_hash = _make_sha256(f"{regex_type}\0{value}")
        cursor = self.execute(
            "INSERT OR IGNORE INTO benign_strings "
            "(regex_type, value, value_hash, source, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (regex_type, value, value_hash, source, created_at),
        )
        return bool(cursor and cursor.rowcount)

    def seed_strings(self, seed_samples: Dict[str, Iterable[str]], source: str):
        for regex_type, values in seed_samples.items():
            for value in values:
                self.insert_benign_string(regex_type, value, source)

    def get_examples(self, regex_type: str, limit: int = 5) -> List[str]:
        rows = self.select(
            "benign_strings",
            columns="value",
            condition="regex_type = ?",
            params=(regex_type,),
            order_by="id ASC",
        )
        rows = rows or []
        return [row[0] for row in rows[:limit]]

    def iter_values(self, regex_type: str):
        cursor = self.execute(
            "SELECT value FROM benign_strings WHERE regex_type = ? ORDER BY id ASC",
            (regex_type,),
        )
        if not cursor:
            return

        while True:
            row = self.fetchone(cursor)
            if row is None:
                break
            yield row[0]


class GeneratedRegexSQLiteDB(_BaseRegexSQLiteDB):
    name = "GeneratedRegexSQLiteDB"

    def init_tables(self):
        self.create_table(
            "generated_regexes",
            "id INTEGER PRIMARY KEY, regex_type TEXT NOT NULL, regex TEXT NOT NULL, "
            "regex_hash TEXT NOT NULL UNIQUE, status TEXT NOT NULL, "
            "rejection_reason TEXT, matched_benign_value TEXT, backend_alias TEXT, "
            "provider TEXT, model TEXT, temperature REAL, prompt_version TEXT, "
            "request_id TEXT, created_at REAL NOT NULL",
        )
        self.execute(
            "CREATE INDEX IF NOT EXISTS idx_generated_regexes_status_type_created "
            "ON generated_regexes (status, regex_type, created_at)"
        )
        self.execute(
            "CREATE INDEX IF NOT EXISTS idx_generated_regexes_type_created "
            "ON generated_regexes (regex_type, created_at)"
        )

    @staticmethod
    def _row_to_dict(row) -> dict:
        return {
            "id": row[0],
            "regex_type": row[1],
            "regex": row[2],
            "regex_hash": row[3],
            "status": row[4],
            "rejection_reason": row[5],
            "matched_benign_value": row[6],
            "backend_alias": row[7],
            "provider": row[8],
            "model": row[9],
            "temperature": row[10],
            "prompt_version": row[11],
            "request_id": row[12],
            "created_at": row[13],
        }

    def get_by_hash(self, regex_hash: str) -> dict | None:
        row = self.select(
            "generated_regexes",
            condition="regex_hash = ?",
            params=(regex_hash,),
            limit=1,
        )
        if not row:
            return None
        return self._row_to_dict(row)

    def insert_generated_regex(self, record: dict):
        self.execute(
            "INSERT OR IGNORE INTO generated_regexes "
            "(regex_type, regex, regex_hash, status, rejection_reason, "
            "matched_benign_value, backend_alias, provider, model, temperature, "
            "prompt_version, request_id, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                record["regex_type"],
                record["regex"],
                record["regex_hash"],
                record["status"],
                record.get("rejection_reason"),
                record.get("matched_benign_value"),
                record.get("backend_alias"),
                record.get("provider"),
                record.get("model"),
                record.get("temperature"),
                record.get("prompt_version"),
                record.get("request_id"),
                record.get("created_at") or time(),
            ),
        )

    def get_recent_history(self, regex_type: str, limit: int) -> List[dict]:
        rows = self.select(
            "generated_regexes",
            condition="regex_type = ?",
            params=(regex_type,),
            order_by="created_at DESC",
        )
        rows = rows or []
        return [self._row_to_dict(row) for row in rows[:limit]]

    def get_generated_regexes(
        self,
        regex_type: str | None = None,
        limit: int | None = None,
        status: str = "accepted",
    ) -> List[dict]:
        condition_parts = []
        params = []
        if status:
            condition_parts.append("status = ?")
            params.append(status)
        if regex_type:
            condition_parts.append("regex_type = ?")
            params.append(regex_type)

        condition = " AND ".join(condition_parts) if condition_parts else None
        rows = self.select(
            "generated_regexes",
            condition=condition,
            params=tuple(params),
            order_by="created_at DESC",
        )
        rows = rows or []
        if limit is not None:
            rows = rows[:limit]
        return [self._row_to_dict(row) for row in rows]

    def get_generated_regexes_count(
        self,
        regex_type: str | None = None,
        status: str = "accepted",
    ) -> int:
        condition_parts = []
        params = []
        if status:
            condition_parts.append("status = ?")
            params.append(status)
        if regex_type:
            condition_parts.append("regex_type = ?")
            params.append(regex_type)

        condition = " AND ".join(condition_parts) if condition_parts else None
        row = self.select(
            "generated_regexes",
            columns="COUNT(*)",
            condition=condition,
            params=tuple(params),
            limit=1,
        )
        return row[0] if row else 0

    def iter_regex_hashes(self, status: str | None = None):
        query = "SELECT regex_hash FROM generated_regexes"
        params = ()
        if status:
            query += " WHERE status = ?"
            params = (status,)
        query += " ORDER BY id ASC"
        cursor = self.execute(
            query,
            params,
        )
        if not cursor:
            return

        while True:
            row = self.fetchone(cursor)
            if row is None:
                break
            yield row[0]

    def prune_rejected_regexes(self, max_records: int):
        if max_records <= 0:
            return

        count = self.get_generated_regexes_count(status="rejected")
        excess = count - max_records
        if excess <= 0:
            return

        self.execute(
            "DELETE FROM generated_regexes WHERE id IN ("
            "SELECT id FROM generated_regexes "
            "WHERE status = 'rejected' "
            "ORDER BY created_at ASC, id ASC LIMIT ?"
            ")",
            (excess,),
        )


class RegexGeneratorStorage:
    def __init__(
        self,
        logger: Output,
        conf,
        output_dir: str,
        main_pid: int,
        db=None,
    ):
        self.logger = logger
        self.conf = conf
        self.output_dir = output_dir
        self.main_pid = main_pid
        self.db = db
        self.store_dir = self._resolve_store_dir()
        self.store_rejected_regexes = self._read_store_rejected_regexes()
        self.max_stored_rejected_regexes = (
            self._read_max_stored_rejected_regexes()
        )
        self.seed_benign_samples = self._read_seed_benign_samples()
        self.enable_local_whitelist = self._read_enable_local_whitelist()
        self.local_whitelist_path = self._read_local_whitelist_path()
        self.tranco_top_benign_limit = self._read_tranco_top_benign_limit()
        self.benign_db = BenignCorpusSQLiteDB(
            self.logger,
            str(Path(self.store_dir) / "benign_corpus.sqlite"),
            self.main_pid,
        )
        self.generated_db = GeneratedRegexSQLiteDB(
            self.logger,
            str(Path(self.store_dir) / "generated_regexes.sqlite"),
            self.main_pid,
        )
        if self.seed_benign_samples and self.benign_db.is_empty():
            self.seed_default_benign_samples()
        self._import_local_whitelist_into_benign_corpus()
        self._import_tranco_top_domains_into_benign_corpus()
        self.bloom_filters = self._build_bloom_filters()
        self.generated_regex_filter = self._build_generated_regex_filter()
        self.rejected_regex_filter = self._build_rejected_regex_filter()

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
            relative_parts = ["regex_generator"]

        return Path(self.output_dir).expanduser().joinpath(*relative_parts)

    def _read_store_dir(self) -> str:
        persistent_value = self._read_string_config(
            "regex_generator_persistent_store_dir"
        )
        if persistent_value:
            return persistent_value

        value = self._read_string_config("regex_generator_store_dir")
        if value:
            return value

        parser = ConfigParser()
        persistent_getter = getattr(
            parser, "regex_generator_persistent_store_dir", None
        )
        if callable(persistent_getter):
            try:
                persistent_value = persistent_getter()
            except TypeError:
                persistent_value = None
            if isinstance(persistent_value, str) and persistent_value.strip():
                return persistent_value.strip()

        parser_getter = getattr(parser, "regex_generator_store_dir", None)
        if callable(parser_getter):
            try:
                value = parser_getter()
            except TypeError:
                value = None
            if isinstance(value, str) and value.strip():
                return value.strip()
        return DEFAULT_REGEX_GENERATOR_STORE_DIR

    def _read_seed_benign_samples(self) -> bool:
        value = self._read_bool_config("regex_generator_seed_benign_samples")
        if value is not None:
            return value

        parser = ConfigParser()
        parser_getter = getattr(parser, "regex_generator_seed_benign_samples", None)
        if callable(parser_getter):
            try:
                value = parser_getter()
            except TypeError:
                value = None
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                return value.strip().lower() in ("true", "1", "yes", "on")
        return True

    def _read_store_rejected_regexes(self) -> bool:
        value = self._read_bool_config("regex_generator_store_rejected_regexes")
        if value is not None:
            return value

        parser = ConfigParser()
        parser_getter = getattr(
            parser, "regex_generator_store_rejected_regexes", None
        )
        if callable(parser_getter):
            try:
                value = parser_getter()
            except TypeError:
                value = None
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                return value.strip().lower() in ("true", "1", "yes", "on")
        return False

    def _read_max_stored_rejected_regexes(self) -> int:
        value = self._read_int_config("regex_generator_max_stored_rejected_regexes")
        if value is not None:
            return max(0, value)

        parser = ConfigParser()
        parser_getter = getattr(
            parser, "regex_generator_max_stored_rejected_regexes", None
        )
        if callable(parser_getter):
            try:
                value = parser_getter()
            except TypeError:
                value = None
            if isinstance(value, int):
                return max(0, value)
            if isinstance(value, str):
                try:
                    return max(0, int(value.strip()))
                except ValueError:
                    pass
        return 10000

    def _read_enable_local_whitelist(self) -> bool:
        value = self._read_bool_config("enable_local_whitelist")
        if value is not None:
            return value

        parser = ConfigParser()
        parser_getter = getattr(parser, "enable_local_whitelist", None)
        if callable(parser_getter):
            try:
                value = parser_getter()
            except TypeError:
                value = None
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                return value.strip().lower() in ("true", "1", "yes", "on")
        return True

    def _read_local_whitelist_path(self) -> str:
        value = self._read_string_config("local_whitelist_path")
        if value:
            return value

        parser = ConfigParser()
        parser_getter = getattr(parser, "local_whitelist_path", None)
        if callable(parser_getter):
            try:
                value = parser_getter()
            except TypeError:
                value = None
            if isinstance(value, str) and value.strip():
                return value.strip()
        return "config/whitelist.conf"

    def _read_tranco_top_benign_limit(self) -> int:
        value = self._read_int_config("tranco_top_benign_limit")
        if value is not None:
            return max(0, value)

        parser = ConfigParser()
        parser_getter = getattr(parser, "tranco_top_benign_limit", None)
        if callable(parser_getter):
            try:
                value = parser_getter()
            except TypeError:
                value = None
            if isinstance(value, int):
                return max(0, value)
            if isinstance(value, str):
                try:
                    return max(0, int(value.strip()))
                except ValueError:
                    pass
        return 1000

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

    def _read_bool_config(self, method_name: str) -> bool | None:
        getter = getattr(self.conf, method_name, None)
        if not callable(getter):
            return None
        try:
            value = getter()
        except TypeError:
            return None
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.strip().lower() in ("true", "1", "yes", "on")
        return None

    def _read_int_config(self, method_name: str) -> int | None:
        getter = getattr(self.conf, method_name, None)
        if not callable(getter):
            return None
        try:
            value = getter()
        except TypeError:
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    def seed_default_benign_samples(self):
        self.benign_db.seed_strings(
            DEFAULT_BENIGN_SEED_SAMPLES,
            source="seed_v1",
        )

    def _import_local_whitelist_into_benign_corpus(self):
        if not self.enable_local_whitelist:
            return

        whitelist_path = Path(self.local_whitelist_path).expanduser()
        if not whitelist_path.is_absolute():
            whitelist_path = Path(os.getcwd()) / whitelist_path
        if not whitelist_path.exists():
            return

        for domain in self._iter_whitelist_domains(whitelist_path):
            hostname = utils.extract_hostname(domain)
            values = {domain}
            if hostname:
                values.add(hostname)

            for regex_type in WHITELIST_COMPATIBLE_REGEX_TYPES:
                for value in values:
                    self.benign_db.insert_benign_string(
                        regex_type,
                        value,
                        source=f"local_whitelist:{whitelist_path}",
                    )

    def _import_tranco_top_domains_into_benign_corpus(self):
        if self.db is None or self.tranco_top_benign_limit <= 0:
            return

        getter = getattr(self.db, "get_tranco_top_domains", None)
        if not callable(getter):
            return

        try:
            domains = getter(limit=self.tranco_top_benign_limit) or []
        except TypeError:
            domains = getter() or []

        for domain in domains[: self.tranco_top_benign_limit]:
            domain = str(domain or "").strip().lower()
            if not utils.is_valid_domain(domain):
                continue

            values = {domain}
            hostname = utils.extract_hostname(domain)
            if hostname:
                values.add(hostname)

            for regex_type in WHITELIST_COMPATIBLE_REGEX_TYPES:
                for value in values:
                    self.benign_db.insert_benign_string(
                        regex_type,
                        value,
                        source="tranco_top_1000",
                    )

    @staticmethod
    def _iter_whitelist_domains(whitelist_path: Path):
        with open(whitelist_path, encoding="utf-8") as whitelist:
            for raw_line in whitelist:
                if (
                    not raw_line
                    or raw_line.startswith(";")
                    or raw_line.startswith("#")
                    or raw_line.startswith('"IoCType"')
                ):
                    continue

                line = raw_line.replace("\n", "").replace(" ", "")
                parts = line.split(",")
                if len(parts) < 4:
                    continue
                if parts[0].lower() != "domain":
                    continue

                domain = parts[1].strip().lower()
                if not utils.is_valid_domain(domain):
                    continue
                yield domain

    def _build_bloom_filters(self) -> dict:
        bloom_filters = {}
        for regex_type in REGEX_TYPES:
            bloom = ScalableBloomFilter(
                mode=ScalableBloomFilter.SMALL_SET_GROWTH,
                error_rate=0.001,
            )
            for value in self.benign_db.iter_values(regex_type):
                bloom.add(value)
            bloom_filters[regex_type] = bloom
        return bloom_filters

    def _build_generated_regex_filter(self):
        bloom = ScalableBloomFilter(
            mode=ScalableBloomFilter.SMALL_SET_GROWTH,
            error_rate=0.001,
        )
        for regex_hash in self.generated_db.iter_regex_hashes():
            bloom.add(regex_hash)
        return bloom

    def _build_rejected_regex_filter(self):
        return ScalableBloomFilter(
            mode=ScalableBloomFilter.SMALL_SET_GROWTH,
            error_rate=0.001,
        )

    def get_benign_examples(self, regex_type: str, limit: int = 5) -> List[str]:
        return self.benign_db.get_examples(regex_type, limit)

    def iter_benign_strings(self, regex_type: str):
        yield from self.benign_db.iter_values(regex_type)

    def add_benign_strings(
        self,
        regex_type: str,
        values: Iterable[str],
        source: str,
    ) -> int:
        inserted = 0
        bloom = self.bloom_filters.get(regex_type)
        for value in values:
            normalized = str(value or "").strip()
            if not normalized:
                continue
            added = self.benign_db.insert_benign_string(
                regex_type,
                normalized,
                source=source,
            )
            if added:
                inserted += 1
                if bloom is not None:
                    bloom.add(normalized)
        return inserted

    def get_recent_history(self, regex_type: str, limit: int) -> List[dict]:
        return self.generated_db.get_recent_history(regex_type, limit)

    def get_generated_regexes(
        self,
        regex_type: str | None = None,
        limit: int | None = None,
        status: str = "accepted",
    ) -> List[dict]:
        return self.generated_db.get_generated_regexes(
            regex_type=regex_type,
            limit=limit,
            status=status,
        )

    def get_generated_regexes_count(
        self,
        regex_type: str | None = None,
        status: str = "accepted",
    ) -> int:
        return self.generated_db.get_generated_regexes_count(
            regex_type=regex_type,
            status=status,
        )

    def get_existing_generated_regex(self, regex_hash: str) -> dict | None:
        return self.generated_db.get_by_hash(regex_hash)

    def might_have_generated_regex(self, regex_hash: str) -> bool:
        return (
            regex_hash in self.generated_regex_filter
            or regex_hash in self.rejected_regex_filter
        )

    def was_rejected_in_current_run(self, regex_hash: str) -> bool:
        return regex_hash in self.rejected_regex_filter

    def store_generated_regex(self, record: dict):
        regex_hash = record["regex_hash"]
        status = record.get("status", "")

        if status == "rejected":
            self.rejected_regex_filter.add(regex_hash)
            if not self.store_rejected_regexes:
                return

        self.generated_db.insert_generated_regex(record)
        self.generated_regex_filter.add(regex_hash)
        if status == "rejected" and self.max_stored_rejected_regexes > 0:
            self.generated_db.prune_rejected_regexes(
                self.max_stored_rejected_regexes
            )
            self.generated_regex_filter = self._build_generated_regex_filter()

    def close(self):
        self.benign_db.close()
        self.generated_db.close()
