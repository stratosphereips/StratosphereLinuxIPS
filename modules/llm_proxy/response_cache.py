# SPDX-License-Identifier: GPL-2.0-only
"""Bounded persistent storage for repeatable LLM responses."""

import hashlib
import json
import sqlite3
import time
from contextlib import closing
from pathlib import Path
from typing import Any

from modules.llm_proxy.llm_backend_config import LLMBackendConfig


MAX_CACHE_BYTES = 256 * 1024 * 1024
MAX_CACHE_ROWS = 50000


def response_cache_path(permanent_dir: str | Path) -> Path:
    """Locate the shared response cache below the configured permanent directory.

    Parameters:
        permanent_dir: Persistent Slips directory.

    Returns:
        Path to the SQLite response cache.
    """
    return Path(permanent_dir) / "databases" / "llm_responses.sqlite"


class LLMResponseCache:
    """Store successful responses without retaining prompts or request IDs."""

    def __init__(self, path: Path, create: bool = True) -> None:
        """Open or initialize the cache file.

        Parameters:
            path: SQLite database path.
            create: Whether to create missing directories and tables.
        """
        self.path = path
        if create:
            path.parent.mkdir(parents=True, exist_ok=True)
            with closing(self._connect()) as db, db:
                db.execute("PRAGMA journal_mode=WAL")
                db.execute(
                    "CREATE TABLE IF NOT EXISTS responses ("
                    "cache_key TEXT PRIMARY KEY, web_digest TEXT, "
                    "response_json TEXT NOT NULL, size_bytes INTEGER NOT NULL, "
                    "created_at REAL NOT NULL)"
                )
                db.execute(
                    "CREATE INDEX IF NOT EXISTS responses_web_digest "
                    "ON responses(web_digest)"
                )
                db.execute(
                    "CREATE INDEX IF NOT EXISTS responses_created_at "
                    "ON responses(created_at)"
                )
            path.chmod(0o600)

    def _connect(self) -> sqlite3.Connection:
        """Connect with a short wait for the other LLM worker.

        Returns:
            SQLite connection.
        """
        db = sqlite3.connect(self.path, timeout=2)
        db.execute("PRAGMA busy_timeout=2000")
        return db

    @staticmethod
    def key(request: dict[str, Any], backend: LLMBackendConfig) -> str:
        """Hash the effective model, generation settings, and normalized prompt.

        Parameters:
            request: Prepared LLM request.
            backend: Selected backend configuration.

        Returns:
            Stable SHA-256 cache key.
        """
        material = {
            "backend": request["backend"],
            "provider": backend.provider,
            "base_url": backend.base_url,
            "model": request.get("model") or backend.model,
            "messages": request["messages"],
            "temperature": request.get("temperature"),
            "max_tokens": request.get("max_tokens"),
        }
        payload = json.dumps(
            material, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def get(self, cache_key: str) -> dict[str, Any] | None:
        """Read a cached successful response.

        Parameters:
            cache_key: Hash of the effective request.

        Returns:
            Saved response fields or None.
        """
        if not self.path.is_file():
            return None
        with closing(self._connect()) as db, db:
            row = db.execute(
                "SELECT response_json FROM responses WHERE cache_key=?",
                (cache_key,),
            ).fetchone()
        return json.loads(row[0]) if row else None

    def get_web(self, digest: str) -> dict[str, Any] | None:
        """Read a saved web explanation after its Redis result expires.

        Parameters:
            digest: Browser explanation identifier.

        Returns:
            Saved explanation fields or None.
        """
        if not self.path.is_file():
            return None
        with closing(self._connect()) as db, db:
            row = db.execute(
                "SELECT response_json FROM responses WHERE web_digest=? "
                "ORDER BY created_at DESC LIMIT 1",
                (digest,),
            ).fetchone()
        return json.loads(row[0]) if row else None

    def put(
        self,
        cache_key: str,
        response: dict[str, Any],
        web_digest: str = "",
    ) -> None:
        """Save a successful response and evict oldest entries at capacity.

        Parameters:
            cache_key: Hash of the effective request.
            response: Provider, model, and generated text.
            web_digest: Browser identifier for on-demand explanations.
        """
        if not response.get("text"):
            return
        value = json.dumps(response, ensure_ascii=False, separators=(",", ":"))
        size_bytes = (
            len(value.encode("utf-8")) + len(cache_key) + len(web_digest)
        )
        if size_bytes > MAX_CACHE_BYTES:
            return
        with closing(self._connect()) as db, db:
            db.execute(
                "INSERT OR REPLACE INTO responses "
                "(cache_key, web_digest, response_json, size_bytes, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (
                    cache_key,
                    web_digest or None,
                    value,
                    size_bytes,
                    time.time(),
                ),
            )
            count, used = db.execute(
                "SELECT COUNT(*), COALESCE(SUM(size_bytes), 0) FROM responses"
            ).fetchone()
            while count > MAX_CACHE_ROWS or used > MAX_CACHE_BYTES:
                old = db.execute(
                    "SELECT cache_key, size_bytes FROM responses "
                    "ORDER BY created_at LIMIT 1"
                ).fetchone()
                if old is None:
                    break
                db.execute(
                    "DELETE FROM responses WHERE cache_key=?", (old[0],)
                )
                count -= 1
                used -= old[1]
