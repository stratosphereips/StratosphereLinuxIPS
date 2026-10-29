"""Bounded network catch-up without replaying historical detections as new alerts."""

import hashlib
import ipaddress
import json
import math
import secrets
import sqlite3
import time
from dataclasses import dataclass, fields
from contextlib import contextmanager, closing
from pathlib import Path
from typing import Any, Callable, Iterator


def network_scope(state: dict[str, Any]) -> str:
    """Return a connected router-and-subnet scope from state, or empty when ambiguous."""
    from slips_files.common.mac import normalize_mac, classify_mac

    mac = normalize_mac(state.get("gateway_mac"))
    if not state.get("connected") or classify_mac(mac) not in {
        "locally_administered",
        "universally_administered",
    }:
        return ""
    try:
        subnet = str(
            ipaddress.ip_network(state["local_network"], strict=False)
        )
    except (KeyError, TypeError, ValueError):
        return ""
    return f"gateway:{mac}|{subnet}"


@dataclass(frozen=True)
class CatchupSettings:
    """Resource and observation-age limits for directed peer catch-up."""

    enabled: bool = True
    fresh_minutes: int = 15
    recent_hours: int = 24
    history_days: int = 7
    max_peers: int = 3
    parallel_pages: int = 2
    page_records: int = 50
    page_bytes: int = 65536
    record_bytes: int = 8192
    transfer_kib_per_second: int = 64
    initial_transfer_mib: int = 2
    max_records: int = 10000
    max_store_mib: int = 64
    reconnect_cooldown_seconds: int = 60

    @classmethod
    def from_config(cls, config: Any) -> "CatchupSettings":
        """Read bounded settings; config is the catch_up mapping; return settings."""
        config = config if isinstance(config, dict) else {}
        values = {}
        limits = {
            "max_peers": 16,
            "parallel_pages": 4,
            "page_records": 50,
            "page_bytes": 65536,
            "record_bytes": 8192,
            "history_days": 30,
            "max_records": 100000,
            "max_store_mib": 512,
        }
        for field in fields(cls):
            value = config.get(field.name, field.default)
            if field.name == "enabled":
                values[field.name] = value is True
                continue
            try:
                values[field.name] = min(
                    limits.get(field.name, 86400), max(1, int(value))
                )
            except (ValueError, TypeError, OverflowError):
                values[field.name] = field.default
        values["page_bytes"] = max(32768, values["page_bytes"])
        return cls(**values)


class CatchupStore:
    """Persist incident revisions and resumable transfers outside run databases."""

    def __init__(self, path: Path, settings: CatchupSettings) -> None:
        """Create indexed state; path is persistent storage and settings sets limits."""
        self.path, self.settings = path, settings
        path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA auto_vacuum=INCREMENTAL")
            conn.executescript(
                "CREATE TABLE IF NOT EXISTS incidents (seq INTEGER PRIMARY KEY AUTOINCREMENT,"
                "network TEXT NOT NULL,author TEXT NOT NULL,incident TEXT NOT NULL,revision INTEGER NOT NULL,"
                "state TEXT NOT NULL,first_seen REAL NOT NULL,last_seen REAL NOT NULL,expires REAL NOT NULL,"
                "threat INTEGER NOT NULL,confidence REAL NOT NULL,received REAL NOT NULL,via TEXT NOT NULL,"
                "data TEXT NOT NULL,seal TEXT NOT NULL,UNIQUE(network,author,incident));"
                "CREATE INDEX IF NOT EXISTS catchup_network_seq ON incidents(network,seq);"
                "CREATE INDEX IF NOT EXISTS catchup_age ON incidents(last_seen);"
                "CREATE TABLE IF NOT EXISTS transfers (network TEXT NOT NULL,peer TEXT NOT NULL,"
                "updated REAL NOT NULL,data TEXT NOT NULL,PRIMARY KEY(network,peer));"
                "CREATE TABLE IF NOT EXISTS coverage (network TEXT PRIMARY KEY,started REAL NOT NULL);"
                "CREATE TABLE IF NOT EXISTS journal (key TEXT PRIMARY KEY,value TEXT NOT NULL);"
                "CREATE TABLE IF NOT EXISTS snapshots (token TEXT PRIMARY KEY,network TEXT NOT NULL,created REAL NOT NULL,data TEXT NOT NULL);"
                "CREATE TABLE IF NOT EXISTS actions (network TEXT NOT NULL,target TEXT NOT NULL,owner TEXT NOT NULL,expires REAL NOT NULL,state TEXT NOT NULL,PRIMARY KEY(network,target));"
            )
            columns = {
                row[1] for row in conn.execute("PRAGMA table_xinfo(incidents)")
            }
            if "target" not in columns:
                conn.execute(
                    "ALTER TABLE incidents ADD COLUMN target TEXT GENERATED ALWAYS AS (json_extract(data,'$.target')) VIRTUAL"
                )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS catchup_target ON incidents(network,target,last_seen)"
            )

            conn.execute(
                "INSERT OR IGNORE INTO journal VALUES ('generation',?)",
                (secrets.token_hex(16),),
            )

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        """Yield a short-lived connection; commit on success and always close it."""
        conn = sqlite3.connect(self.path, timeout=0.2)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def save(
        self, record: dict[str, Any], seal: str = "", via: str = ""
    ) -> bool:
        """Validate and save a newer record, signed seal and delivery peer; return acceptance."""
        now = time.time()
        try:
            encoded = json.dumps(
                record, separators=(",", ":"), allow_nan=False
            )
            if (
                len(encoded.encode()) > self.settings.record_bytes
                or len(seal) > 16384
            ):
                return False
            network, author, incident = (
                record[key] for key in ("network", "author", "incident")
            )
            if not all(
                isinstance(value, str) and 0 < len(value) <= 256
                for value in (network, author, incident)
            ):
                return False
            first, last, expires = (
                float(record[key])
                for key in ("first_seen", "last_seen", "expires")
            )
            revision = int(record["revision"])
            confidence = float(record["confidence"])
            threat = int(record["threat"])
            target = ipaddress.ip_address(record["target"])
            if (
                target.is_multicast
                or target.is_unspecified
                or target.is_loopback
                or str(target) == "255.255.255.255"
                or record["state"] not in {"observed", "withdrawn"}
                or not all(
                    math.isfinite(value)
                    for value in (first, last, expires, confidence)
                )
                or not 0 <= first <= last <= now + 120
                or last < now - self.settings.history_days * 86400
                or not 0 <= confidence <= 1
                or not 0 <= threat <= 4
                or not 0 < revision < 2**63
                or expires > last + self.settings.fresh_minutes * 60 + 0.001
                or expires < 0
            ):
                return False
        except (KeyError, TypeError, ValueError, OverflowError):
            return False
        with self.connect() as conn:
            prior = conn.execute(
                "SELECT revision FROM incidents WHERE network=? AND author=? AND incident=?",
                (network, author, incident),
            ).fetchone()
            if prior and prior[0] >= revision:
                return False
            if not prior:
                count = conn.execute(
                    "SELECT COUNT(*) FROM incidents"
                ).fetchone()[0]
                author_count = conn.execute(
                    "SELECT COUNT(*) FROM incidents WHERE author=?", (author,)
                ).fetchone()[0]
                allocated = (
                    conn.execute("PRAGMA page_count").fetchone()[0]
                    * conn.execute("PRAGMA page_size").fetchone()[0]
                )
                if (
                    count >= self.settings.max_records
                    or author_count >= max(100, self.settings.max_records // 3)
                    or allocated >= self.settings.max_store_mib * 1048576
                ):
                    return False
            conn.execute(
                "INSERT OR IGNORE INTO coverage VALUES (?,?)", (network, now)
            )
            conn.execute(
                "INSERT OR REPLACE INTO incidents(network,author,incident,revision,state,first_seen,last_seen,expires,threat,confidence,received,via,data,seal) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    network,
                    author,
                    incident,
                    revision,
                    record["state"],
                    first,
                    last,
                    expires,
                    threat,
                    confidence,
                    now,
                    via,
                    encoded,
                    seal,
                ),
            )
        return True

    def observe(
        self, evidence: dict[str, Any], network: str, author: str
    ) -> None:
        """Summarize first-hand evidence from network and author without importing peer reports."""
        if evidence.get("peer_report") or not network or not author:
            return
        kind = str(evidence.get("evidence_type", ""))
        threat = {
            "info": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }.get(str(evidence.get("threat_level", "")).lower(), 0)
        if not threat or kind in {
            "P2P_REPORT",
            "MALICIOUS_IP_FROM_P2P_NETWORK",
        }:
            return
        try:
            from slips_files.common.slips_utils import utils

            observed = float(
                utils.convert_ts_format(evidence["timestamp"], "unixtimestamp")
            )
            target = str(evidence["attacker"]["value"])
        except (KeyError, TypeError, ValueError):
            return
        key = json.dumps(
            [
                network,
                target,
                kind,
                evidence.get("proto"),
                evidence.get("dst_port"),
                evidence.get("target_mac", ""),
            ],
            sort_keys=True,
        )
        incident = hashlib.sha256(key.encode()).hexdigest()
        with self.connect() as conn:
            row = conn.execute(
                "SELECT data,revision FROM incidents WHERE network=? AND author=? AND incident=?",
                (network, author, incident),
            ).fetchone()
        old = json.loads(row[0]) if row else {}
        if observed <= old.get("last_seen", 0):
            return
        record = {
            "network": network,
            "author": author,
            "incident": incident,
            "revision": int(row[1]) + 1 if row else 1,
            "state": "observed",
            "target": target,
            "first_seen": old.get("first_seen", observed),
            "last_seen": observed,
            "expires": observed + self.settings.fresh_minutes * 60,
            "threat": threat,
            "confidence": evidence.get("confidence", 0),
            "evidence_type": kind,
            "description": str(evidence.get("description", ""))[:1000],
            "module": evidence.get("source_module", ""),
            "proto": evidence.get("proto"),
            "dst_port": evidence.get("dst_port"),
            "victim": evidence.get("victim") or {},
            "evidence_id": evidence.get("id", ""),
            "count": old.get("count", 0) + 1,
            "method": evidence.get("method", "HEURISTIC"),
            "target_mac": evidence.get("target_mac", ""),
        }
        self.save(record)

    def withdraw(self, author: str, evidence_ids: set[str]) -> None:
        """Withdraw own summaries supported by rejected evidence IDs; never withdraw other authors."""
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT data FROM incidents WHERE author=? AND state='observed'",
                (author,),
            ).fetchall()
        for row in rows:
            record = json.loads(row[0])
            if record.get("evidence_id") in evidence_ids:
                record.update(
                    state="withdrawn",
                    revision=record["revision"] + 1,
                    expires=time.time(),
                )
                record["expires"] = min(
                    record["expires"],
                    record["last_seen"] + self.settings.fresh_minutes * 60,
                )
                self.save(record)

    def transfer(
        self, network: str, peer: str, update: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Read a peer's transfer or persist update; return its state in this network."""
        with self.connect() as conn:
            if update is not None:
                conn.execute(
                    "INSERT OR REPLACE INTO transfers VALUES (?,?,?,?)",
                    (network, peer, time.time(), json.dumps(update)),
                )
            row = conn.execute(
                "SELECT data FROM transfers WHERE network=? AND peer=?",
                (network, peer),
            ).fetchone()
        return json.loads(row[0]) if row else {}

    def page(
        self, request: dict[str, Any], author: str, recipient: str = ""
    ) -> dict[str, Any]:
        """Return a bounded priority page from a stable request snapshot for recipient."""
        now = time.time()
        network, lane = request["network"], request.get("lane", "fresh")
        after = max(0, int(request.get("after", 0)))
        since = max(
            now - self.settings.history_days * 86400,
            float(request.get("since", now)),
        )
        if not math.isfinite(since) or since > now + 120:
            raise ValueError("invalid history start")
        token = recipient + ":" + request["nonce"] + ":" + lane
        with self.connect() as conn:
            generation = conn.execute(
                "SELECT value FROM journal WHERE key='generation'"
            ).fetchone()[0]
            prior = conn.execute(
                "SELECT data FROM snapshots WHERE token=? AND network=? AND created>?",
                (token, network, now - 120),
            ).fetchone()
            reset = not prior and after > 0
            if prior:
                snapshot = json.loads(prior[0])
            else:
                low = (
                    max(0, int(request.get("since_seq", 0)))
                    if lane == "history"
                    and request.get("generation") == generation
                    else 0
                )
                high = conn.execute(
                    "SELECT COALESCE(MAX(seq),0) FROM incidents WHERE network=?",
                    (network,),
                ).fetchone()[0]
                condition = (
                    " AND (state='withdrawn' OR (expires>? AND last_seen>=?))"
                    if lane == "fresh"
                    else ""
                )
                args = [network, low, high, since]
                if lane == "fresh":
                    args.extend([now, now - self.settings.fresh_minutes * 60])
                ids = [
                    row[0]
                    for row in conn.execute(
                        "SELECT seq FROM incidents WHERE network=? AND seq>? AND seq<=? AND last_seen>=?"
                        + condition
                        + " ORDER BY (state='withdrawn') DESC,(last_seen>=?) DESC,threat DESC,last_seen DESC,seq DESC LIMIT ?",
                        [
                            *args,
                            now - self.settings.recent_hours * 3600,
                            self.settings.max_records,
                        ],
                    )
                ]
                snapshot = {"ids": ids, "upto": high}
                conn.execute(
                    "DELETE FROM snapshots WHERE created<?", (now - 120,)
                )
                if (
                    conn.execute("SELECT COUNT(*) FROM snapshots").fetchone()[
                        0
                    ]
                    >= 64
                ):
                    raise ValueError("snapshot capacity reached")
                conn.execute(
                    "INSERT OR REPLACE INTO snapshots VALUES (?,?,?,?)",
                    (token, network, now, json.dumps(snapshot)),
                )
                after = 0
            coverage = conn.execute(
                "SELECT started FROM coverage WHERE network=?", (network,)
            ).fetchone()
            items, cursor, used, missing = [], after, 0, 0
            for index, seq in enumerate(
                snapshot["ids"][after : after + self.settings.page_records],
                after,
            ):
                row = conn.execute(
                    "SELECT data,seal,author FROM incidents WHERE seq=?",
                    (seq,),
                ).fetchone()
                if not row or (row["author"] != author and not row["seal"]):
                    cursor = index + 1
                    missing += 1
                    continue
                item = {"record": json.loads(row["data"]), "seal": row["seal"]}
                cost = len(json.dumps(item).encode()) * 3 + 1024
                if items and used + cost > self.settings.page_bytes - 2048:
                    break
                items.append(item)
                used += cost
                cursor = index + 1
        return {
            "message_type": "catchup_page",
            "network": network,
            "nonce": request["nonce"],
            "lane": lane,
            "after": int(request.get("after", 0)),
            "cursor": cursor,
            "upto": snapshot["upto"],
            "more": cursor < len(snapshot["ids"]),
            "total": len(snapshot["ids"]),
            "reset": reset,
            "missing": missing,
            "generation": generation,
            "coverage_start": float(coverage[0]) if coverage else now,
            "requested_since": since,
            "items": items,
        }

    def prune(self) -> None:
        """Expire records beyond the entire accepted replay horizon and bound transfer state."""
        with self.connect() as conn:
            conn.execute(
                "DELETE FROM incidents WHERE seq IN (SELECT seq FROM incidents WHERE last_seen<? LIMIT 1000)",
                (time.time() - self.settings.history_days * 86400 - 120,),
            )
            conn.execute(
                "DELETE FROM transfers WHERE rowid NOT IN (SELECT rowid FROM transfers ORDER BY updated DESC LIMIT 128)"
            )
            conn.execute(
                "DELETE FROM coverage WHERE network NOT IN (SELECT DISTINCT network FROM incidents) AND network NOT IN (SELECT network FROM transfers)"
            )
            conn.execute(
                "DELETE FROM snapshots WHERE created<?", (time.time() - 120,)
            )
            conn.execute("PRAGMA incremental_vacuum(32)")
            conn.execute(
                "DELETE FROM actions WHERE expires<?", (time.time() - 86400,)
            )
            conn.execute(
                "DELETE FROM actions WHERE expires<? AND rowid NOT IN (SELECT rowid FROM actions ORDER BY expires DESC LIMIT 256)",
                (time.time(),),
            )

    def fresh_support(
        self, network: str, target: str, authors: list[str] | None = None
    ) -> list[dict[str, Any]]:
        """Return bounded unexpired high-confidence reports for target on network, at most five minutes old."""
        now = time.time()
        if authors == []:
            return []
        with self.connect() as conn:
            source_clause = (
                " AND author IN (" + ",".join("?" for _ in authors[:64]) + ")"
                if authors is not None
                else ""
            )
            rows = conn.execute(
                "SELECT data FROM incidents WHERE network=? AND last_seen>=? AND target=? AND expires>? AND state='observed' AND confidence>=0.9 AND threat>=3"
                + source_clause
                + " ORDER BY last_seen DESC LIMIT 100",
                [
                    network,
                    now - 300,
                    target,
                    now,
                    *(authors[:64] if authors is not None else []),
                ],
            ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def action(
        self,
        network: str,
        target: str,
        owner: str = "",
        expires: float = 0,
        state: str = "",
    ) -> dict[str, Any]:
        """Read an owned protection decision or store owner, expiry and state for target on network."""
        with self.connect() as conn:
            if state:
                conn.execute(
                    "INSERT OR REPLACE INTO actions VALUES (?,?,?,?,?)",
                    (network, target, owner, expires, state),
                )
            row = conn.execute(
                "SELECT owner,expires,state FROM actions WHERE network=? AND target=?",
                (network, target),
            ).fetchone()
        return dict(row) if row else {}

    def active_actions(self, network: str) -> list[dict[str, Any]]:
        """Return at most 32 current owned protection requests on network."""
        with self.connect() as conn:
            return [
                dict(row)
                for row in conn.execute(
                    "SELECT target,owner,expires FROM actions WHERE network=? AND state='requested' AND expires>? LIMIT 32",
                    (network, time.time()),
                )
            ]

    @staticmethod
    def view(path: Path, network: str, limit: int = 100) -> dict[str, Any]:
        """Read bounded web data from path and network; return transfers and incident summaries."""
        if not path.exists():
            return {"transfers": [], "incidents": [], "total": 0}
        with closing(
            sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=0.2)
        ) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT data,via,received,expires,state FROM incidents WHERE network=? ORDER BY (state='withdrawn') DESC,(expires>?) DESC,threat DESC,last_seen DESC LIMIT ?",
                (network, time.time(), limit),
            ).fetchall()
            transfers = conn.execute(
                "SELECT peer,updated,data FROM transfers WHERE network=? ORDER BY updated DESC LIMIT 16",
                (network,),
            ).fetchall()
            total = conn.execute(
                "SELECT COUNT(*) FROM incidents WHERE network=?", (network,)
            ).fetchone()[0]
            actions = {
                row["target"]: dict(row)
                for row in conn.execute(
                    "SELECT target,expires,state FROM actions WHERE network=? LIMIT 10000",
                    (network,),
                )
            }
        return {
            "transfers": [
                {
                    "peer": row["peer"],
                    "updated": row["updated"],
                    **json.loads(row["data"]),
                }
                for row in transfers
            ],
            "incidents": [
                {
                    **json.loads(row["data"]),
                    "via": row["via"],
                    "received": row["received"],
                    "expired": row["expires"] <= time.time(),
                    "protection": actions.get(
                        json.loads(row["data"]).get("target", ""), {}
                    ),
                }
                for row in rows
            ],
            "total": total,
            "limit": limit,
        }


class Catchup:
    """Schedule directed exchanges while keeping imported history out of live scoring."""

    def __init__(
        self,
        store: CatchupStore,
        network: Callable[[], str],
        own_id: Callable[[], str],
        send: Callable[[str, dict[str, Any]], None],
        on_import: Callable[[str, dict[str, Any]], None] | None = None,
        on_leave: Callable[[str], None] | None = None,
    ) -> None:
        """Use store, current network, own identity and directed send callback."""
        self.store, self.settings = store, store.settings
        self.network, self.own_id, self.send = network, own_id, send
        self.on_import = on_import
        self.on_leave = on_leave
        self.peers: dict[str, bool] = {}
        self.pending: dict[str, dict[str, Any]] = {}
        self.context = ""
        self.capacity = max(
            self.settings.transfer_kib_per_second * 1024.0,
            self.settings.page_bytes * 3.0,
        )
        self.allowance = self.capacity
        self.last_tick = time.monotonic()
        self.last_prune = 0.0
        self.request_times: dict[str, float] = {}
        self.next_tick = 0.0
        self.bootstrap_cursor = (
            time.time() - self.settings.history_days * 86400,
            "",
        )

    def peer(self, peer: str, connected: bool, supported: bool) -> None:
        """Observe authenticated peer presence, connectivity and protocol support."""
        if not connected:
            self.peers.pop(peer, None)
            self.pending.pop(peer, None)
        elif len(self.peers) < 128 or peer in self.peers:
            if peer not in self.peers:
                self.peers[peer] = supported
                self.request_times.pop(peer, None)
                saved = self.store.transfer(self.network(), peer)
                if (
                    time.time() - saved.get("started", 0)
                    >= self.settings.reconnect_cooldown_seconds
                ):
                    self.store.transfer(
                        self.network(),
                        peer,
                        {
                            "history_cursor": saved.get("history_cursor", 0),
                            "generation": saved.get("generation", ""),
                        },
                    )
                elif saved.get("state") in {"complete", "partial"}:
                    saved.update(
                        state="cooldown",
                        not_before=saved.get("started", 0)
                        + self.settings.reconnect_cooldown_seconds,
                    )
                    self.store.transfer(self.network(), peer, saved)
            else:
                self.peers[peer] = supported
        self.next_tick = 0

    def bootstrap(self, validator: Any) -> None:
        """Import at most fifty existing first-hand observations from validator per call."""
        author, network = self.own_id(), self.network()
        if not author or not self.settings.enabled:
            return
        with validator.connect() as conn:
            rows = conn.execute(
                "SELECT record_id,observed_at,data FROM observations WHERE observed_at>=? AND (observed_at>? OR record_id>?) ORDER BY observed_at,record_id LIMIT 50",
                (self.bootstrap_cursor[0], *self.bootstrap_cursor),
            ).fetchall()
        for row in rows:
            self.bootstrap_cursor = (row["observed_at"], row["record_id"])
            record = json.loads(row["data"])
            if record.get("peer_id") or record.get("network_id") != network:
                continue
            evidence = {
                "id": record["id"],
                "attacker": {"value": record["target"]},
                "timestamp": record["observed_at"],
                "confidence": record["confidence"],
                "evidence_type": record["evidence_type"],
                "threat_level": (
                    "critical"
                    if record["score"] >= 1
                    else (
                        "high"
                        if record["score"] >= 0.8
                        else "medium" if record["score"] >= 0.5 else "low"
                    )
                ),
                "source_module": record.get("provenance", {}).get(
                    "module", ""
                ),
                "description": record.get("provenance", {}).get(
                    "description", ""
                ),
            }
            self.store.observe(evidence, network, author)

    def apply_reviews(self, validator: Any) -> None:
        """Withdraw own rejected observations using bounded batches of validator feedback."""
        with validator.connect() as conn:
            rows = conn.execute(
                "SELECT DISTINCT record_id FROM reviews WHERE verdict IN ('false_positive','expected_behavior','true_negative','conflict') LIMIT 10000"
            ).fetchall()
        self.store.withdraw(self.own_id(), {row[0] for row in rows})

    def handle(self, peer: str, message: dict[str, Any]) -> None:
        """Validate an authenticated peer message before queueing bounded work."""
        if (
            not self.settings.enabled
            or message.get("network") != self.network()
        ):
            return
        self.next_tick = 0
        if message.get("message_type") == "catchup_request":
            now = time.monotonic()
            if (
                now - self.request_times.get(peer, -10) < 0.25
                or len(self.pending) >= 32
            ):
                return
            if (
                not isinstance(message.get("nonce"), str)
                or len(message["nonce"]) != 32
            ):
                return
            if message.get("lane") not in {"fresh", "history"}:
                return
            self.request_times[peer] = now
            if len(self.request_times) > 128:
                self.request_times.pop(next(iter(self.request_times)))
            self.pending[peer] = message
            return
        if message.get("message_type") != "catchup_page" or not message.get(
            "verified"
        ):
            return
        try:
            cursor, upto = int(message["cursor"]), int(message["upto"])
            if cursor < 0 or upto < 0:
                return
        except (KeyError, TypeError, ValueError, OverflowError):
            return
        transfer = self.store.transfer(self.network(), peer)
        if (
            transfer.get("nonce") != message.get("nonce")
            or transfer.get("lane") != message.get("lane")
            or transfer.get("after", 0) != message.get("after")
            or transfer.get("state") != "receiving"
        ):
            return
        items = message.get("items")
        if (
            not isinstance(items, list)
            or len(items) > self.settings.page_records
        ):
            return
        if message.get("reset"):
            transfer.update(
                after=0,
                upto=0,
                waiting=False,
                retries=0,
                nonce=secrets.token_hex(16),
            )
            self.store.transfer(self.network(), peer, transfer)
            return
        if transfer.get("generation") != message.get("generation"):
            transfer["history_cursor"] = 0
        transfer["generation"] = message.get("generation")
        accepted, skipped = 0, 0
        for item in items:
            if not isinstance(item, dict):
                continue
            record = item.get("record", {})
            if record.get("network") != self.network() or record.get(
                "author"
            ) != item.get("verified_author"):
                skipped += 1
                continue
            if self.store.save(record, item.get("seal", ""), peer):
                accepted += 1
                if self.on_import:
                    self.on_import(peer, record)
            else:
                skipped += 1
        transfer["received"] = transfer.get("received", 0) + accepted
        transfer["skipped"] = transfer.get("skipped", 0) + skipped
        transfer["bytes"] = transfer.get("bytes", 0) + len(
            json.dumps(message).encode()
        )
        transfer["coverage_start"] = message.get("coverage_start")
        transfer["missing"] = transfer.get("missing", 0) + int(
            message.get("missing", 0)
        )
        transfer["waiting"] = False
        transfer["retries"] = 0
        transfer["not_before"] = time.time() + 0.35
        if cursor < transfer.get("after", 0) or (
            message.get("more") and cursor == transfer.get("after", 0)
        ):
            transfer["state"] = "partial"
        elif transfer["bytes"] >= self.settings.initial_transfer_mib * 1048576:
            transfer["state"] = "partial"
        elif message.get("more"):
            transfer.update(after=cursor, upto=upto)
        elif transfer["lane"] == "fresh":
            transfer.update(lane="history", after=0, upto=0)
        else:
            transfer.update(
                state="partial" if transfer.get("missing") else "complete",
                history_cursor=upto,
                after=0,
            )
        self.store.transfer(self.network(), peer, transfer)

    def tick(self) -> None:
        """Perform one bounded transfer step; live messages run before this method."""
        if not self.settings.enabled:
            return
        now = time.monotonic()
        if now < self.next_tick:
            return
        self.next_tick = now + 0.25
        network = self.network()
        if network != self.context:
            self.pending.clear()
            if self.context:
                if self.on_leave:
                    self.on_leave(self.context)
                self.peers.clear()
            self.context = network
        if not network or network.startswith("run:"):
            return
        rate = self.settings.transfer_kib_per_second * 1024
        self.allowance = min(
            self.capacity, self.allowance + (now - self.last_tick) * rate
        )
        self.last_tick = now
        if now - self.last_prune > 60:
            self.store.prune()
            self.last_prune = now
        if self.pending:
            peer, request = next(iter(self.pending.items()))
            try:
                page = self.store.page(request, self.own_id(), peer)
            except (KeyError, TypeError, ValueError, OverflowError):
                self.pending.pop(peer, None)
                return
            cost = len(json.dumps(page).encode()) * 3
            if cost > self.allowance:
                return
            self.pending.pop(peer, None)
            self.allowance -= cost
            self.send(peer, page)
        active = 0
        for peer, supported in sorted(
            self.peers.items(), key=lambda item: not item[1]
        )[: self.settings.max_peers]:
            transfer = self.store.transfer(network, peer)
            if not supported:
                if transfer.get("state") != "unsupported":
                    self.store.transfer(
                        network, peer, {"state": "unsupported"}
                    )
                continue
            if transfer.get("state") == "receiving":
                active += 1
                if time.time() < transfer.get("not_before", 0):
                    continue
                if (
                    transfer.get("waiting")
                    and time.time() - transfer.get("sent_at", 0) < 10
                ):
                    continue
                if transfer.get("waiting") and transfer.get("retries", 0) >= 2:
                    transfer.update(state="partial", waiting=False)
                    self.store.transfer(network, peer, transfer)
                    continue
            else:
                if transfer.get(
                    "state"
                ) == "cooldown" and time.time() < transfer.get(
                    "not_before", 0
                ):
                    continue
                if transfer.get("state") in {"complete", "partial"}:
                    continue
                if active >= self.settings.parallel_pages:
                    continue
                transfer = {
                    "state": "receiving",
                    "lane": "fresh",
                    "after": 0,
                    "history_cursor": transfer.get("history_cursor", 0),
                    "generation": transfer.get("generation", ""),
                    "upto": 0,
                    "nonce": secrets.token_hex(16),
                    "started": time.time(),
                    "since": time.time() - self.settings.history_days * 86400,
                }
                active += 1
            if self.allowance < 1024:
                return
            self.allowance -= 1024
            message = {
                "message_type": "catchup_request",
                "network": network,
                **{
                    key: transfer[key]
                    for key in ("lane", "after", "upto", "nonce", "since")
                },
                "since_seq": transfer.get("history_cursor", 0),
                "generation": transfer.get("generation", ""),
            }
            transfer.update(
                waiting=True,
                sent_at=time.time(),
                retries=transfer.get("retries", 0) + 1,
            )
            self.store.transfer(network, peer, transfer)
            self.send(peer, message)
        if not active:
            self.next_tick = now + 2
