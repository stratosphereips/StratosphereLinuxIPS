#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""
Audit and optionally prune accepted regexes that exceed the benign threshold.

This is meant for persistent regex stores where the benign corpus may have
grown over time. A regex accepted earlier can later become too strong against
the current benign corpus even though it passed at generation time.
"""

from __future__ import annotations

import argparse
import json
import re
import signal
import shutil
import sqlite3
import sys
import time
import warnings
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.core.database.sqlite_db.regex_generator_db import REGEX_TYPES
from modules.regex_generator.match_strength import (
    compute_match_strength,
    measure_regex_specificity,
)


@dataclass
class RegexAuditResult:
    id: int
    regex_type: str
    regex: str
    regex_hash: str
    created_at: float
    strongest_benign_score: float
    strongest_benign_value: str


class _NullTimeout:
    def __enter__(self):
        return None

    def __exit__(self, exc_type, exc, exc_tb):
        return False


class _SignalTimeout:
    def __init__(self, timeout_seconds: float):
        self.timeout_seconds = timeout_seconds
        self._previous_handler = None

    def __enter__(self):
        self._previous_handler = signal.getsignal(signal.SIGALRM)
        signal.signal(signal.SIGALRM, self._handle_timeout)
        signal.setitimer(signal.ITIMER_REAL, self.timeout_seconds)
        return None

    def __exit__(self, exc_type, exc, exc_tb):
        signal.setitimer(signal.ITIMER_REAL, 0)
        if self._previous_handler is not None:
            signal.signal(signal.SIGALRM, self._previous_handler)
        return False

    @staticmethod
    def _handle_timeout(signum, frame):
        raise TimeoutError("regex benign scan timed out")


def timeout_context(timeout_seconds: float):
    if timeout_seconds <= 0:
        return _NullTimeout()
    return _SignalTimeout(timeout_seconds)


class AuditProgressTracker:
    BAR_WIDTH = 24

    def __init__(self, total_regexes: int, totals_by_type: dict[str, int]):
        self.total_regexes = max(1, total_regexes)
        self.totals_by_type = dict(totals_by_type)
        self.done_regexes = 0
        self.done_by_type = {regex_type: 0 for regex_type in totals_by_type}
        self.current_type = "-"
        self.comparisons_done = 0
        self.flagged_done = 0
        self.timed_out_done = 0
        self.started_at = time.monotonic()
        self.last_render_at = 0.0
        self.enabled = sys.stderr.isatty()

    def start(self):
        if not self.enabled:
            return
        print(
            (
                "Auditing accepted regexes against the current benign corpus "
                f"({self.total_regexes} regexes)"
            ),
            file=sys.stderr,
            flush=True,
        )
        self._render(force=True)

    def advance(
        self,
        regex_type: str,
        comparisons: int,
        flagged_increment: int = 0,
        timed_out_increment: int = 0,
    ):
        self.done_regexes += 1
        self.current_type = regex_type
        self.comparisons_done += comparisons
        self.flagged_done += flagged_increment
        self.timed_out_done += timed_out_increment
        self.done_by_type[regex_type] = self.done_by_type.get(regex_type, 0) + 1
        self._render()

    def finish(self):
        if not self.enabled:
            return
        self._render(force=True, done=True)
        print(file=sys.stderr, flush=True)

    def _render(self, force: bool = False, done: bool = False):
        if not self.enabled:
            return

        now = time.monotonic()
        if not force and not done and now - self.last_render_at < 0.1:
            return
        self.last_render_at = now

        ratio = min(1.0, self.done_regexes / self.total_regexes)
        filled = int(ratio * self.BAR_WIDTH)
        bar = "[" + ("=" * filled) + ("." * (self.BAR_WIDTH - filled)) + "]"
        elapsed = max(0.001, now - self.started_at)
        if done or ratio >= 1.0:
            eta = 0.0
        else:
            eta = (elapsed / max(ratio, 1e-9)) - elapsed

        type_done = self.done_by_type.get(self.current_type, 0)
        type_total = self.totals_by_type.get(self.current_type, 0)
        status = (
            "\r"
            f"{bar} {ratio * 100:6.2f}% "
            f"| regex {self.done_regexes}/{self.total_regexes} "
            f"| type {self.current_type} {type_done}/{type_total} "
            f"| flagged {self.flagged_done} "
            f"| timed out {self.timed_out_done} "
            f"| cmp {self.comparisons_done:,} "
            f"| ETA {self._format_duration(eta)}"
        )
        print(status, end="", file=sys.stderr, flush=True)

    @staticmethod
    def _format_duration(seconds: float) -> str:
        total_seconds = max(0, int(seconds))
        hours, remainder = divmod(total_seconds, 3600)
        minutes, secs = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Audit accepted regexes against the current benign corpus and "
            "optionally delete those whose strongest benign match meets or "
            "exceeds the configured threshold."
        )
    )
    parser.add_argument(
        "--run-output-dir",
        default="",
        help=(
            "Slips run output directory containing regex_generator/*.sqlite, "
            "or a direct regex store directory containing generated_regexes.sqlite "
            "and benign_corpus.sqlite."
        ),
    )
    parser.add_argument(
        "--regex-db",
        default="",
        help="Path to generated_regexes.sqlite. Overrides --run-output-dir.",
    )
    parser.add_argument(
        "--benign-db",
        default="",
        help="Path to benign_corpus.sqlite. Overrides --run-output-dir.",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=None,
        help=(
            "Benign match-strength threshold. Defaults to "
            "regex_generator.benign_match_strength_threshold from config, "
            "or 75 if unavailable."
        ),
    )
    parser.add_argument(
        "--regex-type",
        action="append",
        choices=sorted(REGEX_TYPES),
        help="Limit the audit to one or more regex types.",
    )
    parser.add_argument(
        "--match-timeout-seconds",
        type=float,
        default=None,
        help=(
            "Maximum wall-clock seconds allowed for one accepted regex to scan "
            "the benign corpus for its regex type. Timed-out regexes are "
            "skipped and never deleted. Defaults to "
            "regex_generator.regex_validation_timeout_seconds from config, "
            "or 2.0 if unavailable. Set 0 to disable."
        ),
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum number of example rows to print per regex type.",
    )
    parser.add_argument(
        "--output-json",
        default="",
        help="Optional JSON output path for the audit summary.",
    )
    parser.add_argument(
        "--delete",
        action="store_true",
        help="Delete accepted regex rows that exceed the threshold.",
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Do not create a backup copy of generated_regexes.sqlite before deletion.",
    )
    parser.add_argument(
        "--vacuum",
        action="store_true",
        help="Run VACUUM on generated_regexes.sqlite after deletion.",
    )
    return parser.parse_args()


def default_threshold() -> float:
    try:
        return float(
            ConfigParser().regex_generator_benign_match_strength_threshold()
        )
    except Exception:
        return 75.0


def default_match_timeout() -> float:
    try:
        return float(ConfigParser().regex_generator_regex_validation_timeout_seconds())
    except Exception:
        return 2.0


def resolve_paths(args: argparse.Namespace) -> tuple[Path, Path]:
    if args.regex_db and args.benign_db:
        return Path(args.regex_db).expanduser(), Path(args.benign_db).expanduser()

    if not args.run_output_dir:
        raise SystemExit(
            "Provide either --regex-db and --benign-db, or --run-output-dir."
        )

    base = Path(args.run_output_dir).expanduser()
    direct_regex = base / "generated_regexes.sqlite"
    direct_benign = base / "benign_corpus.sqlite"
    nested_regex = base / "regex_generator" / "generated_regexes.sqlite"
    nested_benign = base / "regex_generator" / "benign_corpus.sqlite"

    if direct_regex.exists() and direct_benign.exists():
        return direct_regex, direct_benign
    if nested_regex.exists() and nested_benign.exists():
        return nested_regex, nested_benign

    raise SystemExit(
        "Could not find regex DBs. Checked:\n"
        f"- {direct_regex} and {direct_benign}\n"
        f"- {nested_regex} and {nested_benign}"
    )


def load_benign_values(benign_db_path: Path) -> dict[str, list[str]]:
    benign_values = {regex_type: [] for regex_type in REGEX_TYPES}
    with sqlite3.connect(benign_db_path) as conn:
        rows = conn.execute(
            "SELECT regex_type, value FROM benign_strings ORDER BY id ASC"
        )
        for regex_type, value in rows:
            benign_values.setdefault(regex_type, []).append(str(value or ""))
    return benign_values


def load_accepted_regexes(
    regex_db_path: Path, regex_types: set[str]
) -> dict[str, list[dict]]:
    accepted = defaultdict(list)
    with sqlite3.connect(regex_db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT id, regex_type, regex, regex_hash, created_at
            FROM generated_regexes
            WHERE status = 'accepted'
            ORDER BY created_at ASC, id ASC
            """
        ).fetchall()
    for row in rows:
        regex_type = row["regex_type"]
        if regex_type not in regex_types:
            continue
        accepted[regex_type].append(dict(row))
    return accepted


def audit_regex_type(
    regex_rows: list[dict],
    benign_values: list[str],
    threshold: float,
    match_timeout_seconds: float,
    progress: AuditProgressTracker | None = None,
) -> tuple[list[RegexAuditResult], list[dict]]:
    flagged = []
    timed_out = []
    for row in regex_rows:
        comparisons_checked = 0
        flagged_increment = 0
        timed_out_increment = 0
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", FutureWarning)
                compiled = re.compile(row["regex"])
        except re.error:
            if progress is not None:
                progress.advance(
                    row["regex_type"],
                    comparisons=comparisons_checked,
                    flagged_increment=flagged_increment,
                    timed_out_increment=timed_out_increment,
                )
            continue

        regex_features = measure_regex_specificity(row["regex"])
        best_score = 0.0
        best_value = ""
        try:
            with timeout_context(match_timeout_seconds):
                for value in benign_values:
                    comparisons_checked += 1
                    score = compute_match_strength(compiled, value, regex_features)
                    if score > best_score:
                        best_score = score
                        best_value = value
                    if best_score >= threshold:
                        flagged_increment = 1
                        flagged.append(
                            RegexAuditResult(
                                id=int(row["id"]),
                                regex_type=row["regex_type"],
                                regex=row["regex"],
                                regex_hash=row["regex_hash"],
                                created_at=float(row["created_at"]),
                                strongest_benign_score=best_score,
                                strongest_benign_value=best_value,
                            )
                        )
                        break
        except TimeoutError:
            timed_out_increment = 1
            timed_out.append(
                {
                    "id": int(row["id"]),
                    "regex_type": row["regex_type"],
                    "regex": row["regex"],
                    "regex_hash": row["regex_hash"],
                    "created_at": float(row["created_at"]),
                    "comparisons_checked": comparisons_checked,
                }
            )
        if progress is not None:
            progress.advance(
                row["regex_type"],
                comparisons=comparisons_checked,
                flagged_increment=flagged_increment,
                timed_out_increment=timed_out_increment,
            )
    flagged.sort(
        key=lambda item: (
            item.regex_type,
            item.strongest_benign_score,
            item.created_at,
            item.id,
        ),
        reverse=True,
    )
    timed_out.sort(
        key=lambda item: (
            item["regex_type"],
            item["created_at"],
            item["id"],
        ),
        reverse=True,
    )
    return flagged, timed_out


def backup_regex_db(regex_db_path: Path) -> Path:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = regex_db_path.with_suffix(regex_db_path.suffix + f".bak.{timestamp}")
    shutil.copy2(regex_db_path, backup_path)
    return backup_path


def delete_flagged_regexes(
    regex_db_path: Path, flagged_results: list[RegexAuditResult], vacuum: bool
) -> int:
    ids = [result.id for result in flagged_results]
    if not ids:
        return 0

    placeholders = ",".join("?" for _ in ids)
    with sqlite3.connect(regex_db_path) as conn:
        cursor = conn.execute(
            f"DELETE FROM generated_regexes WHERE id IN ({placeholders})",
            ids,
        )
        deleted = int(cursor.rowcount or 0)
        conn.commit()
        if vacuum:
            conn.execute("VACUUM")
    return deleted


def build_summary(
    regex_db_path: Path,
    benign_db_path: Path,
    threshold: float,
    regex_types: list[str],
    accepted_by_type: dict[str, list[dict]],
    flagged_by_type: dict[str, list[RegexAuditResult]],
    timed_out_by_type: dict[str, list[dict]],
    limit: int,
    deleted: int,
    backup_path: Path | None,
    match_timeout_seconds: float,
) -> dict:
    summary_types = {}
    for regex_type in regex_types:
        flagged_rows = flagged_by_type.get(regex_type, [])
        timed_out_rows = timed_out_by_type.get(regex_type, [])
        summary_types[regex_type] = {
            "accepted_count": len(accepted_by_type.get(regex_type, [])),
            "flagged_count": len(flagged_rows),
            "timed_out_count": len(timed_out_rows),
            "examples": [
                {
                    **asdict(result),
                    "created_at_iso": datetime.fromtimestamp(
                        result.created_at, tz=timezone.utc
                    ).isoformat(),
                }
                for result in flagged_rows[:limit]
            ],
            "timed_out_examples": [
                {
                    **row,
                    "created_at_iso": datetime.fromtimestamp(
                        row["created_at"], tz=timezone.utc
                    ).isoformat(),
                }
                for row in timed_out_rows[:limit]
            ],
        }

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "regex_db_path": str(regex_db_path),
        "benign_db_path": str(benign_db_path),
        "threshold": threshold,
        "match_timeout_seconds": match_timeout_seconds,
        "regex_types": regex_types,
        "deleted_count": deleted,
        "backup_path": str(backup_path) if backup_path else "",
        "totals": {
            "accepted_count": sum(
                len(accepted_by_type.get(regex_type, []))
                for regex_type in regex_types
            ),
            "flagged_count": sum(
                len(flagged_by_type.get(regex_type, []))
                for regex_type in regex_types
            ),
            "timed_out_count": sum(
                len(timed_out_by_type.get(regex_type, []))
                for regex_type in regex_types
            ),
        },
        "types": summary_types,
    }


def print_summary(summary: dict, delete_mode: bool):
    action = "Deleted" if delete_mode else "Flagged"
    print(
        f"Threshold: {summary['threshold']:.2f}\n"
        f"Match timeout per regex: {summary['match_timeout_seconds']:.2f}s\n"
        f"Regex DB: {summary['regex_db_path']}\n"
        f"Benign DB: {summary['benign_db_path']}\n"
        f"Accepted rows scanned: {summary['totals']['accepted_count']}\n"
        f"{action} rows: {summary['totals']['flagged_count']}\n"
        f"Timed-out rows skipped: {summary['totals']['timed_out_count']}"
    )
    print(
        "Accepted means rows currently stored in generated_regexes.sqlite "
        "with status='accepted'."
    )
    if delete_mode:
        print(
            "Deleted means accepted rows whose strongest benign match score "
            "met or exceeded the threshold and were removed."
        )
    else:
        print(
            "Flagged means accepted rows whose strongest benign match score "
            "meets or exceeds the threshold against the current benign corpus."
        )
    if summary.get("backup_path"):
        print(f"Backup: {summary['backup_path']}")

    for regex_type in summary["regex_types"]:
        row = summary["types"][regex_type]
        print(
            f"\n[{regex_type}] accepted={row['accepted_count']} "
            f"flagged={row['flagged_count']} "
            f"timed_out={row['timed_out_count']}"
        )
        for example in row["examples"]:
            print(
                "  "
                f"score={example['strongest_benign_score']:.2f} "
                f"value={example['strongest_benign_value']} "
                f"created_at={example['created_at_iso']} "
                f"regex={example['regex']}"
            )
        for example in row["timed_out_examples"]:
            print(
                "  "
                "timed_out "
                f"after_cmp={example['comparisons_checked']} "
                f"created_at={example['created_at_iso']} "
                f"regex={example['regex']}"
            )


def main():
    args = parse_args()
    regex_db_path, benign_db_path = resolve_paths(args)
    threshold = (
        float(args.threshold) if args.threshold is not None else default_threshold()
    )
    match_timeout_seconds = (
        float(args.match_timeout_seconds)
        if args.match_timeout_seconds is not None
        else default_match_timeout()
    )
    regex_types = sorted(set(args.regex_type or REGEX_TYPES))

    benign_values = load_benign_values(benign_db_path)
    accepted_by_type = load_accepted_regexes(regex_db_path, set(regex_types))
    progress = AuditProgressTracker(
        total_regexes=sum(
            len(accepted_by_type.get(regex_type, [])) for regex_type in regex_types
        ),
        totals_by_type={
            regex_type: len(accepted_by_type.get(regex_type, []))
            for regex_type in regex_types
        },
    )
    progress.start()
    flagged_by_type = {}
    timed_out_by_type = {}
    for regex_type in regex_types:
        flagged_rows, timed_out_rows = audit_regex_type(
            accepted_by_type.get(regex_type, []),
            benign_values.get(regex_type, []),
            threshold,
            match_timeout_seconds,
            progress=progress,
        )
        flagged_by_type[regex_type] = flagged_rows
        timed_out_by_type[regex_type] = timed_out_rows
    progress.finish()

    backup_path = None
    deleted = 0
    flagged_results = [
        result
        for regex_type in regex_types
        for result in flagged_by_type.get(regex_type, [])
    ]
    if args.delete and flagged_results:
        if not args.no_backup:
            backup_path = backup_regex_db(regex_db_path)
        deleted = delete_flagged_regexes(regex_db_path, flagged_results, args.vacuum)

    summary = build_summary(
        regex_db_path=regex_db_path,
        benign_db_path=benign_db_path,
        threshold=threshold,
        regex_types=regex_types,
        accepted_by_type=accepted_by_type,
        flagged_by_type=flagged_by_type,
        timed_out_by_type=timed_out_by_type,
        limit=max(0, args.limit),
        deleted=deleted,
        backup_path=backup_path,
        match_timeout_seconds=match_timeout_seconds,
    )
    print_summary(summary, delete_mode=args.delete)

    if args.output_json:
        output_path = Path(args.output_json).expanduser()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
