#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
# ruff: noqa: E402
"""
Offline coverage estimator for RegexGenerator output.

This script reads accepted regexes from a Slips run output directory and
estimates how much of several reference populations they cover:

- benign corpus stored by RegexGenerator
- malicious TI-derived strings
- observed traffic strings extracted from the same Slips run

It writes a standalone HTML report and a JSON summary.
"""

from __future__ import annotations

import argparse
import json
import math
import random
import re
import signal
import sqlite3
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

try:
    import redis
except ImportError:  # pragma: no cover - dependency should exist in runtime
    redis = None

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from slips_files.core.database.sqlite_db.regex_generator_db import REGEX_TYPES
from modules.regex_generator.match_strength import (
    compute_match_strength,
    measure_regex_specificity,
)


DOMAIN_LIKE_TYPES = ("dns_domain", "tls_sni", "certificate_cn")
TYPE_LABELS = {
    "dns_domain": "DNS Domain",
    "uri": "URI",
    "filename": "Filename",
    "tls_sni": "TLS SNI",
    "certificate_cn": "Certificate CN",
}


@dataclass
class TIStats:
    run_redis_port: int
    run_redis_available: bool
    ti_cache_port: int
    ti_cache_db: int
    ti_cache_available: bool
    loaded_feeds: int
    cache_domain_count: int
    cache_ip_count: int
    cache_ja3_count: int
    cache_jarm_count: int
    source_files_scanned: int


class ProgressTracker:
    BAR_WIDTH = 24
    CLEAR_LINE = "\r\033[2K"
    RESET = "\033[0m"
    CYAN = "\033[36m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    MAGENTA = "\033[35m"

    def __init__(self, total_regexes: int, total_comparisons: int, mode: str):
        self.total_regexes = max(1, total_regexes)
        self.total_comparisons = max(1, total_comparisons)
        self.mode = mode
        self.regexes_done = 0
        self.comparisons_done = 0
        self.current_type = "-"
        self.start_time = time.monotonic()

    def print_plan(self):
        print(
            f"🔬 Coverage work estimate: {self.total_regexes} regexes, "
            f"{self.total_comparisons} planned regex/string comparisons "
            "(not raw TI entries)",
            flush=True,
        )
        self._render()

    def advance(self, regex_type: str, regex: str, comparisons: int):
        self.regexes_done += 1
        self.comparisons_done += comparisons
        self.current_type = regex_type
        self._render()

    def finish(self):
        self.regexes_done = self.total_regexes
        self.comparisons_done = self.total_comparisons
        self._render(done=True)
        print(flush=True)

    def _render(self, done: bool = False):
        regex_ratio = min(1.0, self.regexes_done / self.total_regexes)
        filled = int(regex_ratio * self.BAR_WIDTH)
        bar = f"{self.GREEN}{'█' * filled}{self.YELLOW}{'░' * (self.BAR_WIDTH - filled)}{self.RESET}"
        elapsed = max(0.001, time.monotonic() - self.start_time)
        progress_ratio = min(1.0, self.comparisons_done / self.total_comparisons)
        if done or progress_ratio >= 1.0:
            eta_seconds = 0.0
        else:
            eta_seconds = (elapsed / max(progress_ratio, 1e-9)) - elapsed
        status = (
            f"{self.CLEAR_LINE}"
            f"🧪 {self.MAGENTA}{self.mode}{self.RESET} "
            f"{bar} "
            f"{regex_ratio * 100:6.2f}% "
            f"| regex {self.regexes_done}/{self.total_regexes} "
            f"| cmp {self.comparisons_done:,}/{self.total_comparisons:,} "
            f"| type {self.CYAN}{TYPE_LABELS.get(self.current_type, self.current_type)}{self.RESET} "
            f"| ETA ⏳ {self._format_duration(eta_seconds)}"
        )
        print(status, end="", flush=True)

    @staticmethod
    def _format_duration(seconds: float) -> str:
        total_seconds = max(0, int(seconds))
        hours, remainder = divmod(total_seconds, 3600)
        minutes, secs = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"


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
        raise TimeoutError("regex population match timed out")


def timeout_context(timeout_seconds: float):
    if timeout_seconds <= 0:
        return _NullTimeout()
    return _SignalTimeout(timeout_seconds)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate an offline RegexGenerator coverage report."
    )
    parser.add_argument(
        "--run-output-dir",
        required=True,
        help=(
            "Slips run output directory containing regex_generator/*.sqlite, "
            "or a direct regex store directory containing generated_regexes.sqlite "
            "and benign_corpus.sqlite."
        ),
    )
    parser.add_argument(
        "--redis-port",
        type=int,
        default=6379,
        help="Redis port used by the Slips run. Default: 6379.",
    )
    parser.add_argument(
        "--ti-cache-port",
        type=int,
        default=6379,
        help="Redis port of the shared Slips TI cache. Default: 6379.",
    )
    parser.add_argument(
        "--ti-cache-db",
        type=int,
        default=1,
        help="Redis DB number for the shared Slips TI cache. Default: 1.",
    )
    parser.add_argument(
        "--output-html",
        default="",
        help="Path to output HTML report. Default: <run-output-dir>/regex_generator_coverage_report.html",
    )
    parser.add_argument(
        "--output-json",
        default="",
        help="Path to output JSON summary. Default: <run-output-dir>/regex_generator_coverage_report.json",
    )
    parser.add_argument(
        "--sample-limit",
        type=int,
        default=15,
        help="Number of example strings to include per report section.",
    )
    parser.add_argument(
        "--top-regexes",
        type=int,
        default=20,
        help="Number of top regexes to show per type.",
    )
    parser.add_argument(
        "--match-timeout-seconds",
        type=float,
        default=0.25,
        help=(
            "Maximum wall-clock seconds allowed for one regex against one "
            "population of strings for one regex type before it is skipped. "
            "The populations are: benign corpus values, malicious TI values, "
            "observed traffic values, and the reference union of malicious+observed. "
            "Set 0 to disable."
        ),
    )
    parser.add_argument(
        "--max-population-size",
        type=int,
        default=10000,
        help=(
            "Maximum number of strings evaluated for each regex type inside each "
            "population: benign corpus, malicious TI, observed traffic, and "
            "reference union. This cap is applied after --sampling-ratio. "
            "Larger populations are sampled deterministically. Set 0 to disable "
            "the cap."
        ),
    )
    parser.add_argument(
        "--sampling-ratio",
        type=float,
        default=0.1,
        help=(
            "Fraction of strings to evaluate from each regex-type population "
            "before applying --max-population-size. This is applied separately "
            "to benign corpus values, malicious TI values, observed traffic values, "
            "and reference-union values. Use values in (0, 1]. Default: 0.1."
        ),
    )
    parser.add_argument(
        "--full-scan",
        action="store_true",
        help=(
            "Disable both --sampling-ratio and --max-population-size, and scan "
            "all strings in all populations for every regex type: benign corpus, "
            "malicious TI, observed traffic, and reference union."
        ),
    )
    parser.add_argument(
        "--sampling-seed",
        type=int,
        default=1,
        help="Deterministic seed used when sampling large populations.",
    )
    return parser.parse_args()


def normalize_string(value: str) -> str:
    return str(value or "").strip()


def normalize_domain(value: str) -> str:
    value = normalize_string(value).rstrip(".").lower()
    return value


def normalize_uri(value: str) -> str:
    value = normalize_string(value)
    if not value:
        return ""
    parsed = urlparse(value)
    if parsed.scheme and parsed.netloc:
        path = parsed.path or "/"
        if parsed.query:
            return f"{path}?{parsed.query}"
        return path
    return value


def normalize_filename(value: str) -> str:
    value = normalize_string(value)
    if not value:
        return ""
    value = value.split("/")[-1]
    value = value.split("\\")[-1]
    return value.strip()


def normalize_cn(value: str) -> str:
    value = normalize_string(value)
    if not value:
        return ""
    cn_match = re.search(r"(?:^|,)CN=([^,]+)", value)
    if cn_match:
        return cn_match.group(1).strip()
    return value


def add_string(populations: dict[str, set[str]], regex_type: str, value: str):
    if regex_type in DOMAIN_LIKE_TYPES:
        normalized = normalize_domain(value)
    elif regex_type == "uri":
        normalized = normalize_uri(value)
    elif regex_type == "filename":
        normalized = normalize_filename(value)
    else:
        normalized = normalize_string(value)

    if normalized:
        populations[regex_type].add(normalized)


def load_regexes(regex_db_path: Path) -> dict[str, list[dict]]:
    regexes_by_type = defaultdict(list)
    with sqlite3.connect(regex_db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT regex_type, regex, regex_hash, backend_alias, provider, model,
                   temperature, prompt_version, request_id, created_at
            FROM generated_regexes
            WHERE status = 'accepted'
            ORDER BY created_at ASC
            """
        ).fetchall()

    for row in rows:
        regexes_by_type[row["regex_type"]].append(
            {
                "regex": row["regex"],
                "regex_hash": row["regex_hash"],
                "backend_alias": row["backend_alias"],
                "provider": row["provider"],
                "model": row["model"],
                "temperature": row["temperature"],
                "prompt_version": row["prompt_version"],
                "request_id": row["request_id"],
                "created_at": row["created_at"],
            }
        )

    return regexes_by_type


def load_benign_corpus(benign_db_path: Path) -> dict[str, set[str]]:
    populations = {regex_type: set() for regex_type in REGEX_TYPES}
    with sqlite3.connect(benign_db_path) as conn:
        for regex_type, value in conn.execute(
            "SELECT regex_type, value FROM benign_strings"
        ):
            add_string(populations, regex_type, value)
    return populations


def load_tranco_benign_populations(
    ti_cache_port: int,
    ti_cache_db: int,
    limit: int,
) -> dict[str, set[str]]:
    populations = {regex_type: set() for regex_type in REGEX_TYPES}
    if redis is None:
        return populations

    try:
        cache_client = redis.Redis(
            host="127.0.0.1",
            port=ti_cache_port,
            db=ti_cache_db,
            decode_responses=True,
            socket_connect_timeout=1,
            socket_timeout=1,
        )
        if limit <= 0:
            return populations
        tranco_domains = cache_client.lrange("tranco_top_domains", 0, limit - 1)
    except Exception:
        return populations

    for domain in tranco_domains:
        domain = normalize_domain(domain)
        if not domain:
            continue
        for regex_type in DOMAIN_LIKE_TYPES:
            add_string(populations, regex_type, domain)
    return populations


def parse_zeek_json_log(path: Path) -> Iterable[dict]:
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def load_observed_populations(run_output_dir: Path) -> dict[str, set[str]]:
    populations = {regex_type: set() for regex_type in REGEX_TYPES}
    zeek_dir = run_output_dir / "zeek_files"

    dns_log = zeek_dir / "dns.log"
    if dns_log.exists():
        for row in parse_zeek_json_log(dns_log):
            add_string(populations, "dns_domain", row.get("query", ""))

    http_log = zeek_dir / "http.log"
    if http_log.exists():
        for row in parse_zeek_json_log(http_log):
            uri = row.get("uri", "")
            add_string(populations, "uri", uri)
            host = normalize_domain(row.get("host", ""))
            if host:
                add_string(populations, "dns_domain", host)
            filename = filename_from_uri(uri)
            if filename:
                add_string(populations, "filename", filename)

    ssl_log = zeek_dir / "ssl.log"
    if ssl_log.exists():
        for row in parse_zeek_json_log(ssl_log):
            server_name = row.get("server_name", "")
            add_string(populations, "tls_sni", server_name)
            add_string(populations, "dns_domain", server_name)

    x509_log = zeek_dir / "x509.log"
    if x509_log.exists():
        for row in parse_zeek_json_log(x509_log):
            subject = row.get("certificate.subject", "")
            cn = normalize_cn(subject)
            add_string(populations, "certificate_cn", cn)
            if utils.is_valid_domain(cn):
                add_string(populations, "dns_domain", cn)

    files_log = zeek_dir / "files.log"
    if files_log.exists():
        for row in parse_zeek_json_log(files_log):
            filename = row.get("filename", "")
            if filename:
                add_string(populations, "filename", filename)

    if all(not values for values in populations.values()):
        flow_db = run_output_dir / "flows.sqlite"
        if flow_db.exists():
            load_observed_from_flows_sqlite(flow_db, populations)

    return populations


def load_observed_from_flows_sqlite(
    flows_db_path: Path, populations: dict[str, set[str]]
):
    with sqlite3.connect(flows_db_path) as conn:
        rows = conn.execute("SELECT flow_type, flow FROM altflows")
        for flow_type, flow_json in rows:
            try:
                flow = json.loads(flow_json)
            except json.JSONDecodeError:
                continue

            if flow_type == "dns":
                add_string(populations, "dns_domain", flow.get("query", ""))
            elif flow_type == "http":
                uri = flow.get("uri", "")
                add_string(populations, "uri", uri)
                add_string(populations, "dns_domain", flow.get("host", ""))
                filename = filename_from_uri(uri)
                if filename:
                    add_string(populations, "filename", filename)
            elif flow_type == "ssl":
                add_string(
                    populations,
                    "tls_sni",
                    flow.get("server_name", flow.get("subject", "")),
                )


def merge_populations(
    base: dict[str, set[str]], extra: dict[str, set[str]]
) -> dict[str, set[str]]:
    for regex_type, values in extra.items():
        base.setdefault(regex_type, set()).update(values)
    return base


def filename_from_uri(uri: str) -> str:
    normalized = normalize_uri(uri)
    if not normalized:
        return ""
    path = normalized.split("?", 1)[0]
    filename = normalize_filename(path)
    if "." not in filename:
        return ""
    return filename


def load_ti_populations(
    run_redis_port: int,
    ti_cache_port: int,
    ti_cache_db: int,
) -> tuple[dict[str, set[str]], TIStats]:
    populations = {regex_type: set() for regex_type in REGEX_TYPES}
    config = ConfigParser()
    loaded_feeds = 0
    cache_domain_count = 0
    cache_ip_count = 0
    cache_ja3_count = 0
    cache_jarm_count = 0
    run_redis_available = False
    ti_cache_available = False
    have_cached_domains = False

    if redis is not None:
        try:
            run_client = redis.Redis(
                host="127.0.0.1",
                port=run_redis_port,
                decode_responses=True,
                socket_connect_timeout=1,
                socket_timeout=1,
            )
            loaded = run_client.get("loaded_TI_files_number")
            loaded_feeds = int(loaded or 0)
            run_redis_available = True
        except Exception:
            run_redis_available = False

        try:
            cache_client = redis.Redis(
                host="127.0.0.1",
                port=ti_cache_port,
                db=ti_cache_db,
                decode_responses=True,
                socket_connect_timeout=1,
                socket_timeout=1,
            )
            redis_domains = cache_client.hkeys("IoC_domains")
            cache_domain_count = len(redis_domains)
            cache_ip_count = cache_client.hlen("IoC_ips")
            cache_ja3_count = cache_client.hlen("IoC_JA3")
            cache_jarm_count = cache_client.hlen("IoC_JARM")
            ti_cache_available = True
            for domain in redis_domains:
                domain = normalize_domain(domain)
                if not domain:
                    continue
                for regex_type in DOMAIN_LIKE_TYPES:
                    add_string(populations, regex_type, domain)
                add_string(populations, "dns_domain", domain)
            have_cached_domains = bool(redis_domains)
        except Exception:
            ti_cache_available = False

    scanned_files = 0
    if not have_cached_domains:
        for file_path in ti_source_files(config):
            scanned_files += 1
            populate_ti_strings_from_file(file_path, populations)
    else:
        for file_path in ti_source_files(config):
            scanned_files += 1
            populate_ti_strings_from_file(
                file_path,
                populations,
                add_domains=False,
            )

    return populations, TIStats(
        run_redis_port=run_redis_port,
        run_redis_available=run_redis_available,
        ti_cache_port=ti_cache_port,
        ti_cache_db=ti_cache_db,
        ti_cache_available=ti_cache_available,
        loaded_feeds=loaded_feeds,
        cache_domain_count=cache_domain_count,
        cache_ip_count=cache_ip_count,
        cache_ja3_count=cache_ja3_count,
        cache_jarm_count=cache_jarm_count,
        source_files_scanned=scanned_files,
    )


def ti_source_files(config: ConfigParser) -> Iterable[Path]:
    candidates = [
        Path(config.local_ti_data_path()),
        Path(config.remote_ti_data_path()),
    ]
    seen = set()
    for base in candidates:
        if not base.is_absolute():
            base = Path.cwd() / base
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file():
                continue
            if path.name.startswith("."):
                continue
            if path.suffix.lower() in {".pyc", ".png", ".jpg", ".jpeg"}:
                continue
            resolved = str(path.resolve())
            if resolved in seen:
                continue
            seen.add(resolved)
            yield path


def populate_ti_strings_from_file(
    path: Path,
    populations: dict[str, set[str]],
    add_domains: bool = True,
) -> None:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return

    for token in tokenize_ti_text(text):
        add_ti_token(token, populations, add_domains=add_domains)


def tokenize_ti_text(text: str) -> Iterable[str]:
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue

        for token in re.split(r"[\s,\t;\"']+", line):
            token = token.strip()
            if token:
                yield token


def add_ti_token(
    token: str,
    populations: dict[str, set[str]],
    add_domains: bool = True,
) -> None:
    token = token.strip().strip(",")
    if not token:
        return

    ioc_type = utils.detect_ioc_type(token)
    if ioc_type == "domain" and add_domains:
        domain = normalize_domain(token)
        for regex_type in DOMAIN_LIKE_TYPES:
            add_string(populations, regex_type, domain)
        add_string(populations, "dns_domain", domain)
        return

    if ioc_type != "url":
        return

    parsed = urlparse(token)
    domain = normalize_domain(parsed.hostname or "")
    if domain and add_domains:
        for regex_type in DOMAIN_LIKE_TYPES:
            add_string(populations, regex_type, domain)
        add_string(populations, "dns_domain", domain)

    uri = normalize_uri(token)
    if uri:
        add_string(populations, "uri", uri)
        filename = filename_from_uri(uri)
        if filename:
            add_string(populations, "filename", filename)


def compile_regexes(regexes_by_type: dict[str, list[dict]]) -> dict[str, list[dict]]:
    compiled_by_type = defaultdict(list)
    for regex_type, regex_rows in regexes_by_type.items():
        for row in regex_rows:
            try:
                compiled = re.compile(row["regex"])
            except re.error:
                continue
            enriched = dict(row)
            enriched["compiled"] = compiled
            compiled_by_type[regex_type].append(enriched)
    return compiled_by_type


def sample_population(
    values: list[str],
    max_population_size: int,
    sampling_seed: int,
    sampling_ratio: float,
) -> tuple[list[str], int]:
    original_total = len(values)
    if original_total == 0:
        return values, original_total

    target_size = original_total
    if 0 < sampling_ratio < 1:
        target_size = max(1, int(original_total * sampling_ratio))

    if max_population_size > 0:
        target_size = min(target_size, max_population_size)

    if target_size >= original_total:
        return values, original_total

    sampler = random.Random(f"{sampling_seed}:{original_total}")
    sampled = sampler.sample(values, target_size)
    sampled.sort()
    return sampled, original_total


def mean_score(scores: list[float]) -> float | None:
    if not scores:
        return None
    return sum(scores) / len(scores)


def stddev_score(scores: list[float]) -> float | None:
    if not scores:
        return None
    avg = mean_score(scores)
    if avg is None:
        return None
    variance = sum((score - avg) ** 2 for score in scores) / len(scores)
    return math.sqrt(variance)


def build_score_stats(
    scores_all: list[float],
    matched_scores: list[float],
    total_values: int,
) -> dict:
    match_count = len(matched_scores)
    return {
        "total_evaluated": total_values,
        "match_count": match_count,
        "match_ratio": (match_count / total_values) if total_values else None,
        "avg_all": mean_score(scores_all),
        "std_all": stddev_score(scores_all),
        "avg_match": mean_score(matched_scores),
        "std_match": stddev_score(matched_scores),
        "max": max(scores_all) if scores_all else None,
    }


def compute_coverage(
    compiled_regexes: dict[str, list[dict]],
    benign_populations: dict[str, set[str]],
    malicious_populations: dict[str, set[str]],
    observed_populations: dict[str, set[str]],
    match_timeout_seconds: float,
    max_population_size: int,
    sampling_seed: int,
    sampling_ratio: float,
    progress: ProgressTracker | None = None,
):
    summary = {}

    for regex_type in REGEX_TYPES:
        benign_values_all = sorted(benign_populations.get(regex_type, set()))
        malicious_values_all = sorted(malicious_populations.get(regex_type, set()))
        observed_values_all = sorted(observed_populations.get(regex_type, set()))
        reference_union_all = sorted(
            set(malicious_values_all).union(observed_values_all)
        )

        benign_values, benign_original_total = sample_population(
            benign_values_all,
            max_population_size,
            sampling_seed,
            sampling_ratio,
        )
        malicious_values, malicious_original_total = sample_population(
            malicious_values_all,
            max_population_size,
            sampling_seed,
            sampling_ratio,
        )
        observed_values, observed_original_total = sample_population(
            observed_values_all,
            max_population_size,
            sampling_seed,
            sampling_ratio,
        )
        reference_union, reference_original_total = sample_population(
            reference_union_all,
            max_population_size,
            sampling_seed,
            sampling_ratio,
        )

        population_map = {
            "benign": benign_values,
            "malicious": malicious_values,
            "observed": observed_values,
            "reference_union": reference_union,
        }
        original_totals = {
            "benign": benign_original_total,
            "malicious": malicious_original_total,
            "observed": observed_original_total,
            "reference_union": reference_original_total,
        }
        regex_rows = compiled_regexes.get(regex_type, [])

        overall_matches = {name: set() for name in population_map}
        population_timeout_counts = {name: 0 for name in population_map}
        regex_details = []
        for row in regex_rows:
            detail = {
                "regex": row["regex"],
                "request_id": row["request_id"],
                "matches": {},
                "score_stats": {},
                "timed_out_populations": [],
                "unique_reference_matches": 0,
                "score": 0,
                "quality_score": 0.0,
                "strength_gap": 0.0,
            }
            compiled = row["compiled"]
            regex_features = measure_regex_specificity(row["regex"])
            comparisons_for_regex = sum(len(values) for values in population_map.values())
            for population_name, values in population_map.items():
                try:
                    with timeout_context(match_timeout_seconds):
                        matched = []
                        scores_all = []
                        matched_scores = []
                        for value in values:
                            score = compute_match_strength(
                                compiled,
                                value,
                                regex_features,
                            )
                            scores_all.append(score)
                            if score > 0:
                                matched.append(value)
                                matched_scores.append(score)
                except TimeoutError:
                    matched = []
                    scores_all = []
                    matched_scores = []
                    detail["timed_out_populations"].append(population_name)
                    population_timeout_counts[population_name] += 1
                detail["matches"][population_name] = matched
                detail["score_stats"][population_name] = build_score_stats(
                    scores_all,
                    matched_scores,
                    len(values),
                )
                overall_matches[population_name].update(matched)

            detail["unique_reference_matches"] = len(
                set(detail["matches"]["reference_union"])
            )
            detail["score"] = (
                len(detail["matches"]["reference_union"])
                - len(detail["matches"]["benign"])
            )
            malicious_avg = detail["score_stats"]["malicious"]["avg_all"] or 0.0
            benign_avg = detail["score_stats"]["benign"]["avg_all"] or 0.0
            detail["strength_gap"] = malicious_avg - benign_avg
            detail["quality_score"] = detail["strength_gap"]
            regex_details.append(detail)
            if progress is not None:
                progress.advance(
                    regex_type,
                    row["regex"],
                    comparisons_for_regex,
                )

        regex_details.sort(
            key=lambda item: (
                item["quality_score"],
                item["score_stats"]["malicious"]["avg_all"] or 0.0,
                item["unique_reference_matches"],
                -len(item["matches"]["benign"]),
            ),
            reverse=True,
        )

        population_stats = {}
        for population_name, values in population_map.items():
            total = len(values)
            matched_values = sorted(overall_matches[population_name])
            unmatched_values = [value for value in values if value not in overall_matches[population_name]]
            original_total = original_totals[population_name]
            population_stats[population_name] = {
                "total": total,
                "original_total": original_total,
                "sampled": total != original_total,
                "matched": len(matched_values),
                "coverage_ratio": (len(matched_values) / total) if total else None,
                "timeout_count": population_timeout_counts[population_name],
                "matched_values": matched_values,
                "unmatched_values": unmatched_values,
            }

        summary[regex_type] = {
            "regex_count": len(regex_rows),
            "populations": population_stats,
            "regex_details": regex_details,
        }

    return summary


def build_report_payload(
    run_output_dir: Path,
    regex_db_path: Path,
    benign_db_path: Path,
    ti_stats: TIStats,
    coverage_summary: dict,
):
    totals = {
        "accepted_regexes": sum(
            details["regex_count"] for details in coverage_summary.values()
        ),
        "types_with_regexes": sum(
            1 for details in coverage_summary.values() if details["regex_count"]
        ),
    }
    generated_at = datetime.now(timezone.utc).isoformat()
    return {
        "generated_at": generated_at,
        "run_output_dir": str(run_output_dir),
        "regex_db_path": str(regex_db_path),
        "benign_db_path": str(benign_db_path),
        "ti": {
            "run_redis_port": ti_stats.run_redis_port,
            "run_redis_available": ti_stats.run_redis_available,
            "ti_cache_port": ti_stats.ti_cache_port,
            "ti_cache_db": ti_stats.ti_cache_db,
            "ti_cache_available": ti_stats.ti_cache_available,
            "loaded_feeds": ti_stats.loaded_feeds,
            "cache_domain_count": ti_stats.cache_domain_count,
            "cache_ip_count": ti_stats.cache_ip_count,
            "cache_ja3_count": ti_stats.cache_ja3_count,
            "cache_jarm_count": ti_stats.cache_jarm_count,
            "source_files_scanned": ti_stats.source_files_scanned,
        },
        "totals": totals,
        "types": coverage_summary,
    }


def ratio_text(value: float | None) -> str:
    if value is None:
        return "n/a"
    percentage = value * 100
    if percentage == 0:
        return "0.0%"

    formatted = f"{percentage:.6f}".rstrip("0").rstrip(".")
    if "." not in formatted:
        formatted = f"{formatted}.0"
    return f"{formatted}%"


def score_text(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:.2f}"


def avg_std_text(stats: dict) -> str:
    avg = stats.get("avg_all")
    std = stats.get("std_all")
    if avg is None:
        return "n/a"
    if std is None:
        return f"{avg:.2f}"
    return f"{avg:.2f} ± {std:.2f}"


def matched_avg_std_text(stats: dict) -> str:
    avg = stats.get("avg_match")
    std = stats.get("std_match")
    if avg is None:
        return "n/a"
    if std is None:
        return f"{avg:.2f}"
    return f"{avg:.2f} ± {std:.2f}"


def render_scatter_plot(regex_type: str, regex_rows: list[dict]) -> str:
    points = []
    width = 520
    height = 360
    padding = 44
    inner_w = width - padding * 2
    inner_h = height - padding * 2
    usable_rows = 0
    for row in regex_rows:
        benign_avg = row["score_stats"]["benign"]["avg_all"]
        malicious_avg = row["score_stats"]["malicious"]["avg_all"]
        if benign_avg is None and malicious_avg is None:
            continue
        usable_rows += 1
        x = padding + (benign_avg or 0.0) / 100.0 * inner_w
        y = height - padding - (malicious_avg or 0.0) / 100.0 * inner_h
        quality = row.get("quality_score", 0.0)
        color = "#1e7a46" if quality >= 0 else "#a73f24"
        radius = 3 if row["score_stats"]["malicious"]["match_count"] < 5 else 4
        title = (
            f"{row['regex']}\n"
            f"malicious avg_all={score_text(malicious_avg)} std_all={score_text(row['score_stats']['malicious']['std_all'])} "
            f"avg_match={score_text(row['score_stats']['malicious']['avg_match'])} matches={row['score_stats']['malicious']['match_count']}\n"
            f"benign avg_all={score_text(benign_avg)} std_all={score_text(row['score_stats']['benign']['std_all'])} "
            f"avg_match={score_text(row['score_stats']['benign']['avg_match'])} matches={row['score_stats']['benign']['match_count']}\n"
            f"gap={score_text(row.get('strength_gap'))}"
        )
        points.append(
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{radius}" fill="{color}" fill-opacity="0.68">'
            f"<title>{escape(title)}</title></circle>"
        )

    if usable_rows == 0:
        return '<p class="small">No benign/malicious score data available for this type.</p>'

    return f"""
    <div class="card">
      <h4>Strength Scatter</h4>
      <p class="small">Each point is one accepted regex. X uses the benign average score across all tested benign strings, with non-matches counted as 0. Y uses the malicious average score across all tested malicious strings, with non-matches counted as 0. The ideal area is upper-left.</p>
      <svg viewBox="0 0 {width} {height}" width="100%" height="360" role="img" aria-label="{escape(TYPE_LABELS[regex_type])} strength scatter plot">
        <rect x="0" y="0" width="{width}" height="{height}" fill="#fffdfa" />
        <line x1="{padding}" y1="{height - padding}" x2="{width - padding}" y2="{height - padding}" stroke="#bfb6a8" stroke-width="1.5" />
        <line x1="{padding}" y1="{padding}" x2="{padding}" y2="{height - padding}" stroke="#bfb6a8" stroke-width="1.5" />
        <line x1="{padding}" y1="{height - padding - inner_h / 2:.1f}" x2="{width - padding}" y2="{height - padding - inner_h / 2:.1f}" stroke="#e4ddd1" stroke-dasharray="4 4" />
        <line x1="{padding + inner_w / 2:.1f}" y1="{padding}" x2="{padding + inner_w / 2:.1f}" y2="{height - padding}" stroke="#e4ddd1" stroke-dasharray="4 4" />
        <text x="{width / 2:.1f}" y="{height - 8}" text-anchor="middle" font-size="13" fill="#6c665d">Benign average score</text>
        <text x="16" y="{height / 2:.1f}" text-anchor="middle" font-size="13" fill="#6c665d" transform="rotate(-90 16 {height / 2:.1f})">Malicious average score</text>
        <text x="{padding}" y="{height - padding + 18}" font-size="12" fill="#6c665d">0</text>
        <text x="{width - padding - 10}" y="{height - padding + 18}" font-size="12" fill="#6c665d">100</text>
        <text x="{padding - 22}" y="{height - padding + 4}" font-size="12" fill="#6c665d">0</text>
        <text x="{padding - 30}" y="{padding + 4}" font-size="12" fill="#6c665d">100</text>
        {''.join(points)}
      </svg>
    </div>
    """


def render_html(report: dict, sample_limit: int, top_regexes: int) -> str:
    rows = []
    for regex_type in REGEX_TYPES:
        details = report["types"][regex_type]
        populations = details["populations"]
        rows.append(
            f"""
            <tr>
              <td>{escape(TYPE_LABELS[regex_type])}</td>
              <td>{details['regex_count']}</td>
              <td>{pop_text(populations['reference_union'])}</td>
              <td>{pop_text(populations['malicious'])}</td>
              <td>{pop_text(populations['observed'])}</td>
              <td>{pop_text(populations['benign'])}</td>
            </tr>
            """
        )

    sections = []
    for regex_type in REGEX_TYPES:
        details = report["types"][regex_type]
        populations = details["populations"]
        regex_rows = details["regex_details"][:top_regexes]
        all_regex_rows = details["regex_details"]

        population_blocks = []
        for population_name in ("reference_union", "malicious", "observed", "benign"):
            stats = populations[population_name]
            label = {
                "reference_union": "Reference Union",
                "malicious": "Malicious TI",
                "observed": "Observed Traffic",
                "benign": "Benign Corpus",
            }[population_name]
            population_blocks.append(
                f"""
                <div class="card">
                  <h4>{escape(label)}</h4>
                  <p><strong>{stats['matched']}</strong> matched out of <strong>{stats['total']}</strong> values</p>
                  <p>Coverage: <strong>{ratio_text(stats['coverage_ratio'])}</strong></p>
                  <p class="small">Sampled population: <span class="status">{str(stats['sampled']).lower()}</span>{f", original total {stats['original_total']}" if stats['sampled'] else ""}</p>
                  <p class="small">Timed-out regex checks: {stats['timeout_count']}</p>
                  <p class="small">Matched samples: {sample_list(stats['matched_values'], sample_limit)}</p>
                  <p class="small">Unmatched samples: {sample_list(stats['unmatched_values'], sample_limit)}</p>
                </div>
                """
            )

        regex_table_rows = []
        for row in regex_rows:
            regex_table_rows.append(
                f"""
                <tr>
                  <td><code>{escape(row['regex'])}</code></td>
                  <td>{row['score_stats']['malicious']['match_count']}</td>
                  <td>{avg_std_text(row['score_stats']['malicious'])}</td>
                  <td>{matched_avg_std_text(row['score_stats']['malicious'])}</td>
                  <td>{row['score_stats']['benign']['match_count']}</td>
                  <td>{avg_std_text(row['score_stats']['benign'])}</td>
                  <td>{matched_avg_std_text(row['score_stats']['benign'])}</td>
                  <td>{score_text(row.get('strength_gap'))}</td>
                  <td>{len(row['matches']['reference_union'])}</td>
                  <td>{len(row['timed_out_populations'])}</td>
                </tr>
                """
            )

        sections.append(
            f"""
            <section>
              <h2>{escape(TYPE_LABELS[regex_type])}</h2>
              <div class="grid">
                {''.join(population_blocks)}
              </div>
              {render_scatter_plot(regex_type, all_regex_rows)}
              <h3>Top Regexes By Malicious-vs-Benign Strength</h3>
              <table>
                <thead>
                  <tr>
                    <th>Regex</th>
                    <th><span class="help" title="Number of matched strings for this regex inside the Malicious TI population for this type.">Malicious Matches</span></th>
                    <th><span class="help" title="Average ± standard deviation of match strength across all malicious strings tested for this regex and this type. Non-matches count as score 0, so this rewards both coverage and strong matches. Higher is better.">Malicious All Avg ± Std</span></th>
                    <th><span class="help" title="Average ± standard deviation of match strength only across malicious strings that this regex actually matched. This shows how strong the successful malicious matches are, independent of coverage.">Malicious Matched Avg ± Std</span></th>
                    <th><span class="help" title="Number of matched strings for this regex inside the benign corpus for this type. Lower is better.">Benign Matches</span></th>
                    <th><span class="help" title="Average ± standard deviation of match strength across all benign strings tested for this regex and this type. Non-matches count as score 0. Lower is better.">Benign All Avg ± Std</span></th>
                    <th><span class="help" title="Average ± standard deviation of match strength only across benign strings that this regex actually matched. Lower is better.">Benign Matched Avg ± Std</span></th>
                    <th><span class="help" title="Current ranking score = malicious all-strings average score minus benign all-strings average score. Higher is better.">Strength Gap</span></th>
                    <th><span class="help" title="Number of matched strings for this regex inside the Reference Union population for this type. Reference Union = Malicious TI ∪ Observed.">Reference Union</span></th>
                    <th><span class="help" title="How many population checks for this regex hit the timeout guard and were skipped.">Timeouts</span></th>
                  </tr>
                </thead>
                <tbody>
                  {''.join(regex_table_rows) or '<tr><td colspan="9">No accepted regexes.</td></tr>'}
                </tbody>
              </table>
            </section>
            """
        )

    ti = report["ti"]
    glossary = """
      <section>
        <h2>How To Read This</h2>
        <div class="grid">
          <div class="card">
            <h4>Accepted Regexes</h4>
            <p class="small">
              The number of regexes currently stored as accepted for that type.
            </p>
          </div>
          <div class="card">
            <h4>Reference Union</h4>
            <p class="small">
              The union of <strong>Malicious TI</strong> and <strong>Observed Traffic</strong>
              for that type. It answers: how much of the combined malicious and seen-in-this-run
              population is covered by the regex set.
            </p>
          </div>
          <div class="card">
            <h4>Malicious TI</h4>
            <p class="small">
              Strings derived from Slips threat-intelligence data. For domain-like types this mainly
              comes from the TI cache. For URI and filename it may also come from parsed TI files.
            </p>
          </div>
          <div class="card">
            <h4>Observed</h4>
            <p class="small">
              Strings extracted from the selected run itself, using Zeek logs or <code>flows.sqlite</code>.
              This is not necessarily malicious. It is the local seen population for that run.
            </p>
          </div>
          <div class="card">
            <h4>Benign Spillover</h4>
            <p class="small">
              Matches against the benign corpus. For domain-like types this benign side may also
              include the Tranco top 1000 domains from the Slips cache. Lower is better. High benign
              spillover means the regex set is too broad for that type.
            </p>
          </div>
          <div class="card">
            <h4>Coverage Numbers</h4>
            <p class="small">
              Values are shown as <code>matched / total (percent)</code>. If a population was sampled,
              the report says so explicitly and the percentage is over the sampled population, not the
              full original population.
            </p>
          </div>
          <div class="card">
            <h4>Progress Bar Numbers</h4>
            <p class="small">
              In terminal output, <code>regex</code> means how many accepted regexes have been processed.
              <code>cmp</code> means planned regex-versus-string match operations across the selected
              populations. It is not the number of TI entries. The count grows because many regexes are
              tested against many strings, often across multiple regex types.
            </p>
          </div>
          <div class="card">
            <h4>Timeouts</h4>
            <p class="small">
              Some regexes are expensive to evaluate. A timeout means the report skipped that regex for
              that population instead of hanging forever.
            </p>
          </div>
          <div class="card">
            <h4>Top Regexes Score</h4>
            <p class="small">
              The top-regex ranking now uses <code>strength_gap = malicious_avg_all - benign_avg_all</code>.
              Both averages are computed over all tested strings in that population, with non-matches counted as <code>0</code>.
              Higher is better because it means broader and/or stronger malicious matches with weaker benign matches.
            </p>
          </div>
          <div class="card">
            <h4>Match Strength</h4>
            <p class="small">
              Each regex/string match gets a score from <code>0</code> to <code>100</code> using the same
              formula as the live RegexGenerator benign filter. The score rewards wider coverage, anchoring,
              and specificity, and penalizes broad wildcard-heavy patterns. In the report, non-matches are
              treated as score <code>0</code> when computing whole-population averages and standard deviations.
            </p>
          </div>
          <div class="card">
            <h4>Strength Scatter</h4>
            <p class="small">
              Each point is one regex. X is the average benign match score. Y is the average malicious match score.
              The ideal region is upper-left: high malicious strength and low benign strength.
            </p>
          </div>
        </div>
      </section>
    """
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Regex Coverage Report</title>
  <style>
    :root {{
      --bg: #f4f1ea;
      --panel: #fffdfa;
      --ink: #1e1c1a;
      --muted: #6c665d;
      --accent: #a73f24;
      --line: #dfd7ca;
      --good: #1e7a46;
      --warn: #b7791f;
    }}
    body {{
      margin: 0;
      font-family: Georgia, "Times New Roman", serif;
      color: var(--ink);
      background: linear-gradient(180deg, #efe8db 0%, var(--bg) 100%);
    }}
    .wrap {{
      max-width: 1200px;
      margin: 0 auto;
      padding: 32px 24px 56px;
    }}
    h1, h2, h3, h4 {{ margin: 0 0 12px; }}
    p {{ margin: 0 0 10px; }}
    .lede {{
      color: var(--muted);
      max-width: 900px;
      margin-bottom: 22px;
    }}
    .hero {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 18px;
      padding: 24px;
      box-shadow: 0 18px 40px rgba(61, 43, 31, 0.08);
      margin-bottom: 24px;
    }}
    .meta {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 14px;
      margin-top: 18px;
    }}
    .card {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 16px;
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 14px;
      margin-bottom: 18px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 14px;
      overflow: hidden;
      margin-bottom: 24px;
    }}
    th, td {{
      padding: 10px 12px;
      border-bottom: 1px solid var(--line);
      vertical-align: top;
      text-align: left;
    }}
    th {{
      background: #f0e7d8;
      font-size: 0.94rem;
    }}
    tr:last-child td {{ border-bottom: none; }}
    code {{
      font-family: "SFMono-Regular", Consolas, monospace;
      font-size: 0.9rem;
      word-break: break-all;
    }}
    .small {{
      color: var(--muted);
      font-size: 0.92rem;
    }}
    .status {{
      display: inline-block;
      padding: 3px 8px;
      border-radius: 999px;
      font-size: 0.86rem;
      background: #efe7d7;
      border: 1px solid var(--line);
    }}
    .help {{
      cursor: help;
      text-decoration: underline dotted;
      text-underline-offset: 3px;
    }}
    section {{
      margin-top: 30px;
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="hero">
      <h1>Regex Coverage Report</h1>
      <p class="lede">
        Offline estimate of accepted RegexGenerator coverage against three reference populations:
        benign corpus, TI-derived malicious strings, and observed traffic from the selected Slips run.
        For domain-like types, the benign side also includes the Tranco top 1000 domains when available
        in the Slips cache.
      </p>
      <div class="meta">
        <div class="card">
          <h4>Run</h4>
          <p><code>{escape(report['run_output_dir'])}</code></p>
          <p class="small">Generated at {escape(report['generated_at'])}</p>
        </div>
        <div class="card">
          <h4>Regexes</h4>
          <p><strong>{report['totals']['accepted_regexes']}</strong> accepted regexes</p>
          <p class="small">{report['totals']['types_with_regexes']} types currently populated</p>
        </div>
        <div class="card">
          <h4>Threat Intelligence</h4>
          <p>Run Redis <strong>{ti['run_redis_port']}</strong>, TI cache <strong>{ti['ti_cache_port']}/{ti['ti_cache_db']}</strong></p>
          <p class="small">Run Redis: <span class="status">{str(ti['run_redis_available']).lower()}</span>, TI cache: <span class="status">{str(ti['ti_cache_available']).lower()}</span></p>
          <p class="small">Loaded feeds: {ti['loaded_feeds']}, cached domains: {ti['cache_domain_count']}, cached IPs: {ti['cache_ip_count']}, JA3: {ti['cache_ja3_count']}, JARM: {ti['cache_jarm_count']}</p>
          <p class="small">Supplemental TI files scanned for URL and filename extraction: {ti['source_files_scanned']}</p>
        </div>
        <div class="card">
          <h4>Databases</h4>
          <p class="small">Regex DB: <code>{escape(report['regex_db_path'])}</code></p>
          <p class="small">Benign DB: <code>{escape(report['benign_db_path'])}</code></p>
        </div>
      </div>
    </div>

    <h2>Coverage by Type</h2>
    <table>
      <thead>
        <tr>
          <th>Type</th>
          <th><span class="help" title="Number of accepted regexes currently stored for this type.">Accepted Regexes</span></th>
          <th><span class="help" title="Union of the Malicious TI and Observed populations for this regex type: all unique strings that are either in TI or seen in the selected run.">Reference Union</span></th>
          <th><span class="help" title="Strings derived from Slips threat-intelligence data for this regex type. For domain-like types this mainly comes from the TI Redis cache.">Malicious TI</span></th>
          <th><span class="help" title="Strings of this regex type extracted from the selected Slips run, usually from Zeek logs or flows.sqlite.">Observed</span></th>
          <th><span class="help" title="Matches against the benign corpus for this regex type. Lower is better because these are likely false positives.">Benign Spillover</span></th>
        </tr>
      </thead>
      <tbody>
        {''.join(rows)}
      </tbody>
    </table>

    {glossary}

    {''.join(sections)}
  </div>
</body>
</html>
"""


def pop_text(stats: dict) -> str:
    summary = (
        f"{stats['matched']}/{stats['total']} "
        f"({ratio_text(stats['coverage_ratio'])})"
    )
    if stats.get("sampled"):
        return f"{summary}, sample of {stats['original_total']}"
    return summary


def sample_list(values: list[str], limit: int) -> str:
    if not values:
        return "none"
    values = values[:limit]
    return ", ".join(f"<code>{escape(value)}</code>" for value in values)


def ensure_paths(
    args: argparse.Namespace,
) -> tuple[Path, Path, Path, Path, Path]:
    input_path = Path(args.run_output_dir).expanduser().resolve()

    store_dir_candidate = input_path
    direct_regex_db_path = store_dir_candidate / "generated_regexes.sqlite"
    direct_benign_db_path = store_dir_candidate / "benign_corpus.sqlite"
    nested_regex_db_path = (
        input_path / "regex_generator" / "generated_regexes.sqlite"
    )
    nested_benign_db_path = input_path / "regex_generator" / "benign_corpus.sqlite"

    if direct_regex_db_path.exists() and direct_benign_db_path.exists():
        run_output_dir = input_path
        regex_db_path = direct_regex_db_path
        benign_db_path = direct_benign_db_path
    elif nested_regex_db_path.exists() and nested_benign_db_path.exists():
        run_output_dir = input_path
        regex_db_path = nested_regex_db_path
        benign_db_path = nested_benign_db_path
    else:
        raise FileNotFoundError(
            "Could not find regex SQLite files. Expected either:\n"
            f"- {direct_regex_db_path} and {direct_benign_db_path}\n"
            f"- {nested_regex_db_path} and {nested_benign_db_path}"
        )

    output_html = (
        Path(args.output_html).expanduser().resolve()
        if args.output_html
        else run_output_dir / "regex_generator_coverage_report.html"
    )
    output_json = (
        Path(args.output_json).expanduser().resolve()
        if args.output_json
        else run_output_dir / "regex_generator_coverage_report.json"
    )
    output_html.parent.mkdir(parents=True, exist_ok=True)
    output_json.parent.mkdir(parents=True, exist_ok=True)
    return run_output_dir, regex_db_path, benign_db_path, output_html, output_json


def main():
    args = parse_args()
    if args.sampling_ratio <= 0 or args.sampling_ratio > 1:
        raise ValueError("--sampling-ratio must be greater than 0 and less than or equal to 1")
    if args.full_scan:
        args.max_population_size = 0
        args.sampling_ratio = 1.0
    config = ConfigParser()
    tranco_top_benign_limit = config.tranco_top_benign_limit()

    (
        run_output_dir,
        regex_db_path,
        benign_db_path,
        output_html,
        output_json,
    ) = ensure_paths(args)

    regexes_by_type = load_regexes(regex_db_path)
    benign_populations = load_benign_corpus(benign_db_path)
    benign_populations = merge_populations(
        benign_populations,
        load_tranco_benign_populations(
            args.ti_cache_port,
            args.ti_cache_db,
            tranco_top_benign_limit,
        ),
    )
    observed_populations = load_observed_populations(run_output_dir)
    malicious_populations, ti_stats = load_ti_populations(
        args.redis_port,
        args.ti_cache_port,
        args.ti_cache_db,
    )
    compiled_regexes = compile_regexes(regexes_by_type)
    total_regexes = sum(len(rows) for rows in compiled_regexes.values())
    sampled_benign = {
        regex_type: sample_population(
            sorted(benign_populations.get(regex_type, set())),
            args.max_population_size,
            args.sampling_seed,
            args.sampling_ratio,
        )[0]
        for regex_type in REGEX_TYPES
    }
    sampled_malicious = {
        regex_type: sample_population(
            sorted(malicious_populations.get(regex_type, set())),
            args.max_population_size,
            args.sampling_seed,
            args.sampling_ratio,
        )[0]
        for regex_type in REGEX_TYPES
    }
    sampled_observed = {
        regex_type: sample_population(
            sorted(observed_populations.get(regex_type, set())),
            args.max_population_size,
            args.sampling_seed,
            args.sampling_ratio,
        )[0]
        for regex_type in REGEX_TYPES
    }
    total_comparisons = 0
    for regex_type in REGEX_TYPES:
        reference_union = set(sampled_malicious[regex_type]).union(
            sampled_observed[regex_type]
        )
        comparisons_per_regex = (
            len(sampled_benign[regex_type])
            + len(sampled_malicious[regex_type])
            + len(sampled_observed[regex_type])
            + len(reference_union)
        )
        total_comparisons += comparisons_per_regex * len(
            compiled_regexes.get(regex_type, [])
        )

    mode = "full scan" if args.full_scan else "sampled estimate"
    progress = ProgressTracker(total_regexes, total_comparisons, mode)
    print(
        f"Starting coverage report in {mode} mode. "
        f"match_timeout_seconds={args.match_timeout_seconds}, "
        f"max_population_size={args.max_population_size}, "
        f"sampling_ratio={args.sampling_ratio}",
        flush=True,
    )
    progress.print_plan()
    coverage_summary = compute_coverage(
        compiled_regexes,
        benign_populations,
        malicious_populations,
        observed_populations,
        args.match_timeout_seconds,
        args.max_population_size,
        args.sampling_seed,
        args.sampling_ratio,
        progress,
    )
    progress.finish()
    report = build_report_payload(
        run_output_dir,
        regex_db_path,
        benign_db_path,
        ti_stats,
        coverage_summary,
    )

    output_html.write_text(
        render_html(report, args.sample_limit, args.top_regexes),
        encoding="utf-8",
    )
    output_json.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"HTML report written to {output_html}")
    print(f"JSON summary written to {output_json}")


if __name__ == "__main__":
    main()
