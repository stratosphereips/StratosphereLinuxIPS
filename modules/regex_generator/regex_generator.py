# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
import os
import random
import re
import signal
import time
import uuid
from hashlib import sha256

from slips_files.common.abstracts.imodule import IModule
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from slips_files.core.database.sqlite_db.regex_generator_db import (
    REGEX_TYPES,
    RegexGeneratorStorage,
)


PROMPT_VERSION = "regex-generator-v2"
SYSTEM_PROMPT = """
Return exactly one regex line.
No JSON.
No explanation.
No code fences.
Do not wrap the regex in slashes.
Use a conservative regex subset portable to Zeek and Python.
Do not use lookbehind, named groups, backreferences, or inline flags.
Avoid catastrophic backtracking and nested wildcards.
Keep it specific enough to avoid broad benign matching.
Keep it under 120 characters.
Model uncommon lexical structure, not explicit threat vocabulary.
Do not use literal threat words, brand names, or exact known IOCs.
""".strip()

TYPE_PROMPTS = {
    "dns_domain": """
Generate one DNS domain regex for uncommon suspicious-looking lexical structure.
Target rare structure such as random-looking labels, encoded-looking subdomains,
digit-heavy tokens, awkward token boundaries, or unusual subdomain depth.
The input is only a domain name, not a URL.
Prefer anchors when useful.
Do not use words such as malware, trojan, virus, exploit, c2, bot, or ransom.
""".strip(),
    "uri": """
Generate one HTTP URI regex for uncommon suspicious-looking lexical structure.
Target rare path structure such as encoded segments, awkward separators,
unusual extension combinations, or long mixed-token segments.
Avoid ordinary website paths unless the lexical structure is clearly unusual.
Do not use words such as malware, trojan, virus, exploit, c2, bot, or ransom.
""".strip(),
    "filename": """
Generate one filename regex for uncommon suspicious-looking lexical structure.
Target rare structure such as double extensions, deceptive token boundaries,
random-looking names, or unusual risky extension combinations.
Prefer anchors when useful.
Do not use words such as malware, trojan, virus, exploit, c2, bot, or ransom.
""".strip(),
    "tls_sni": """
Generate one TLS SNI hostname regex for uncommon suspicious-looking lexical structure.
Target rare structure such as disposable subdomains, random-looking host labels,
awkward token composition, or deceptive naming without using explicit threat words.
The input is only the SNI hostname.
Prefer anchors when useful.
Do not use words such as malware, trojan, virus, exploit, c2, bot, or ransom.
""".strip(),
    "certificate_cn": """
Generate one X.509 certificate Common Name regex for uncommon suspicious-looking lexical structure.
Target rare structure such as deceptive hostnames, awkward token combinations,
random or encoded-looking names, or unusual service-like naming patterns.
The input is only the CN text.
Prefer anchors when useful.
Do not use words such as malware, trojan, virus, exploit, c2, bot, or ransom.
""".strip(),
}


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
        raise TimeoutError("regex validation timed out")


class RegexGenerator(IModule):
    name = "RegexGenerator"
    description = "Continuously generates and validates pseudo-random regexes"
    authors = ["OpenAI Codex"]

    def init(self):
        self.c_llm = self.db.subscribe(self.db.channels.LLM_RESPONSE)
        self.channels = {
            self.db.channels.LLM_RESPONSE: self.c_llm,
        }
        self.storage = None
        self.enabled = False
        self.create_log_file = False
        self.log_file_path = os.path.join(self.output_dir, "regex_generator.log")
        self.enable_log_rotation = True
        self.log_rotation_period = 86400
        self.last_log_rotation_time = time.time()
        self.generation_interval_seconds = 5.0
        self.allowed_backends = []
        self.llm_temperature = 1.2
        self.llm_max_tokens = 80
        self.llm_response_timeout_seconds = 90
        self.recent_history_size = 0
        self.max_regex_length = 180
        self.regex_validation_timeout_seconds = 2.0
        self.type_weights = {regex_type: 1.0 for regex_type in REGEX_TYPES}
        self.pending_request = None
        self.next_generation_at = 0.0
        self._rng = random.Random()
        self.read_configuration()

    def read_configuration(self):
        conf = (
            self.conf
            if hasattr(self.conf, "regex_generator_enabled")
            else ConfigParser()
        )
        self.enabled = conf.regex_generator_enabled()
        self.create_log_file = conf.regex_generator_create_log_file()
        self.enable_log_rotation = conf.rotation()
        self.log_rotation_period = self._parse_rotation_period_seconds(
            conf.rotation_period()
        )
        self.generation_interval_seconds = (
            conf.regex_generator_generation_interval_seconds()
        )
        self.allowed_backends = conf.regex_generator_allowed_backends()
        self.llm_temperature = conf.regex_generator_llm_temperature()
        self.llm_max_tokens = conf.regex_generator_llm_max_tokens()
        self.llm_response_timeout_seconds = (
            conf.regex_generator_llm_response_timeout_seconds()
        )
        self.recent_history_size = conf.regex_generator_recent_history_size()
        self.max_regex_length = conf.regex_generator_max_regex_length()
        self.regex_validation_timeout_seconds = (
            conf.regex_generator_regex_validation_timeout_seconds()
        )
        self.type_weights = conf.regex_generator_type_weights()

    def pre_main(self):
        utils.drop_root_privs_permanently()

        if not self.enabled:
            self.print("RegexGenerator module disabled in config.", 2, 0)
            return True

        self._init_log_file()
        self.storage = RegexGeneratorStorage(
            self.logger,
            self.conf,
            self.output_dir,
            self.ppid,
        )
        self.next_generation_at = time.time()
        self._log_detail("RegexGenerator module ready.")
        self._log_detail(
            f"Using storage at {self.storage.store_dir}. "
            f"Benign corpus DB: {self.storage.benign_db.db_path}. "
            f"Generated regex DB: {self.storage.generated_db.db_path}."
        )
        self._log_detail(
            "Rejected regex persistence is "
            f"{'enabled' if self.storage.store_rejected_regexes else 'disabled'}."
        )
        self.print("RegexGenerator module ready.", 2, 0)

    def shutdown_gracefully(self):
        if self.storage:
            self.storage.close()
        return True

    def main(self):
        now = time.time()
        if self.pending_request:
            self._handle_pending_response(now)
            return

        if now < self.next_generation_at:
            time.sleep(min(0.5, self.next_generation_at - now))
            return

        available_backends = self.db.get_available_llm_backends()
        backend = self._select_backend(available_backends)
        if not backend:
            self._log_detail(
                "No runtime-ready LLM backend available yet. Waiting for discovery."
            )
            self.print(
                "RegexGenerator is waiting for a runtime-ready LLM backend.",
                2,
                0,
            )
            self.next_generation_at = now + self.generation_interval_seconds
            time.sleep(min(0.5, self.generation_interval_seconds))
            return

        regex_type = self._choose_regex_type()
        self._log_detail(
            f"Starting generation cycle. regex_type={regex_type} backend={backend}"
        )
        self._send_generation_request(regex_type, backend)

    def _init_log_file(self):
        if not self.create_log_file:
            return

        os.makedirs(self.output_dir, exist_ok=True)
        if not os.path.exists(self.log_file_path):
            with open(self.log_file_path, "w", encoding="utf-8") as log_file:
                log_file.write("")
        self.last_log_rotation_time = time.time()

    def _log_detail(self, text: str):
        if not self.create_log_file:
            return

        self._rotate_log_file_if_needed()
        human_readable_datetime = utils.convert_ts_format(
            time.time(), utils.alerts_format
        )
        with open(self.log_file_path, "a", encoding="utf-8") as log_file:
            log_file.write(f"{human_readable_datetime} - {text}\n")

    def _rotate_log_file_if_needed(self):
        if not self.enable_log_rotation or self.log_rotation_period <= 0:
            return

        now = time.time()
        if now - self.last_log_rotation_time < self.log_rotation_period:
            return

        if os.path.exists(self.log_file_path) and os.path.getsize(
            self.log_file_path
        ) > 0:
            timestamp = time.strftime("%Y%m%d-%H%M%S", time.localtime(now))
            rotated_path = f"{self.log_file_path}.{timestamp}"
            os.replace(self.log_file_path, rotated_path)

        with open(self.log_file_path, "w", encoding="utf-8") as log_file:
            log_file.write("")
        self.last_log_rotation_time = now

    @staticmethod
    def _parse_rotation_period_seconds(rotation_period) -> int:
        if isinstance(rotation_period, (int, float)):
            return max(1, int(rotation_period))

        text = str(rotation_period or "").strip().lower().replace(" ", "")
        match = re.fullmatch(
            r"(?P<value>\d+)(?P<unit>sec|secs|second|seconds|min|mins|minute|minutes|hr|hrs|hour|hours|day|days)",
            text,
        )
        if not match:
            return 86400

        value = int(match.group("value"))
        unit = match.group("unit")
        multipliers = {
            "sec": 1,
            "secs": 1,
            "second": 1,
            "seconds": 1,
            "min": 60,
            "mins": 60,
            "minute": 60,
            "minutes": 60,
            "hr": 3600,
            "hrs": 3600,
            "hour": 3600,
            "hours": 3600,
            "day": 86400,
            "days": 86400,
        }
        return max(1, value * multipliers[unit])

    def _select_backend(self, available_backends: dict) -> str:
        available = available_backends.get("backends", {})
        if not available:
            return ""

        for backend in self.allowed_backends:
            if backend in available:
                return backend

        default_backend = available_backends.get("default_backend", "")
        if default_backend in available:
            return default_backend

        if self.allowed_backends:
            return ""

        return sorted(available)[0]

    def _choose_regex_type(self) -> str:
        regex_types = list(self.type_weights)
        weights = [self.type_weights[regex_type] for regex_type in regex_types]
        return self._rng.choices(regex_types, weights=weights, k=1)[0]

    def _send_generation_request(self, regex_type: str, backend: str):
        request_id = f"{self.name}-{uuid.uuid4()}"
        generation_nonce = str(uuid.uuid4())
        request = {
            "request_id": request_id,
            "requester": self.name,
            "backend": backend,
            "messages": self._build_prompt_messages(regex_type, generation_nonce),
            "temperature": self.llm_temperature,
            "max_tokens": self.llm_max_tokens,
            "metadata": {
                "regex_type": regex_type,
                "prompt_version": PROMPT_VERSION,
                "generation_nonce": generation_nonce,
            },
        }
        self.db.publish(
            self.db.channels.LLM_REQUEST,
            json.dumps(request),
        )
        self._log_detail(
            f"Published llm_request request_id={request_id} "
            f"regex_type={regex_type} backend={backend}"
        )
        self.pending_request = {
            "request_id": request_id,
            "regex_type": regex_type,
            "backend": backend,
            "sent_at": time.time(),
            "generation_nonce": generation_nonce,
            "last_warning_at": 0.0,
        }

    def _build_prompt_messages(
        self,
        regex_type: str,
        generation_nonce: str,
    ) -> list:
        user_prompt = (
            f"Type: {regex_type}\n"
            f"Prompt version: {PROMPT_VERSION}\n"
            f"Nonce: {generation_nonce}\n"
            "Goal: generate a regex for uncommon suspicious-looking lexical structure.\n"
            "Prefer structural contrast over explicit malicious words.\n"
            "Do not repeat previous generations.\n"
            f"{TYPE_PROMPTS[regex_type]}\n"
            "Return one regex only."
        )
        return [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]

    def _handle_pending_response(self, now: float):
        self._warn_if_llm_is_slow(now)

        if not (msg := self.get_msg(self.db.channels.LLM_RESPONSE)):
            time.sleep(0.1)
            return

        try:
            response = json.loads(msg["data"])
        except (TypeError, json.JSONDecodeError):
            return

        if response.get("request_id") != self.pending_request["request_id"]:
            return

        self._log_detail(
            f"Received matching llm_response request_id={response.get('request_id')}"
        )
        self._finalize_request(response)
        self.pending_request = None
        self.next_generation_at = time.time() + self.generation_interval_seconds

    def _warn_if_llm_is_slow(self, now: float):
        if self.llm_response_timeout_seconds <= 0:
            return

        elapsed = now - self.pending_request["sent_at"]
        if elapsed <= self.llm_response_timeout_seconds:
            return

        last_warning_at = self.pending_request.get("last_warning_at", 0.0)
        warning_interval = max(30.0, float(self.llm_response_timeout_seconds))
        if last_warning_at and now - last_warning_at < warning_interval:
            return

        self.print(
            f"RegexGenerator is still waiting for llm_response after {elapsed:.1f}s.",
            2,
            0,
        )
        self._log_detail(
            f"Still waiting for llm_response request_id="
            f"{self.pending_request['request_id']} elapsed={elapsed:.1f}s"
        )
        self.pending_request["last_warning_at"] = now

    def _finalize_request(self, response: dict):
        if not response.get("success"):
            self._log_detail(
                f"LLM response failed request_id={response.get('request_id')} "
                f"error={response.get('error', 'unknown')}"
            )
            self.print(
                f"RegexGenerator LLM error: {response.get('error', 'unknown')}",
                0,
                1,
            )
            return

        llm_text = response.get("text", "")
        regex, rejection_reason = self._extract_regex_from_llm_text(llm_text)
        if rejection_reason:
            self._log_detail(
                f"Rejected malformed LLM response request_id="
                f"{self.pending_request['request_id']} reason={rejection_reason} "
                f"raw_preview={self._short_preview(llm_text)!r}"
            )
            self.print(
                f"RegexGenerator rejected malformed LLM response: {rejection_reason}",
                0,
                1,
            )
            return

        record = {
            "regex_type": self.pending_request["regex_type"],
            "regex": regex,
            "regex_hash": self._hash_regex(regex),
            "backend_alias": self.pending_request["backend"],
            "provider": response.get("provider"),
            "model": response.get("model"),
            "temperature": self.llm_temperature,
            "prompt_version": PROMPT_VERSION,
            "request_id": self.pending_request["request_id"],
            "created_at": time.time(),
        }
        self._validate_and_store_regex(record)

    def _extract_regex_from_llm_text(self, llm_text: str) -> tuple[str, str | None]:
        raw_regex = self._extract_raw_regex_candidate(llm_text)
        if raw_regex:
            return raw_regex, None

        payload = self._extract_json_payload(llm_text)
        if payload is None:
            return "", "invalid_response"

        if not isinstance(payload, dict):
            return "", "response_not_object"

        regex = payload.get("regex")
        if not isinstance(regex, str) or not regex.strip():
            return "", "missing_regex"

        return regex.strip(), None

    @staticmethod
    def _extract_raw_regex_candidate(llm_text: str) -> str:
        if not isinstance(llm_text, str):
            return ""

        text = RegexGenerator._strip_code_fences(llm_text).strip()
        if not text:
            return ""

        for line in text.splitlines():
            candidate = line.strip().strip("`").strip()
            if not candidate:
                continue
            if candidate.lower().startswith("regex:"):
                candidate = candidate.split(":", 1)[1].strip()
            candidate = candidate.strip().strip('"').strip("'")
            if candidate.startswith("/") and candidate.endswith("/") and len(candidate) > 1:
                candidate = candidate[1:-1].strip()
            if not candidate or " " in candidate or candidate.startswith("{"):
                continue
            if not re.search(r"[\^\$\[\]\(\)\{\}\\\.\|\*\+\?]", candidate):
                continue
            return candidate

        return ""

    @staticmethod
    def _strip_code_fences(text: str) -> str:
        stripped = text.strip()
        if not stripped.startswith("```"):
            return stripped

        lines = stripped.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        return "\n".join(lines).strip()

    @staticmethod
    def _extract_json_payload(llm_text: str) -> dict | None:
        if not isinstance(llm_text, str):
            return None

        candidates = [llm_text.strip()]
        fenced_match = re.search(
            r"```(?:json)?\s*(\{.*?\})\s*```",
            llm_text,
            flags=re.DOTALL,
        )
        if fenced_match:
            candidates.append(fenced_match.group(1).strip())

        object_text = RegexGenerator._extract_first_json_object(llm_text)
        if object_text:
            candidates.append(object_text)

        for candidate in candidates:
            if not candidate:
                continue
            try:
                return json.loads(candidate)
            except (TypeError, json.JSONDecodeError):
                continue

        return None

    @staticmethod
    def _extract_first_json_object(text: str) -> str | None:
        start = text.find("{")
        while start != -1:
            depth = 0
            in_string = False
            escaped = False
            for idx in range(start, len(text)):
                char = text[idx]
                if in_string:
                    if escaped:
                        escaped = False
                    elif char == "\\":
                        escaped = True
                    elif char == '"':
                        in_string = False
                    continue

                if char == '"':
                    in_string = True
                elif char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0:
                        return text[start : idx + 1].strip()

            start = text.find("{", start + 1)

        return None

    @staticmethod
    def _short_preview(text: str, limit: int = 200) -> str:
        text = " ".join(str(text).split())
        if len(text) <= limit:
            return text
        return f"{text[:limit]}..."

    @staticmethod
    def _hash_regex(regex: str) -> str:
        return sha256(regex.encode("utf-8")).hexdigest()

    def _validate_and_store_regex(self, record: dict):
        try:
            with self._regex_validation_timeout():
                validation_error = self._validate_regex(record["regex"])
        except TimeoutError:
            self._store_rejected_regex(record, "regex_validation_timeout")
            return

        if validation_error:
            self._store_rejected_regex(record, validation_error)
            return

        if self.storage.might_have_generated_regex(record["regex_hash"]):
            if self.storage.get_existing_generated_regex(
                record["regex_hash"]
            ) or self.storage.was_rejected_in_current_run(record["regex_hash"]):
                self._log_detail(
                    f"Rejected duplicate regex request_id={record['request_id']} "
                    f"regex_type={record['regex_type']} regex={record['regex']}"
                )
                self.print(
                    f"RegexGenerator rejected duplicate regex: {record['regex']}",
                    2,
                    0,
                )
                return

        try:
            with self._regex_validation_timeout():
                compiled_regex = re.compile(record["regex"])
                matched_benign = self._find_matching_benign_value(
                    record["regex_type"],
                    compiled_regex,
                )
        except TimeoutError:
            self._store_rejected_regex(record, "regex_validation_timeout")
            return

        if matched_benign:
            self._store_rejected_regex(
                record,
                "matched_benign_data",
                matched_benign_value=matched_benign,
            )
            return

        record["status"] = "accepted"
        record["rejection_reason"] = None
        record["matched_benign_value"] = None
        self.storage.store_generated_regex(record)
        self._log_detail(
            f"Accepted regex request_id={record['request_id']} "
            f"regex_type={record['regex_type']} regex={record['regex']}"
        )

    def _store_rejected_regex(
        self,
        record: dict,
        rejection_reason: str,
        matched_benign_value: str | None = None,
    ):
        record["status"] = "rejected"
        record["rejection_reason"] = rejection_reason
        record["matched_benign_value"] = matched_benign_value
        self.storage.store_generated_regex(record)
        extra = (
            f" matched_benign_value={matched_benign_value}"
            if matched_benign_value
            else ""
        )
        self._log_detail(
            f"Rejected regex request_id={record['request_id']} "
            f"regex_type={record['regex_type']} reason={rejection_reason}"
            f"{extra} regex={record['regex']}"
        )

    def _regex_validation_timeout(self):
        timeout = float(self.regex_validation_timeout_seconds)
        if timeout <= 0:
            return _NullTimeout()
        return _SignalTimeout(timeout)

    def _validate_regex(self, regex: str) -> str | None:
        try:
            regex.encode("ascii")
        except UnicodeEncodeError:
            return "non_ascii_regex"

        if len(regex) > self.max_regex_length:
            return "regex_too_long"

        if regex in {".*", ".+", "^.*$", "^.+$"}:
            return "regex_too_broad"

        if "(?<=" in regex or "(?<!" in regex:
            return "unsupported_lookbehind"

        if re.search(r"\\[1-9]", regex):
            return "unsupported_backreference"

        stripped_regex = regex.strip()
        if stripped_regex.startswith(".*") and stripped_regex.endswith(".*"):
            return "unbounded_prefix_suffix"
        if stripped_regex.startswith("^.*") and stripped_regex.endswith(".*$"):
            return "unbounded_prefix_suffix"

        if re.search(r"\((?:[^()]|\\.)*[.*+](?:[^()]|\\.)*\)[*+]", regex):
            return "nested_wildcards"

        if self._is_too_broad_alternation(regex):
            return "regex_too_broad"

        try:
            re.compile(regex)
        except re.error:
            return "invalid_regex_syntax"

        return None

    @staticmethod
    def _is_too_broad_alternation(regex: str) -> bool:
        stripped_regex = regex.strip("^$()")
        if "|" not in stripped_regex:
            return False

        parts = [part.strip("()[]{}?+*.^$") for part in stripped_regex.split("|")]
        parts = [part for part in parts if part]
        if len(parts) < 4:
            return False
        return all(len(part) <= 2 for part in parts)

    def _find_matching_benign_value(self, regex_type: str, compiled_regex) -> str | None:
        for value in self.storage.iter_benign_strings(regex_type):
            if compiled_regex.search(value):
                return value
        return None
