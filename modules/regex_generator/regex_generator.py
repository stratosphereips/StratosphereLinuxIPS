# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
import random
import re
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


PROMPT_VERSION = "regex-generator-v1"
SYSTEM_PROMPT = """
You generate one Zeek-compatible detection regex for a single field type.

Rules:
- Output raw JSON only.
- JSON shape: {"regex":"...","rationale":"..."}
- Return exactly one regex and one short rationale.
- Do not wrap the regex in slashes.
- Do not use code fences.
- Use a conservative regex subset portable to Zeek and Python.
- Do not use lookbehind, named groups, backreferences, or inline flags.
- Avoid catastrophic backtracking and nested wildcards.
- The regex must be specific enough to avoid broad benign matching.
- The regex should target suspicious lexical patterns, not exact known IOCs.
- The regex must differ materially from the recent history list.
""".strip()

TYPE_PROMPTS = {
    "dns_domain": """
Generate a regex for a suspicious DNS domain name.
Focus on lexical patterns often seen in malicious domains:
- long random-looking labels
- encoded-looking subdomains
- suspicious mixtures of letters and digits
- staged subdomains used for tunneling or C2
Avoid matching common enterprise, CDN, and consumer domains.
The input string is only a domain name, not a URL.
Prefer anchoring with ^ and $ when appropriate.
""".strip(),
    "uri": """
Generate a regex for a suspicious HTTP URI path or full request URI.
Focus on suspicious lexical patterns such as:
- staged payload download paths
- fake update or panel paths
- encoded or obfuscated path segments
- suspicious script/file combinations
Avoid matching ordinary website paths like /, /login, /favicon.ico, health checks,
and typical API routes unless the suspicious lexical combination is strong.
""".strip(),
    "filename": """
Generate a regex for a suspicious filename.
Focus on lexical patterns such as:
- double extensions
- lure words with executable/script extensions
- suspicious archive or installer names
- encoded/random-looking names with risky extensions
Avoid matching ordinary office documents, images, backups, and standard installers.
Prefer anchoring with ^ and $ when appropriate.
""".strip(),
    "tls_sni": """
Generate a regex for a suspicious TLS SNI hostname.
Focus on lexical patterns such as:
- disposable subdomain structures
- random-looking host labels
- deceptive update or login hostnames
- beacon-like hostnames with unusual token composition
Avoid matching major SaaS, CDN, cloud, browser, and operating-system update hosts.
The input string is only the SNI hostname.
Prefer anchoring with ^ and $ when appropriate.
""".strip(),
    "certificate_cn": """
Generate a regex for a suspicious X.509 certificate Common Name.
Focus on lexical patterns such as:
- deceptive hostnames
- awkward token combinations suggesting malware infrastructure
- random or encoded-looking names
- names imitating software update or login services
Avoid matching common public web certificates and ordinary enterprise names.
The input string is only the CN text.
Prefer anchoring with ^ and $ when appropriate.
""".strip(),
}


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
        self.generation_interval_seconds = 5.0
        self.allowed_backends = []
        self.llm_temperature = 1.2
        self.llm_max_tokens = 220
        self.llm_response_timeout_seconds = 90
        self.recent_history_size = 20
        self.max_regex_length = 180
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
        self.type_weights = conf.regex_generator_type_weights()

    def pre_main(self):
        utils.drop_root_privs_permanently()

        if not self.enabled:
            self.print("RegexGenerator module disabled in config.", 2, 0)
            return True

        self.storage = RegexGeneratorStorage(
            self.logger,
            self.conf,
            self.output_dir,
            self.ppid,
        )
        self.next_generation_at = time.time()
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
            self.print(
                "RegexGenerator is waiting for a runtime-ready LLM backend.",
                2,
                0,
            )
            self.next_generation_at = now + self.generation_interval_seconds
            time.sleep(min(0.5, self.generation_interval_seconds))
            return

        regex_type = self._choose_regex_type()
        self._send_generation_request(regex_type, backend)

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
        self.pending_request = {
            "request_id": request_id,
            "regex_type": regex_type,
            "backend": backend,
            "sent_at": time.time(),
            "generation_nonce": generation_nonce,
        }

    def _build_prompt_messages(
        self,
        regex_type: str,
        generation_nonce: str,
    ) -> list:
        history = self.storage.get_recent_history(
            regex_type, self.recent_history_size
        )
        benign_examples = self.storage.get_benign_examples(regex_type, limit=5)

        history_lines = []
        for item in history:
            history_lines.append(
                f'- status={item["status"]} regex={item["regex"]}'
            )
        history_text = "\n".join(history_lines) or "- none"
        benign_text = "\n".join(f"- {value}" for value in benign_examples)
        benign_text = benign_text or "- none"

        user_prompt = (
            f"Regex type: {regex_type}\n"
            f"Prompt version: {PROMPT_VERSION}\n"
            f"Generation nonce: {generation_nonce}\n\n"
            f"{TYPE_PROMPTS[regex_type]}\n\n"
            "Recent regex history that must not be repeated or trivially rewritten:\n"
            f"{history_text}\n\n"
            "Common benign examples that must stay unmatched if reasonably possible:\n"
            f"{benign_text}\n\n"
            "Return strict raw JSON only."
        )
        return [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]

    def _handle_pending_response(self, now: float):
        if now - self.pending_request["sent_at"] > self.llm_response_timeout_seconds:
            self.print(
                "RegexGenerator request timed out waiting for llm_response.",
                0,
                1,
            )
            self.pending_request = None
            self.next_generation_at = now + self.generation_interval_seconds
            return

        if not (msg := self.get_msg(self.db.channels.LLM_RESPONSE)):
            time.sleep(0.1)
            return

        try:
            response = json.loads(msg["data"])
        except (TypeError, json.JSONDecodeError):
            return

        if response.get("request_id") != self.pending_request["request_id"]:
            return

        self._finalize_request(response)
        self.pending_request = None
        self.next_generation_at = time.time() + self.generation_interval_seconds

    def _finalize_request(self, response: dict):
        if not response.get("success"):
            self.print(
                f"RegexGenerator LLM error: {response.get('error', 'unknown')}",
                0,
                1,
            )
            return

        llm_text = response.get("text", "")
        regex, rejection_reason = self._extract_regex_from_llm_text(llm_text)
        if rejection_reason:
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
        try:
            payload = json.loads(llm_text)
        except (TypeError, json.JSONDecodeError):
            return "", "invalid_json"

        if not isinstance(payload, dict):
            return "", "response_not_object"

        regex = payload.get("regex")
        if not isinstance(regex, str) or not regex.strip():
            return "", "missing_regex"

        return regex.strip(), None

    @staticmethod
    def _hash_regex(regex: str) -> str:
        return sha256(regex.encode("utf-8")).hexdigest()

    def _validate_and_store_regex(self, record: dict):
        validation_error = self._validate_regex(record["regex"])
        if validation_error:
            self._store_rejected_regex(record, validation_error)
            return

        if self.storage.get_existing_generated_regex(record["regex_hash"]):
            self.print(
                f"RegexGenerator rejected duplicate regex: {record['regex']}",
                2,
                0,
            )
            return

        compiled_regex = re.compile(record["regex"])
        matched_benign = self._find_matching_benign_value(
            record["regex_type"],
            compiled_regex,
        )
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
