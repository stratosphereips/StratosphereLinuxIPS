# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
import os
import time
import uuid
from collections import deque

from slips_files.common.abstracts.imodule import IModule
from slips_files.common.output_paths import get_alerts_path_inside_output_dir
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from slips_files.core.structures.alerts import dict_to_alert
from slips_files.core.structures.evidence import dict_to_evidence


PROMPT_VERSION = "alert-summary-v1"
LOG_VERBOSITY_SUMMARY = 1
LOG_VERBOSITY_REQUESTS = 2
LOG_VERBOSITY_DEBUG = 3
SYSTEM_PROMPT = """
You are a very professional and senior cybersecurity researcher and incident analyst.
Use only the provided alert and evidence data.
Write exactly one paragraph of plain text for a human analyst.
Explain the main suspicious behavior, what evidence most strongly supports or weakens the alert,
whether it looks like a likely true positive, likely false positive, or uncertain, and how risky it appears.
If the evidence is weak, incomplete, or conflicting, say that clearly.
Do not use bullet points, markdown, headings, or JSON.
Do not invent missing facts.
""".strip()


class AlertSummary(IModule):
    name = "alert_summary"
    description = "Summarizes alerts for analysts using the shared LLM module"
    authors = ["OpenAI Codex"]

    def init(self):
        """Initialize channels, queue state, and module configuration."""
        self.enabled = False
        self.allowed_backends = []
        self.llm_temperature = 0.2
        self.llm_max_tokens = 220
        self.llm_response_timeout_seconds = 120
        self.log_verbosity = LOG_VERBOSITY_REQUESTS
        self.pending_alerts = deque()
        self.pending_request = None
        self.summary_log = None
        self.operation_log = None
        self.operation_log_path = os.path.join(
            self.parent_output_dir,
            "llm-summary",
            "alert_summary.log",
        )
        self.summary_log_path = os.path.join(
            get_alerts_path_inside_output_dir(self.parent_output_dir),
            "alerts-summary.log",
        )
        self.read_configuration()

    def subscribe_to_channels(self):
        """Subscribe to alert and shared LLM response channels."""
        self.c_alert = self.db.subscribe("new_alert")
        self.c_llm = self.db.subscribe(self.db.channels.LLM_RESPONSE)
        self.channels = {
            "new_alert": self.c_alert,
            self.db.channels.LLM_RESPONSE: self.c_llm,
        }

    def read_configuration(self):
        """Read alert summary settings from the active Slips configuration."""
        conf = (
            self.conf
            if hasattr(self.conf, "alert_summary_enabled")
            else ConfigParser()
        )
        self.enabled = conf.alert_summary_enabled()
        self.allowed_backends = conf.alert_summary_allowed_backends()
        self.llm_temperature = conf.alert_summary_llm_temperature()
        self.llm_max_tokens = conf.alert_summary_llm_max_tokens()
        self.llm_response_timeout_seconds = (
            conf.alert_summary_llm_response_timeout_seconds()
        )
        self.log_verbosity = conf.alert_summary_log_verbosity()

    def pre_main(self):
        """Drop privileges and initialize the output log file if enabled."""
        utils.drop_root_privs_permanently()

        if not self.enabled:
            self.print("AlertSummary module disabled in config.", 2, 0)
            return True

        self._init_operation_log_file()
        self._init_summary_log_file()
        self._log_operation(
            "AlertSummary module ready. "
            f"summary_log={self.summary_log_path} "
            f"operation_log={self.operation_log_path}",
            verbosity=LOG_VERBOSITY_SUMMARY,
        )

    def should_stop(self) -> bool:
        """Keep running during shutdown while summary work is still pending."""
        if not self.termination_event.is_set():
            return False

        if self._has_pending_work():
            return False

        return super().should_stop()

    def shutdown_gracefully(self):
        """Close the summary log file on shutdown."""
        if self.pending_request:
            alert = self.pending_request["alert"]
            self._write_summary_entry(
                alert,
                "LLM summary unavailable: Module stopped before the LLM reply was processed.",
            )
            self._log_operation(
                f"Shutdown flushed pending request for alert_id={alert.id}.",
                verbosity=LOG_VERBOSITY_SUMMARY,
            )
            self.pending_request = None

        if self.pending_alerts:
            self._flush_queued_alerts_without_backend(
                "Module stopped before pending alerts were summarized."
            )

        self._log_operation(
            "AlertSummary module stopped.",
            verbosity=LOG_VERBOSITY_SUMMARY,
        )
        if self.summary_log is not None:
            self.summary_log.close()
        if self.operation_log is not None:
            self.operation_log.close()

    def main(self):
        """Queue new alerts, process shared LLM responses, and dispatch work."""
        self._queue_new_alert()

        if self.pending_request:
            self._handle_pending_response()
            if self.pending_request:
                return

        if not self.pending_alerts:
            return

        available_backends = self.db.get_available_llm_backends()
        backend = self._select_backend(available_backends)
        if not backend:
            if self.termination_event.is_set():
                self._flush_queued_alerts_without_backend(
                    "No runtime-ready LLM backend available."
                )
            elif self.pending_alerts:
                self._log_operation(
                    "No runtime-ready LLM backend available yet. "
                    f"queued_alerts={len(self.pending_alerts)}",
                    verbosity=LOG_VERBOSITY_REQUESTS,
                )
            return

        self._dispatch_next_alert(backend)

    def _init_operation_log_file(self):
        """Create or clear the per-run alert summary operation log file."""
        os.makedirs(os.path.dirname(self.operation_log_path), exist_ok=True)
        utils.initialize_logfile(
            self.operation_log_path,
            getattr(self.args, "is_slips_started_by_an_update", False),
        )
        self.operation_log = open(
            self.operation_log_path, "a", encoding="utf-8"
        )

        conf = ConfigParser()
        utils.change_logfiles_ownership(
            self.operation_log_path,
            conf.get_UID(),
            conf.get_GID(),
        )

    def _init_summary_log_file(self):
        """Create or clear alerts-summary.log for the current Slips run."""
        os.makedirs(os.path.dirname(self.summary_log_path), exist_ok=True)
        utils.initialize_logfile(
            self.summary_log_path,
            getattr(self.args, "is_slips_started_by_an_update", False),
        )
        self.summary_log = open(self.summary_log_path, "a", encoding="utf-8")

        conf = ConfigParser()
        utils.change_logfiles_ownership(
            self.summary_log_path,
            conf.get_UID(),
            conf.get_GID(),
        )

    def _queue_new_alert(self):
        """Parse and enqueue a new alert together with its correlated evidence."""
        msg = self.get_msg("new_alert")
        if not msg:
            return

        try:
            alert = dict_to_alert(json.loads(msg["data"]))
        except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
            self.print(f"Unable to parse new_alert payload: {exc}", 0, 1)
            self._log_operation(
                f"Unable to parse new_alert payload: {exc}",
                verbosity=LOG_VERBOSITY_SUMMARY,
            )
            return

        evidences = self._get_alert_evidence(alert)
        self.pending_alerts.append(
            {
                "alert": alert,
                "evidences": evidences,
            }
        )
        self._log_operation(
            f"Queued alert_id={alert.id} "
            f"profileid={alert.profile} "
            f"timewindow={alert.timewindow} "
            f"evidence_count={len(evidences)} "
            f"queue_size={len(self.pending_alerts)}",
            verbosity=LOG_VERBOSITY_REQUESTS,
        )

    def _get_alert_evidence(self, alert) -> list:
        """Load and normalize all evidence records referenced by the alert."""
        profileid = str(alert.profile)
        twid = str(alert.timewindow)
        raw_evidence = self.db.get_twid_evidence(profileid, twid) or {}

        evidence_records = []
        for evidence_id in alert.correl_id:
            payload = raw_evidence.get(evidence_id)
            if isinstance(payload, str):
                try:
                    payload = json.loads(payload)
                except json.JSONDecodeError:
                    continue

            if not isinstance(payload, dict):
                continue

            try:
                evidence_records.append(dict_to_evidence(payload))
            except (KeyError, TypeError, ValueError):
                continue

        if not evidence_records:
            evidence_records = [alert.last_evidence]

        evidence_records.sort(key=self._get_evidence_sort_key)
        return evidence_records

    def _get_evidence_sort_key(self, evidence) -> tuple:
        """Build a stable sort key even when evidence timestamps vary in type."""
        timestamp = getattr(evidence, "timestamp", "")

        if isinstance(timestamp, (int, float)):
            return (0, float(timestamp))

        try:
            return (0, float(utils.convert_ts_format(timestamp, "unixtimestamp")))
        except (TypeError, ValueError):
            return (1, str(timestamp))

    def _select_backend(self, available_backends: dict) -> str:
        """Choose a runtime-ready backend using module preferences first."""
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

    def _dispatch_next_alert(self, backend: str):
        """Publish one alert summary request to the shared LLM module."""
        queued_alert = self.pending_alerts.popleft()
        alert = queued_alert["alert"]
        evidences = queued_alert["evidences"]
        request_id = f"{self.name}-{uuid.uuid4()}"
        request = self._build_llm_request(
            request_id,
            backend,
            alert,
            evidences,
        )
        self.db.publish(self.db.channels.LLM_REQUEST, json.dumps(request))
        self._log_operation(
            f"Published llm_request request_id={request_id} "
            f"alert_id={alert.id} "
            f"backend={backend} "
            f"evidence_count={len(evidences)}",
            verbosity=LOG_VERBOSITY_REQUESTS,
        )
        self.pending_request = {
            "request_id": request_id,
            "backend": backend,
            "alert": alert,
            "evidences": evidences,
            "sent_at": time.time(),
        }

    def _build_llm_request(
        self,
        request_id: str,
        backend: str,
        alert,
        evidences: list,
    ) -> dict:
        """Build the shared LLM request payload for one alert."""
        return {
            "request_id": request_id,
            "requester": self.name,
            "backend": backend,
            "messages": self._build_prompt_messages(alert, evidences),
            "temperature": self.llm_temperature,
            "max_tokens": self.llm_max_tokens,
            "metadata": {
                "alert_id": alert.id,
                "profileid": str(alert.profile),
                "timewindow": str(alert.timewindow),
                "evidence_count": len(evidences),
                "prompt_version": PROMPT_VERSION,
            },
        }

    def _build_prompt_messages(self, alert, evidences: list) -> list:
        """Create the system and user prompt messages for one alert."""
        context = {
            "alert": self._build_alert_payload(alert),
            "evidences": [
                self._build_evidence_payload(evidence)
                for evidence in evidences
            ],
        }
        user_prompt = (
            "Summarize this Slips alert for a human analyst.\n"
            "Requirements:\n"
            "- One paragraph only.\n"
            "- Be concise but specific.\n"
            "- Focus on whether the alert is likely real, uncertain, or likely false positive, and why.\n"
            "- Mention the main suspicious behavior and the likely operational risk.\n"
            "- Base the assessment only on the provided evidence.\n\n"
            f"Prompt version: {PROMPT_VERSION}\n"
            "Alert context:\n"
            f"{json.dumps(context, indent=2, sort_keys=True)}"
        )
        return [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]

    def _build_alert_payload(self, alert) -> dict:
        """Create a compact JSON-serializable summary of the alert itself."""
        profileid = str(alert.profile)
        hostname = self.db.get_hostname_from_profile(profileid) or ""
        return {
            "id": alert.id,
            "profile_ip": alert.profile.ip,
            "profile_hostname": hostname,
            "timewindow": {
                "number": alert.timewindow.number,
                "start_time": alert.timewindow.start_time,
                "end_time": alert.timewindow.end_time,
            },
            "last_flow_datetime": alert.last_flow_datetime,
            "threat_level": str(alert.threat_level),
            "confidence": alert.confidence,
            "accumulated_threat_level": alert.accumulated_threat_level,
            "correlated_evidence_count": len(alert.correl_id),
        }

    def _build_evidence_payload(self, evidence) -> dict:
        """Create a compact JSON-serializable view of one evidence record."""
        payload = {
            "id": evidence.id,
            "evidence_type": self._format_enum_name(evidence.evidence_type),
            "description": evidence.description,
            "timestamp": evidence.timestamp,
            "threat_level": str(evidence.threat_level),
            "confidence": evidence.confidence,
            "evidence_signal": self._format_enum_name(
                evidence.evidence_signal
            ),
            "proto": self._format_enum_value(evidence.proto),
            "src_port": evidence.src_port,
            "dst_port": evidence.dst_port,
            "uid_count": len(evidence.uid),
            "attacker": self._build_entity_payload(evidence.attacker),
            "victim": self._build_entity_payload(evidence.victim),
        }
        return payload

    def _build_entity_payload(self, entity) -> dict:
        """Normalize attacker or victim metadata for prompt inclusion."""
        if not entity:
            return {}

        payload = {
            "direction": self._format_enum_name(entity.direction),
            "ioc_type": self._format_enum_name(entity.ioc_type),
            "value": entity.value,
            "TI": entity.TI,
            "AS": entity.AS,
            "rDNS": entity.rDNS,
            "SNI": entity.SNI,
            "DNS_resolution": entity.DNS_resolution,
            "queries": entity.queries,
            "CNAME": entity.CNAME,
        }
        return {
            key: value
            for key, value in payload.items()
            if value not in ("", None, [], {})
        }

    def _format_enum_name(self, value) -> str:
        """Return a readable lower-case name for enums or raw string values."""
        if value is None:
            return ""
        name = getattr(value, "name", None)
        if isinstance(name, str) and name.strip():
            return name.strip().lower()
        return str(value).strip().lower()

    def _format_enum_value(self, value) -> str:
        """Return a readable value for enums or raw string values."""
        if value is None:
            return ""
        enum_value = getattr(value, "value", None)
        if isinstance(enum_value, str) and enum_value.strip():
            return enum_value.strip()
        return str(value).strip().lower()

    def _handle_pending_response(self):
        """Consume the matching shared LLM response or fail on timeout."""
        msg = self.get_msg(self.db.channels.LLM_RESPONSE)
        if msg:
            try:
                response = json.loads(msg["data"])
            except (TypeError, json.JSONDecodeError):
                self._log_operation(
                    "Received malformed llm_response payload. Ignoring.",
                    verbosity=LOG_VERBOSITY_DEBUG,
                )
                return

            if response.get("request_id") != self.pending_request["request_id"]:
                return

            self._finalize_request(response)
            return

        if not self._is_response_timed_out():
            return

        self._finalize_request(
            {
                "request_id": self.pending_request["request_id"],
                "backend": self.pending_request["backend"],
                "success": False,
                "error": "LLM summary request timed out.",
                "text": "",
            }
        )

    def _is_response_timed_out(self) -> bool:
        """Return True when the active request exceeded the configured timeout."""
        if not self.pending_request or self.llm_response_timeout_seconds <= 0:
            return False

        elapsed = time.time() - self.pending_request["sent_at"]
        return elapsed >= self.llm_response_timeout_seconds

    def _finalize_request(self, response: dict):
        """Write either a summary paragraph or a failure note for one alert."""
        request = self.pending_request
        if not request:
            return

        alert = request["alert"]
        if response.get("success") and str(response.get("text", "")).strip():
            summary = self._normalize_summary_text(response["text"])
            self._write_summary_entry(
                alert,
                f"LLM summary: {summary}",
            )
            self._log_operation(
                f"Received successful llm_response request_id="
                f"{request['request_id']} alert_id={alert.id}",
                verbosity=LOG_VERBOSITY_REQUESTS,
            )
        else:
            error = str(response.get("error", "Unknown LLM summary failure."))
            self._write_summary_entry(
                alert,
                f"LLM summary unavailable: {error}",
            )
            self._log_operation(
                f"LLM summary unavailable for alert_id={alert.id}: {error}",
                verbosity=LOG_VERBOSITY_SUMMARY,
            )

        self.pending_request = None

    def _normalize_summary_text(self, text: str) -> str:
        """Collapse any multi-paragraph response into one plain-text paragraph."""
        normalized = " ".join(str(text or "").split())
        return normalized.strip()

    def _has_pending_work(self) -> bool:
        """Return True when alert summaries still need LLM processing."""
        return bool(self.pending_request or self.pending_alerts)

    def _flush_queued_alerts_without_backend(self, reason: str):
        """Write failure notes for queued alerts when shutdown happens first."""
        while self.pending_alerts:
            queued_alert = self.pending_alerts.popleft()
            self._write_summary_entry(
                queued_alert["alert"],
                f"LLM summary unavailable: {reason}",
            )
            self._log_operation(
                f"Flushed alert_id={queued_alert['alert'].id}: {reason}",
                verbosity=LOG_VERBOSITY_SUMMARY,
            )

    def _write_summary_entry(self, alert, summary_text: str):
        """Append one human-readable summary line to alerts-summary.log."""
        if self.summary_log is None:
            return

        profileid = str(alert.profile)
        hostname = self.db.get_hostname_from_profile(profileid) or ""
        profile = alert.profile.ip
        if hostname:
            profile = f"{profile} ({hostname})"

        try:
            alert_time = utils.convert_ts_format(
                alert.last_flow_datetime, utils.alerts_format
            )
        except (TypeError, ValueError):
            alert_time = alert.last_flow_datetime

        entry = (
            f"{alert_time}: "
            f"Src IP {profile}. "
            f"Alert {alert.id} on timewindow {alert.timewindow.number}. "
            f"{summary_text}"
        )
        self.summary_log.write(f"{entry}\n")
        self.summary_log.flush()
        os.fsync(self.summary_log.fileno())
        self._log_operation(
            f"Wrote summary entry for alert_id={alert.id} "
            f"timewindow={alert.timewindow.number}",
            verbosity=LOG_VERBOSITY_REQUESTS,
        )

    def _log_operation(
        self, message: str, verbosity: int = LOG_VERBOSITY_REQUESTS
    ):
        """Append one line to the module operation log."""
        if self.operation_log is None:
            return
        if verbosity > self.log_verbosity:
            return

        timestamp = utils.get_human_readable_datetime()
        self.operation_log.write(f"{timestamp} {message}\n")
        self.operation_log.flush()
        os.fsync(self.operation_log.fileno())
