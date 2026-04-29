# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
import os
import re
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime
from typing import Any

from slips_files.common.abstracts.imodule import IModule
from slips_files.common.output_paths import get_alerts_path_inside_output_dir
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from slips_files.core.structures.alerts import dict_to_alert
from slips_files.core.structures.evidence import dict_to_evidence


PROMPT_VERSION = "alert-summary-v2"
LOG_VERBOSITY_SUMMARY = 1
LOG_VERBOSITY_REQUESTS = 2
LOG_VERBOSITY_DEBUG = 3
APPROX_CHARS_PER_TOKEN = 4
FINAL_PROMPT_INPUT_TOKEN_BUDGET = 3200
REDUCTION_PROMPT_INPUT_TOKEN_BUDGET = 2400
REDUCTION_MAX_TOKENS = 180
MAX_REDUCTION_DEPTH = 6
MAX_SAMPLE_VALUES = 5
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
REDUCTION_SYSTEM_PROMPT = """
You are compressing raw security evidence into a compact intermediate digest for a later analyst summary.
Use only the provided evidence subset.
Write exactly one plain-text paragraph.
Preserve concrete behaviors, time ranges, counts, suspicious indicators, and false-positive clues when they matter.
Do not invent missing facts and do not add introductions or meta-commentary.
""".strip()


class AlertSummary(IModule):
    name = "alert_summary"
    description = "Summarizes alerts for analysts using the shared LLM module"
    authors = ["OpenAI Codex"]

    def init(self):
        """Initialize channels, queues, and runtime configuration."""
        self.enabled = False
        self.allowed_backends = []
        self.llm_temperature = 0.2
        self.llm_max_tokens = 220
        self.llm_response_timeout_seconds = 120
        self.log_verbosity = LOG_VERBOSITY_REQUESTS
        self.pending_alerts = deque()
        self.active_job = None
        self.pending_request = None
        self.summary_log = None
        self.operation_log = None
        self.last_logged_pending_llm_requests = None
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
        """Drop privileges and initialize the output files if enabled."""
        utils.drop_root_privs_permanently()

        if not self.enabled:
            self.print("AlertSummary module disabled in config.", 2, 0)
            return True

        self._init_operation_log_file()
        self._init_summary_log_file()
        self._log_operation(
            "AlertSummary module ready. "
            f"summary_log={self.summary_log_path} "
            f"operation_log={self.operation_log_path} "
            f"prompt_version={PROMPT_VERSION}",
            verbosity=LOG_VERBOSITY_SUMMARY,
        )

    def should_stop(self) -> bool:
        """
        Stop once shutdown starts and this module has no actionable work left.

        We wait for both local work and the shared LLM service's requester-level
        in-flight counter. That keeps the module alive until every
        `requester=alert_summary` response has been published, even if local
        channel-tracker state is stale or replies were produced out of order.
        """
        if not self.termination_event.is_set():
            return False

        if self._has_pending_work():
            return False

        pending_llm_requests = self.db.get_pending_llm_request_count(self.name)
        if pending_llm_requests > 0:
            if self.last_logged_pending_llm_requests != pending_llm_requests:
                self._log_operation(
                    "Waiting for shared LLM responses before shutdown "
                    f"requester={self.name} pending_requests={pending_llm_requests}",
                    verbosity=LOG_VERBOSITY_SUMMARY,
                )
                self.last_logged_pending_llm_requests = pending_llm_requests
            return False

        self.last_logged_pending_llm_requests = None

        return not self.channel_tracker.get("new_alert", {}).get(
            "msg_received", False
        )

    def shutdown_gracefully(self):
        """Flush unresolved work to the summary file and close log handles."""
        if self.active_job:
            alert = self.active_job["alert"]
            self._write_summary_entry(
                alert,
                self._build_fallback_summary(
                    alert,
                    self.active_job["evidences"],
                    "Module stopped before the LLM reply was processed.",
                ),
            )
            self._log_operation(
                f"Shutdown flushed active alert_id={alert.id}.",
                verbosity=LOG_VERBOSITY_SUMMARY,
            )
            self.active_job = None
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
        """Queue alerts, process LLM replies, and advance the active job."""
        self._queue_new_alert()

        if self.pending_request:
            self._handle_pending_response()
            if self.pending_request:
                return

        if self.active_job:
            self._advance_active_job()
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

        self._start_next_alert_job(backend)

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
        """Parse and enqueue a new alert together with its evidence records."""
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

    def _start_next_alert_job(self, backend: str):
        """Create a multi-step summary job for the next queued alert."""
        queued_alert = self.pending_alerts.popleft()
        alert = queued_alert["alert"]
        evidences = queued_alert["evidences"]
        grouped_items = self._build_grouped_evidence_items(evidences)
        self.active_job = {
            "alert": alert,
            "evidences": evidences,
            "backend": backend,
            "grouped_item_count": len(grouped_items),
            "current_items": grouped_items,
            "reduction_layer": 0,
            "current_chunks": [],
            "completed_chunk_summaries": [],
        }
        self._log_operation(
            f"Started alert summary job alert_id={alert.id} "
            f"backend={backend} evidence_count={len(evidences)} "
            f"grouped_items={len(grouped_items)}",
            verbosity=LOG_VERBOSITY_REQUESTS,
        )
        self._advance_active_job()

    def _advance_active_job(self):
        """Dispatch the next LLM request for the active alert summary job."""
        if not self.active_job or self.pending_request:
            return

        job = self.active_job
        alert = job["alert"]
        final_messages = self._build_prompt_messages(
            alert,
            job["current_items"],
            len(job["evidences"]),
            job["grouped_item_count"],
            job["reduction_layer"],
        )
        final_token_estimate = self._estimate_messages_tokens(final_messages)
        self._log_operation(
            f"Evaluated final summary prompt alert_id={alert.id} "
            f"estimated_input_tokens={final_token_estimate} "
            f"budget={FINAL_PROMPT_INPUT_TOKEN_BUDGET} "
            f"reduction_layer={job['reduction_layer']} "
            f"digest_items={len(job['current_items'])}",
            verbosity=LOG_VERBOSITY_DEBUG,
        )
        if self._messages_fit(
            final_messages, FINAL_PROMPT_INPUT_TOKEN_BUDGET
        ):
            self._dispatch_llm_request(
                phase="final_summary",
                messages=final_messages,
                max_tokens=self.llm_max_tokens,
                metadata={
                    "alert_id": alert.id,
                    "profileid": str(alert.profile),
                    "timewindow": str(alert.timewindow),
                    "evidence_count": len(job["evidences"]),
                    "grouped_item_count": job["grouped_item_count"],
                    "digest_item_count": len(job["current_items"]),
                    "reduction_layer": job["reduction_layer"],
                    "prompt_version": PROMPT_VERSION,
                },
            )
            return

        if job["reduction_layer"] >= MAX_REDUCTION_DEPTH:
            self._fail_active_job(
                "Prompt remained too large after recursive evidence reduction."
            )
            return

        chunks = self._chunk_items_for_reduction(
            alert,
            job["current_items"],
            job["reduction_layer"],
        )
        if not chunks:
            self._fail_active_job(
                "Unable to build reduction chunks for alert summary."
            )
            return

        job["current_chunks"] = chunks
        job["completed_chunk_summaries"] = []
        self._log_operation(
            f"Starting reduction layer={job['reduction_layer'] + 1} "
            f"for alert_id={alert.id} chunks={len(chunks)} "
            f"source_items={len(job['current_items'])}",
            verbosity=LOG_VERBOSITY_REQUESTS,
        )
        self._dispatch_reduction_chunk(0)

    def _dispatch_reduction_chunk(self, chunk_index: int):
        """Send one evidence chunk for intermediate summarization."""
        job = self.active_job
        if not job:
            return

        chunk_items = job["current_chunks"][chunk_index]
        messages = self._build_reduction_messages(
            job["alert"],
            chunk_items,
            job["reduction_layer"] + 1,
            chunk_index + 1,
            len(job["current_chunks"]),
            len(job["current_items"]),
        )
        self._dispatch_llm_request(
            phase="reduction",
            messages=messages,
            max_tokens=REDUCTION_MAX_TOKENS,
            metadata={
                "alert_id": job["alert"].id,
                "profileid": str(job["alert"].profile),
                "timewindow": str(job["alert"].timewindow),
                "evidence_count": len(job["evidences"]),
                "grouped_item_count": job["grouped_item_count"],
                "digest_item_count": len(job["current_items"]),
                "reduction_layer": job["reduction_layer"] + 1,
                "chunk_index": chunk_index + 1,
                "chunk_count": len(job["current_chunks"]),
                "prompt_version": PROMPT_VERSION,
            },
        )

    def _dispatch_llm_request(
        self,
        phase: str,
        messages: list,
        max_tokens: int,
        metadata: dict,
    ):
        """Publish one LLM request for either reduction or final summarization."""
        if not self.active_job:
            return

        request_id = f"{self.name}-{uuid.uuid4()}"
        request = {
            "request_id": request_id,
            "requester": self.name,
            "backend": self.active_job["backend"],
            "messages": messages,
            "temperature": self.llm_temperature,
            "max_tokens": max_tokens,
            "metadata": metadata,
        }
        self.pending_request = {
            "request_id": request_id,
            "backend": self.active_job["backend"],
            "alert": self.active_job["alert"],
            "evidences": self.active_job["evidences"],
            "phase": phase,
            "sent_at": time.time(),
            "metadata": metadata,
        }

        try:
            self.db.publish(self.db.channels.LLM_REQUEST, json.dumps(request))
        except Exception:
            self.pending_request = None
            raise

        self._log_operation(
            f"Published llm_request request_id={request_id} "
            f"alert_id={self.active_job['alert'].id} "
            f"phase={phase} "
            f"backend={self.active_job['backend']} "
            f"max_tokens={max_tokens} "
            f"metadata={json.dumps(metadata, sort_keys=True)}",
            verbosity=LOG_VERBOSITY_REQUESTS,
        )

    def _build_prompt_messages(
        self,
        alert,
        evidence_items: list[str],
        evidence_count: int,
        grouped_item_count: int,
        reduction_layer: int,
    ) -> list:
        """
        Create the final analyst-summary prompt for one alert.

        :param alert: Alert being summarized.
        :param evidence_items: Grouped evidence lines or reduced digest items.
        :param evidence_count: Total evidence records attached to the alert.
        :param grouped_item_count: Count of grouped evidence patterns.
        :param reduction_layer: Number of prior reduction layers applied.
        :return: Chat messages for the shared LLM module.
        """
        user_prompt = (
            "You are a security analyst. Translate this Slips alert into one "
            "clear, concise paragraph for a human analyst.\n\n"
            f"{self._build_alert_metadata_text(alert, evidence_count, grouped_item_count, reduction_layer)}\n\n"
            "EVIDENCE DIGEST:\n"
            f"{self._format_digest_items(evidence_items)}\n\n"
            "YOUR TASK:\n"
            "1. Explain the main suspicious behavior in plain language.\n"
            "2. Identify the strongest evidence that supports or weakens the alert.\n"
            "3. State whether it looks like a likely true positive, likely false positive, or uncertain.\n"
            "4. State the likely operational risk or urgency.\n\n"
            "OUTPUT RULES:\n"
            "- Write exactly one paragraph.\n"
            "- Use plain text only.\n"
            "- Base the assessment only on the provided data.\n"
            "- If the evidence is repetitive, weak, incomplete, or contradictory, say so clearly.\n"
            f"- Prompt version: {PROMPT_VERSION}"
        )
        return [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]

    def _build_reduction_messages(
        self,
        alert,
        evidence_items: list[str],
        reduction_layer: int,
        chunk_index: int,
        chunk_count: int,
        source_item_count: int,
    ) -> list:
        """
        Create an intermediate reduction prompt for one evidence chunk.

        :param alert: Alert being summarized.
        :param evidence_items: Chunk items to compress further.
        :param reduction_layer: One-based reduction layer number.
        :param chunk_index: One-based chunk position in this layer.
        :param chunk_count: Total chunk count in this layer.
        :param source_item_count: Number of digest items before chunking.
        :return: Chat messages for the shared LLM module.
        """
        user_prompt = (
            "Compress this alert evidence subset into a compact intermediate "
            "digest for a later final analyst summary.\n\n"
            f"{self._build_alert_metadata_text(alert, len(self.active_job['evidences']), self.active_job['grouped_item_count'], reduction_layer - 1)}\n"
            f"Reduction layer: {reduction_layer}\n"
            f"Chunk: {chunk_index}/{chunk_count}\n"
            f"Source digest items in this layer: {source_item_count}\n\n"
            "EVIDENCE SUBSET:\n"
            f"{self._format_digest_items(evidence_items)}\n\n"
            "OUTPUT RULES:\n"
            "- Write exactly one paragraph.\n"
            "- Keep it shorter than the source evidence subset.\n"
            "- Preserve the most important behaviors, time ranges, counts, indicators, and false-positive clues.\n"
            "- Do not include introductions, bullet points, markdown, or JSON.\n"
            "- Do not make a final analyst verdict for the whole alert.\n"
            f"- Prompt version: {PROMPT_VERSION}"
        )
        return [
            {"role": "system", "content": REDUCTION_SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]

    def _build_alert_metadata_text(
        self,
        alert,
        evidence_count: int,
        grouped_item_count: int,
        reduction_layer: int,
    ) -> str:
        """
        Format the alert metadata section used by both prompt types.

        :param alert: Alert being summarized.
        :param evidence_count: Total evidence records attached to the alert.
        :param grouped_item_count: Count of grouped evidence patterns.
        :param reduction_layer: Number of completed reduction layers.
        :return: Multi-line metadata block.
        """
        profileid = str(alert.profile)
        hostname = self.db.get_hostname_from_profile(profileid) or ""
        profile = alert.profile.ip
        if hostname:
            profile = f"{profile} ({hostname})"

        start_time = self._format_timestamp_for_prompt(
            getattr(alert.timewindow, "start_time", "")
        )
        end_time = self._format_timestamp_for_prompt(
            getattr(alert.timewindow, "end_time", "")
        )
        if start_time and end_time:
            time_range = f"{start_time} to {end_time}"
        else:
            time_range = start_time or end_time or "Unknown"

        return (
            "INCIDENT METADATA:\n"
            f"- Alert ID: {alert.id}\n"
            f"- Source IP: {profile}\n"
            f"- Timewindow: {alert.timewindow.number}\n"
            f"- Time Range: {time_range}\n"
            f"- Accumulated Threat Level: {alert.accumulated_threat_level}\n"
            f"- Alert Confidence: {alert.confidence:.2f}\n"
            f"- Correlated Evidence Records: {evidence_count}\n"
            f"- Grouped Evidence Patterns: {grouped_item_count}\n"
            f"- Completed Reduction Layers: {reduction_layer}"
        )

    def _format_digest_items(self, evidence_items: list[str]) -> str:
        """
        Render grouped evidence or digest items for a prompt body.

        :param evidence_items: Items to format.
        :return: Multi-line evidence block.
        """
        if not evidence_items:
            return "- No evidence details were available."
        return "\n".join(f"- {item}" for item in evidence_items)

    def _build_grouped_evidence_items(self, evidences: list) -> list[str]:
        """
        Group similar evidence descriptions into prompt-friendly digest lines.

        :param evidences: Evidence records for one alert.
        :return: Ordered list of grouped evidence lines.
        """
        grouped_evidences = defaultdict(list)
        for evidence in evidences:
            description = str(getattr(evidence, "description", "") or "").strip()
            grouped_evidences[self._normalize_pattern(description)].append(
                evidence
            )

        summaries = []
        for _, group in grouped_evidences.items():
            group.sort(key=self._get_evidence_sort_key)
            first = group[0]
            first_time = self._format_short_time(first.timestamp)
            last_time = self._format_short_time(group[-1].timestamp)
            time_range = (
                f"{first_time}-{last_time}"
                if first_time and last_time and first_time != last_time
                else first_time or last_time or "time-unknown"
            )

            description = str(getattr(first, "description", "") or "").strip()
            sample_values = self._extract_sample_values(
                [
                    str(getattr(evidence, "description", "") or "")
                    for evidence in group[:3]
                ]
            )
            severity_counts = self._count_group_severities(group)
            severity_text = self._format_severity_counts(severity_counts)

            if len(group) == 1:
                line = f"{time_range} | {description}"
            else:
                line = (
                    f"{time_range} | {description} "
                    f"({len(group)}x similar"
                )
                if severity_text:
                    line += f", severities: {severity_text}"
                if sample_values:
                    line += (
                        ", samples: " + ", ".join(sample_values[:MAX_SAMPLE_VALUES])
                    )
                line += ")"

            summaries.append(
                {
                    "count": len(group),
                    "line": self._normalize_summary_text(line),
                    "sort_key": self._get_evidence_sort_key(first),
                }
            )

        summaries.sort(key=lambda item: (-item["count"], item["sort_key"]))
        return [item["line"] for item in summaries]

    def _normalize_pattern(self, description: str) -> str:
        """
        Normalize variable values in descriptions before grouping.

        :param description: Raw evidence description.
        :return: Normalized grouping key.
        """
        pattern = description
        pattern = re.sub(
            r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "<IP>", pattern
        )
        pattern = re.sub(
            r"\b\d+/(TCP|UDP)\b", r"<PORT>/\1", pattern, flags=re.IGNORECASE
        )
        pattern = re.sub(
            r"port[s]?:?\s*\d+(?:-\d+)?",
            "port <PORT>",
            pattern,
            flags=re.IGNORECASE,
        )
        pattern = re.sub(r"\b\d+\b", "<NUM>", pattern)
        return pattern

    def _extract_sample_values(self, descriptions: list[str]) -> list[str]:
        """
        Extract useful IP and port examples from grouped descriptions.

        :param descriptions: Raw evidence descriptions from one group.
        :return: Deduplicated example values.
        """
        sample_values = []
        for description in descriptions:
            sample_values.extend(
                re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", description)
            )
            sample_values.extend(
                [
                    f"{port}/{proto.upper()}"
                    for port, proto in re.findall(
                        r"\b(\d+)/(TCP|UDP)\b",
                        description,
                        flags=re.IGNORECASE,
                    )
                ]
            )

        unique_samples = []
        seen = set()
        for value in sample_values:
            if value in seen:
                continue
            seen.add(value)
            unique_samples.append(value)
        return unique_samples

    def _count_group_severities(self, evidences: list) -> dict:
        """
        Count threat levels inside one grouped evidence set.

        :param evidences: Evidence records in the group.
        :return: Severity count mapping.
        """
        severity_counts = {}
        for evidence in evidences:
            severity = str(getattr(evidence, "threat_level", "info")).lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        return severity_counts

    def _format_severity_counts(self, severity_counts: dict) -> str:
        """
        Format grouped severity counts for prompt readability.

        :param severity_counts: Severity count mapping.
        :return: Human-readable summary string.
        """
        ordered = ["critical", "high", "medium", "low", "info"]
        parts = []
        for severity in ordered:
            count = severity_counts.get(severity, 0)
            if count:
                parts.append(f"{severity}={count}")
        return ", ".join(parts)

    def _format_short_time(self, timestamp) -> str:
        """
        Convert a timestamp into HH:MM when possible.

        :param timestamp: Timestamp value in any Slips-supported format.
        :return: Short human-readable time.
        """
        iso_timestamp = self._convert_timestamp_to_iso(timestamp)
        if not iso_timestamp:
            return str(timestamp or "")

        try:
            parsed = datetime.fromisoformat(iso_timestamp)
        except ValueError:
            return str(timestamp or "")
        return parsed.strftime("%H:%M")

    def _format_timestamp_for_prompt(self, timestamp) -> str:
        """
        Convert a timestamp into the long prompt-friendly format.

        :param timestamp: Timestamp value in any Slips-supported format.
        :return: Prompt-friendly timestamp string.
        """
        iso_timestamp = self._convert_timestamp_to_iso(timestamp)
        if not iso_timestamp:
            return str(timestamp or "")

        try:
            parsed = datetime.fromisoformat(iso_timestamp)
        except ValueError:
            return str(timestamp or "")
        return parsed.strftime("%Y-%m-%d %H:%M:%S")

    def _convert_timestamp_to_iso(self, timestamp) -> str:
        """
        Convert a timestamp into ISO format when possible.

        :param timestamp: Timestamp value in any Slips-supported format.
        :return: ISO timestamp string or an empty string.
        """
        if timestamp in ("", None):
            return ""
        try:
            return str(utils.convert_ts_format(timestamp, "iso"))
        except (TypeError, ValueError):
            return ""

    def _chunk_items_for_reduction(
        self,
        alert,
        items: list[str],
        reduction_layer: int,
    ) -> list[list[str]]:
        """
        Split digest items into chunks that fit the reduction prompt budget.

        :param alert: Alert being summarized.
        :param items: Current digest items to reduce.
        :param reduction_layer: Zero-based current reduction layer.
        :return: List of chunks, each chunk being a list of digest items.
        """
        expanded_items = []
        for item in items:
            if self._single_item_fits_reduction_prompt(
                alert, item, reduction_layer
            ):
                expanded_items.append(item)
                continue

            split_items = self._split_item_for_reduction(
                alert,
                item,
                reduction_layer,
            )
            self._log_operation(
                f"Split oversized digest item for alert_id={alert.id} "
                f"layer={reduction_layer + 1} "
                f"parts={len(split_items)}",
                verbosity=LOG_VERBOSITY_REQUESTS,
            )
            expanded_items.extend(split_items)

        chunks = []
        current_chunk = []
        for item in expanded_items:
            trial_chunk = current_chunk + [item]
            if current_chunk and not self._chunk_fits_reduction_prompt(
                alert,
                trial_chunk,
                reduction_layer,
                len(items),
            ):
                chunks.append(current_chunk)
                current_chunk = [item]
                continue
            current_chunk = trial_chunk

        if current_chunk:
            chunks.append(current_chunk)
        return chunks

    def _single_item_fits_reduction_prompt(
        self,
        alert,
        item: str,
        reduction_layer: int,
    ) -> bool:
        """
        Check whether one digest item fits in a reduction prompt.

        :param alert: Alert being summarized.
        :param item: One digest item to test.
        :param reduction_layer: Zero-based current reduction layer.
        :return: True when the item fits without splitting.
        """
        return self._chunk_fits_reduction_prompt(
            alert,
            [item],
            reduction_layer,
            1,
        )

    def _chunk_fits_reduction_prompt(
        self,
        alert,
        items: list[str],
        reduction_layer: int,
        source_item_count: int,
    ) -> bool:
        """
        Estimate whether a chunk fits the reduction prompt budget.

        :param alert: Alert being summarized.
        :param items: Candidate chunk items.
        :param reduction_layer: Zero-based current reduction layer.
        :param source_item_count: Number of source digest items in this layer.
        :return: True when the prompt estimate fits the configured budget.
        """
        messages = self._build_reduction_messages(
            alert,
            items,
            reduction_layer + 1,
            1,
            1,
            source_item_count,
        )
        return self._messages_fit(
            messages, REDUCTION_PROMPT_INPUT_TOKEN_BUDGET
        )

    def _split_item_for_reduction(
        self,
        alert,
        item: str,
        reduction_layer: int,
    ) -> list[str]:
        """
        Split one oversized digest item into smaller parts without truncating.

        :param alert: Alert being summarized.
        :param item: Oversized digest item text.
        :param reduction_layer: Zero-based current reduction layer.
        :return: List of smaller digest items.
        """
        empty_messages = self._build_reduction_messages(
            alert,
            [],
            reduction_layer + 1,
            1,
            1,
            1,
        )
        overhead_tokens = self._estimate_messages_tokens(empty_messages)
        available_tokens = max(
            120,
            REDUCTION_PROMPT_INPUT_TOKEN_BUDGET - overhead_tokens - 64,
        )
        parts = self._split_text_to_budget(item, available_tokens)
        if len(parts) == 1:
            return parts
        return [
            f"{part} (continued segment {index}/{len(parts)})"
            for index, part in enumerate(parts, start=1)
        ]

    def _split_text_to_budget(
        self,
        text: str,
        token_budget: int,
    ) -> list[str]:
        """
        Split a text block by sentence and word boundaries to fit a budget.

        :param text: Input text to split.
        :param token_budget: Approximate token budget per part.
        :return: Ordered list of text parts.
        """
        normalized = self._normalize_summary_text(text)
        if self._estimate_text_tokens(normalized) <= token_budget:
            return [normalized]

        for separator in ("\n", "; ", ". ", ", "):
            parts = self._split_text_by_separator(
                normalized,
                separator,
                token_budget,
            )
            if len(parts) > 1 and all(
                self._estimate_text_tokens(part) <= token_budget
                for part in parts
            ):
                return parts

        return self._split_text_by_words(normalized, token_budget)

    def _split_text_by_separator(
        self,
        text: str,
        separator: str,
        token_budget: int,
    ) -> list[str]:
        """
        Try to split a text block on one separator while honoring a budget.

        :param text: Input text to split.
        :param separator: Separator to preserve between pieces.
        :param token_budget: Approximate token budget per part.
        :return: Split text parts.
        """
        raw_parts = [part.strip() for part in text.split(separator) if part.strip()]
        if len(raw_parts) <= 1:
            return [text]

        merged_parts = []
        current = ""
        for part in raw_parts:
            candidate = part if not current else f"{current}{separator}{part}"
            if self._estimate_text_tokens(candidate) <= token_budget:
                current = candidate
                continue
            if current:
                merged_parts.append(current)
            current = part

        if current:
            merged_parts.append(current)
        return merged_parts

    def _split_text_by_words(
        self,
        text: str,
        token_budget: int,
    ) -> list[str]:
        """
        Split a text block by words when coarser separators are not enough.

        :param text: Input text to split.
        :param token_budget: Approximate token budget per part.
        :return: Split text parts.
        """
        words = text.split()
        if not words:
            return [text]

        parts = []
        current_words = []
        for word in words:
            candidate_words = current_words + [word]
            candidate = " ".join(candidate_words)
            if current_words and self._estimate_text_tokens(candidate) > token_budget:
                parts.append(" ".join(current_words))
                current_words = [word]
                continue
            current_words = candidate_words

        if current_words:
            parts.append(" ".join(current_words))
        return parts

    def _estimate_messages_tokens(self, messages: list[dict]) -> int:
        """
        Estimate the input token count for a message list.

        :param messages: Chat messages to estimate.
        :return: Approximate token count.
        """
        token_count = 0
        for message in messages:
            token_count += 12
            token_count += self._estimate_text_tokens(message.get("content", ""))
        return token_count

    def _estimate_text_tokens(self, text: str) -> int:
        """
        Estimate token count from text length using a conservative heuristic.

        :param text: Input text to estimate.
        :return: Approximate token count.
        """
        normalized = str(text or "")
        return max(1, (len(normalized) + APPROX_CHARS_PER_TOKEN - 1) // APPROX_CHARS_PER_TOKEN)

    def _messages_fit(self, messages: list[dict], budget: int) -> bool:
        """
        Return True when the prompt estimate fits the chosen budget.

        :param messages: Chat messages to estimate.
        :param budget: Maximum estimated input tokens.
        :return: True when the prompt should fit.
        """
        return self._estimate_messages_tokens(messages) <= budget

    def _handle_pending_response(self):
        """Consume the matching shared LLM response or wait for shutdown."""
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

        if self.termination_event.is_set():
            if not self.pending_request.get("shutdown_wait_logged", False):
                self._log_operation(
                    "Shutdown is in progress; keeping alert_summary alive "
                    f"for in-flight request_id={self.pending_request['request_id']} "
                    "until the shared LLM module replies.",
                    verbosity=LOG_VERBOSITY_SUMMARY,
                )
                self.pending_request["shutdown_wait_logged"] = True
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
        """
        Continue the reduction pipeline or write the final alert summary.

        :param response: Shared LLM response payload.
        :return: None
        """
        request = self.pending_request
        job = self.active_job
        if not request or not job:
            return

        phase = request["phase"]
        usage = response.get("usage") or {}
        usage_suffix = (
            " "
            f"usage={json.dumps(usage, sort_keys=True)}"
            if usage
            else ""
        )

        if response.get("success") and str(response.get("text", "")).strip():
            text = self._normalize_summary_text(response["text"])
            if phase == "final_summary":
                self._write_summary_entry(job["alert"], f"LLM summary: {text}")
                self._log_operation(
                    f"Received successful llm_response request_id={request['request_id']} "
                    f"alert_id={job['alert'].id} phase={phase}{usage_suffix}",
                    verbosity=LOG_VERBOSITY_REQUESTS,
                )
                self.pending_request = None
                self.active_job = None
                return

            job["completed_chunk_summaries"].append(text)
            chunk_index = int(request["metadata"].get("chunk_index", 1))
            chunk_count = int(request["metadata"].get("chunk_count", 1))
            self._log_operation(
                f"Received reduction digest request_id={request['request_id']} "
                f"alert_id={job['alert'].id} "
                f"layer={request['metadata'].get('reduction_layer')} "
                f"chunk={chunk_index}/{chunk_count}{usage_suffix}",
                verbosity=LOG_VERBOSITY_REQUESTS,
            )
            self.pending_request = None

            if chunk_index < chunk_count:
                self._dispatch_reduction_chunk(chunk_index)
                return

            job["current_items"] = job["completed_chunk_summaries"]
            job["completed_chunk_summaries"] = []
            job["current_chunks"] = []
            job["reduction_layer"] += 1
            self._log_operation(
                f"Completed reduction layer={job['reduction_layer']} "
                f"for alert_id={job['alert'].id} "
                f"resulting_digest_items={len(job['current_items'])}",
                verbosity=LOG_VERBOSITY_REQUESTS,
            )
            self._advance_active_job()
            return

        error = str(response.get("error", "Unknown LLM summary failure."))
        self._log_operation(
            f"LLM request failed for alert_id={job['alert'].id} "
            f"phase={phase}: {error}",
            verbosity=LOG_VERBOSITY_SUMMARY,
        )
        self._fail_active_job(error)

    def _normalize_summary_text(self, text: str) -> str:
        """
        Collapse any multi-line reply into one plain-text paragraph.

        :param text: Raw model response.
        :return: Single-paragraph normalized text.
        """
        normalized = " ".join(str(text or "").split())
        return normalized.strip()

    def _has_pending_work(self) -> bool:
        """
        Return True when alert summaries still require processing.

        :return: True while alerts are queued or in-flight.
        """
        return bool(self.pending_alerts or self.active_job or self.pending_request)

    def _fail_active_job(self, reason: str):
        """
        Write a fallback summary for the active alert and clear its state.

        :param reason: Why the LLM pipeline failed.
        :return: None
        """
        if not self.active_job:
            return

        alert = self.active_job["alert"]
        self._write_summary_entry(
            alert,
            self._build_fallback_summary(
                alert,
                self.active_job["evidences"],
                reason,
            ),
        )
        self.pending_request = None
        self.active_job = None

    def _flush_queued_alerts_without_backend(self, reason: str):
        """Write failure notes for queued alerts when shutdown happens first."""
        while self.pending_alerts:
            queued_alert = self.pending_alerts.popleft()
            self._write_summary_entry(
                queued_alert["alert"],
                self._build_fallback_summary(
                    queued_alert["alert"],
                    queued_alert["evidences"],
                    reason,
                ),
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

    def _build_fallback_summary(
        self,
        alert,
        evidences: list,
        reason: str,
    ) -> str:
        """
        Generate a local one-paragraph summary when the LLM path fails.

        :param alert: Alert being summarized.
        :param evidences: Evidence records correlated with the alert.
        :param reason: Why the LLM summary was unavailable.
        :return: Single-paragraph fallback summary.
        """
        severity_counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
        for evidence in evidences:
            severity = str(getattr(evidence, "threat_level", "info")).lower()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        grouped_items = self._build_grouped_evidence_items(evidences)
        strongest_indicators = "; ".join(grouped_items[:3]) or (
            "the correlated evidence set"
        )

        verdict = self._classify_alert_verdict(
            alert,
            evidences,
            severity_counts,
        )
        risk = self._classify_alert_risk(alert, severity_counts)
        return (
            f"LLM summary unavailable ({reason}). "
            f"Local heuristic summary: this alert correlates {len(evidences)} "
            f"evidence records for source IP {alert.profile.ip}, with the "
            f"strongest indicators being {strongest_indicators}. "
            f"The evidence mix includes {severity_counts.get('high', 0)} high, "
            f"{severity_counts.get('medium', 0)} medium, "
            f"{severity_counts.get('low', 0)} low, and "
            f"{severity_counts.get('info', 0)} informational findings. "
            f"Based on the accumulated threat level "
            f"{alert.accumulated_threat_level:.2f} and confidence "
            f"{alert.confidence:.2f}, this looks {verdict} and the "
            f"operational risk appears {risk}."
        )

    def _classify_alert_verdict(
        self,
        alert,
        evidences: list,
        severity_counts: dict,
    ) -> str:
        """
        Estimate the analyst verdict for a fallback summary.

        :param alert: Alert being summarized.
        :param evidences: Evidence records correlated with the alert.
        :param severity_counts: Count of evidence severities.
        :return: Human-readable verdict label.
        """
        if severity_counts.get("high", 0) >= 3 or alert.confidence >= 0.8:
            return "like a likely true positive"
        if (
            evidences
            and severity_counts.get("info", 0) >= len(evidences)
            and alert.confidence < 0.4
        ):
            return "uncertain and may be a false positive"
        if alert.confidence >= 0.5 or severity_counts.get("medium", 0) >= 2:
            return "concerning but still somewhat uncertain"
        return "uncertain"

    def _classify_alert_risk(
        self,
        alert,
        severity_counts: dict,
    ) -> str:
        """
        Estimate operational risk for a fallback summary.

        :param alert: Alert being summarized.
        :param severity_counts: Count of evidence severities.
        :return: Risk label for the summary paragraph.
        """
        if severity_counts.get("high", 0) >= 3 or alert.accumulated_threat_level >= 10:
            return "high"
        if severity_counts.get("medium", 0) >= 2 or alert.accumulated_threat_level >= 5:
            return "medium"
        return "low"
