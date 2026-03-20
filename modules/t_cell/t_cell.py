# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
import os
import re
import time
from dataclasses import dataclass
from urllib.parse import urlparse

from modules.regex_generator.match_strength import (
    compute_match_strength,
    measure_regex_specificity,
)
from slips_files.common.abstracts.imodule import IModule
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from slips_files.core.structures.evidence import (
    EvidenceSignal,
    IoCType,
    dict_to_evidence,
)

STATE_MATURE = 0
STATE_ANTIGEN_RECOGNIZED = 1
STATE_ANERGIC = 2
STATE_ACTIVATED = 3
STATE_EFFECTOR = 4
STATE_MEMORY = 5

STATE_INFO = {
    STATE_MATURE: {"label": "0 - mature", "color": "\033[36m"},
    STATE_ANTIGEN_RECOGNIZED: {
        "label": "1 - antigen-recognized",
        "color": "\033[33m",
    },
    STATE_ANERGIC: {"label": "2 - anergic", "color": "\033[34m"},
    STATE_ACTIVATED: {"label": "3 - activated", "color": "\033[35m"},
    STATE_EFFECTOR: {"label": "4 - effector", "color": "\033[31m"},
    STATE_MEMORY: {"label": "5 - memory", "color": "\033[32m"},
}
COLOR_RESET = "\033[0m"
SUPPORTED_REGEX_TYPES = (
    "dns_domain",
    "uri",
    "filename",
    "tls_sni",
    "certificate_cn",
)
DEFAULT_COSTIM_WEIGHTS = {
    "confidence": 0.35,
    "related_pamps": 0.25,
    "danger": 0.40,
}
LOG_VERBOSITY_SUMMARY = 1
LOG_VERBOSITY_DECISIONS = 2
LOG_VERBOSITY_DEBUG = 3


@dataclass(frozen=True)
class AntigenCandidate:
    regex_type: str
    value: str

    def as_dict(self) -> dict:
        return {"regex_type": self.regex_type, "value": self.value}


@dataclass(frozen=True)
class RegexMatch:
    regex_type: str
    value: str
    regex_hash: str
    regex: str
    created_at: float
    specificity: float

    def as_dict(self) -> dict:
        return {
            "regex_type": self.regex_type,
            "value": self.value,
            "regex_hash": self.regex_hash,
            "regex": self.regex,
            "created_at": self.created_at,
            "specificity": self.specificity,
        }


class TCell(IModule):
    name = "T Cell"
    description = (
        "Immune-style responder that matches PAMP antigens to regexes and "
        "uses both PAMP and DAMP danger pressure to escalate to blocking "
        "or memory."
    )
    authors = ["OpenAI Codex"]

    def init(self):
        self.c_evidence = self.db.subscribe("evidence_added")
        self.channels = {"evidence_added": self.c_evidence}
        self.enabled = False
        self.create_log_file = True
        self.log_colors = True
        self.log_verbosity = LOG_VERBOSITY_SUMMARY
        self.log_file_path = os.path.join(self.output_dir, "t_cell.log")
        self.storage = None
        self.state_wait_timeout_seconds = 3600.0
        self.observation_retention_seconds = 604800
        self.anergy_ttl_seconds = 21600
        self.related_lookback_seconds = 3600
        self.related_pamps_saturation = 5.0
        self.danger_saturation = 2.5
        self.damp_danger_weight = 1.5
        self.co_stimulation_threshold = 0.65
        self.co_stimulation_weights = DEFAULT_COSTIM_WEIGHTS.copy()
        self.novelty_window_seconds = 86400
        self.context_recent_window_seconds = 1800
        self.effector_threshold = 0.70
        self.effector_min_related_count = 4
        self.effector_cooldown_seconds = 1800
        self.memory_threshold = 0.60
        self.memory_trend_ratio_max = 0.60
        self.memory_min_related_count = 3
        self.simulate_effector_without_blocking = True
        self.read_configuration()

    def read_configuration(self):
        conf = self.conf if hasattr(self.conf, "t_cell_enabled") else ConfigParser()
        self.enabled = conf.t_cell_enabled()
        self.create_log_file = conf.t_cell_create_log_file()
        self.log_colors = conf.t_cell_log_colors()
        self.log_verbosity = conf.t_cell_log_verbosity()
        try:
            self.state_wait_timeout_seconds = float(
                conf.get_tw_width_in_seconds()
            )
        except Exception:
            self.state_wait_timeout_seconds = 3600.0
        self.observation_retention_seconds = (
            conf.t_cell_observation_retention_seconds()
        )
        self.anergy_ttl_seconds = conf.t_cell_anergy_ttl_seconds()
        self.related_lookback_seconds = conf.t_cell_related_lookback_seconds()
        self.related_pamps_saturation = conf.t_cell_related_pamps_saturation()
        self.danger_saturation = conf.t_cell_danger_saturation()
        self.damp_danger_weight = conf.t_cell_damp_danger_weight()
        self.co_stimulation_threshold = conf.t_cell_co_stimulation_threshold()
        self.co_stimulation_weights = self._normalize_weights(
            conf.t_cell_co_stimulation_weights()
        )
        self.novelty_window_seconds = conf.t_cell_novelty_window_seconds()
        self.context_recent_window_seconds = (
            conf.t_cell_context_recent_window_seconds()
        )
        self.effector_threshold = conf.t_cell_effector_threshold()
        self.effector_min_related_count = (
            conf.t_cell_effector_min_related_count()
        )
        self.effector_cooldown_seconds = (
            conf.t_cell_effector_cooldown_seconds()
        )
        self.memory_threshold = conf.t_cell_memory_threshold()
        self.memory_trend_ratio_max = conf.t_cell_memory_trend_ratio_max()
        self.memory_min_related_count = conf.t_cell_memory_min_related_count()
        self.simulate_effector_without_blocking = (
            conf.t_cell_simulate_effector_without_blocking()
        )

    def pre_main(self):
        utils.drop_root_privs_permanently()
        if not self.enabled:
            self.print("T Cell module disabled in config.", 2, 0)
            return True

        self.storage = self.db.get_t_cell_storage()
        self._init_log_file()
        self._log_detail("T Cell module ready.")
        return False

    def shutdown_gracefully(self):
        return True

    def main(self):
        if msg := self.get_msg("evidence_added"):
            self._process_evidence_message(msg)
        return False

    @staticmethod
    def _normalize_weights(weights: dict) -> dict:
        sanitized = {}
        for key, default_value in DEFAULT_COSTIM_WEIGHTS.items():
            raw_value = weights.get(key, default_value)
            try:
                raw_value = float(raw_value)
            except (TypeError, ValueError):
                raw_value = default_value
            sanitized[key] = max(0.0, raw_value)

        total = sum(sanitized.values())
        if total <= 0:
            total = sum(DEFAULT_COSTIM_WEIGHTS.values())
            sanitized = DEFAULT_COSTIM_WEIGHTS.copy()
        return {key: value / total for key, value in sanitized.items()}

    def _process_evidence_message(self, message: dict):
        try:
            raw_evidence = json.loads(message["data"])
            evidence = dict_to_evidence(raw_evidence)
        except Exception:
            self.print_traceback()
            return

        now = time.time()
        responsible_ip = self._get_responsible_ip(evidence)
        antigens = self._extract_antigen_candidates(evidence)
        if antigens:
            self._log_event(
                action="antigens_extracted",
                state=None,
                evidence=evidence,
                details=(
                    "antigens="
                    + ", ".join(
                        f"{candidate.regex_type}:{candidate.value}"
                        for candidate in antigens
                    )
                ),
                verbosity=LOG_VERBOSITY_DEBUG,
            )
        observation_id = self.storage.insert_observation(
            {
                "evidence_id": evidence.id,
                "evidence_type": str(evidence.evidence_type),
                "evidence_signal": str(evidence.evidence_signal),
                "profile_ip": responsible_ip,
                "timewindow_number": evidence.timewindow.number,
                "timestamp": evidence.timestamp,
                "observed_at": now,
                "confidence": evidence.confidence,
                "threat_level": str(evidence.threat_level),
                "threat_level_value": float(evidence.threat_level.value),
                "interface": evidence.interface,
                "uids": evidence.uid,
                "antigen_count": len(antigens),
                "antigens": [candidate.as_dict() for candidate in antigens],
                "matched_regexes": [],
                "raw_evidence": raw_evidence,
            }
        )
        matched_regexes = []

        if evidence.evidence_signal != EvidenceSignal.PAMP:
            self._log_event(
                action="ignored_non_pamp",
                state=None,
                evidence=evidence,
                details=f"signal={evidence.evidence_signal}",
                verbosity=LOG_VERBOSITY_DECISIONS,
            )
            self._prune_observations(now)
            return

        if not antigens:
            self._log_event(
                action="no_antigen_extracted",
                state=None,
                evidence=evidence,
                details=(
                    "no supported dns_domain/uri/filename/tls_sni/"
                    "certificate_cn values found"
                ),
                verbosity=LOG_VERBOSITY_DECISIONS,
            )
            self._prune_observations(now)
            return

        for candidate in antigens:
            match = self._process_candidate(
                evidence,
                observation_id,
                candidate,
                now,
                responsible_ip,
            )
            if match:
                matched_regexes.append(match.as_dict())

        self.storage.update_observation_matches(observation_id, matched_regexes)
        self._prune_observations(now)

    def _process_candidate(
        self,
        evidence,
        observation_id: int,
        candidate: AntigenCandidate,
        now: float,
        responsible_ip: str,
    ) -> RegexMatch | None:
        cell = self._get_or_create_cell(
            responsible_ip, candidate.regex_type, candidate.value, now
        )

        if (
            cell["state"] == STATE_ANERGIC
            and cell.get("anergic_until")
            and now < cell["anergic_until"]
        ):
            self._log_event(
                action="anergy_suppressed",
                state=cell["state"],
                evidence=evidence,
                cell=cell,
                details=f"until={cell['anergic_until']:.3f}",
                verbosity=LOG_VERBOSITY_DECISIONS,
            )
            return None

        if (
            cell["state"] == STATE_ANERGIC
            and cell.get("anergic_until")
            and now >= cell["anergic_until"]
        ):
            cell = self._transition_cell(
                cell=cell,
                to_state=STATE_MATURE,
                reason="anergy_expired",
                evidence=evidence,
                observation_id=observation_id,
                now=now,
                scores={"anergic_until": None},
                extra_updates={"anergic_until": None},
            )

        match = self._find_best_regex_match(candidate)
        if not match:
            if cell["state"] == STATE_MATURE:
                cell = self._transition_cell(
                    cell=cell,
                    to_state=STATE_ANERGIC,
                    reason="no_regex_match",
                    evidence=evidence,
                    observation_id=observation_id,
                    now=now,
                    scores={"anergic_until": now + self.anergy_ttl_seconds},
                    extra_updates={"anergic_until": now + self.anergy_ttl_seconds},
                )
            else:
                self._update_cell(
                    cell,
                    now,
                    last_observation_id=observation_id,
                    last_evidence_id=evidence.id,
                    context={
                        "reason": "no_regex_match_after_activation",
                        "observation_id": observation_id,
                    },
                )
                self._log_event(
                    action="no_regex_match",
                    state=cell["state"],
                    evidence=evidence,
                    cell=cell,
                    details=(
                        "cell already active; keeping current state without "
                        "a new regex match"
                    ),
                    verbosity=LOG_VERBOSITY_DECISIONS,
                )
            return None

        match_updates = {
            "matched_regex_hash": match.regex_hash,
            "matched_regex": match.regex,
            "matched_value": match.value,
            "last_observation_id": observation_id,
            "last_evidence_id": evidence.id,
            "anergic_until": None,
        }
        if cell["state"] == STATE_MATURE:
            cell = self._transition_cell(
                cell=cell,
                to_state=STATE_ANTIGEN_RECOGNIZED,
                reason="antigen_recognized",
                evidence=evidence,
                observation_id=observation_id,
                now=now,
                match=match,
                scores={"regex_specificity": match.specificity},
                extra_updates=match_updates,
            )
        else:
            cell = self._update_cell(
                cell,
                now,
                **match_updates,
            )

        if cell["state"] == STATE_MEMORY:
            self._update_cell(
                cell,
                now,
                context={
                    "reason": "memory_retained",
                    "observation_id": observation_id,
                    "matched_regex_hash": match.regex_hash,
                },
            )
            self._log_event(
                action="memory_retained",
                state=STATE_MEMORY,
                evidence=evidence,
                cell=cell,
                match=match,
                details=(
                    "memory already exists for this cell; keeping the memory "
                    "state without storing a new memory event"
                ),
                verbosity=LOG_VERBOSITY_DEBUG,
            )
            return match

        co_stimulation = self._compute_co_stimulation(
            responsible_ip,
            observation_id,
            candidate,
            match,
            now,
        )
        cell = self._update_cell(
            cell,
            now,
            last_co_stimulation=co_stimulation["value"],
            context={"co_stimulation": co_stimulation},
        )

        if cell["state"] < STATE_ACTIVATED:
            wait_elapsed = self._get_state_wait_elapsed(cell, now)
            if co_stimulation["value"] >= self.co_stimulation_threshold:
                cell = self._transition_cell(
                    cell=cell,
                    to_state=STATE_ACTIVATED,
                    reason="co_stimulation_threshold_met",
                    evidence=evidence,
                    observation_id=observation_id,
                    now=now,
                    match=match,
                    scores=co_stimulation,
                )
            elif (
                cell["state"] == STATE_ANTIGEN_RECOGNIZED
                and self._state_wait_expired(cell, now)
            ):
                cell = self._transition_cell(
                    cell=cell,
                    to_state=STATE_ANERGIC,
                    reason="co_stimulation_timeout",
                    evidence=evidence,
                    observation_id=observation_id,
                    now=now,
                    match=match,
                    scores={
                        **co_stimulation,
                        "elapsed": wait_elapsed,
                        "wait_limit": self.state_wait_timeout_seconds,
                        "anergic_until": now + self.anergy_ttl_seconds,
                    },
                    extra_updates={
                        "anergic_until": now + self.anergy_ttl_seconds,
                    },
                )
                return match
            else:
                self._log_event(
                    action="waiting_for_co_stimulation",
                    state=cell["state"],
                    evidence=evidence,
                    cell=cell,
                    match=match,
                    details=(
                        "score below threshold; keeping the cell in "
                        "antigen-recognized state until more corroborating "
                        "PAMPs arrive"
                    ),
                    metrics={
                        "score": co_stimulation["value"],
                        "threshold": co_stimulation["threshold"],
                        "gap": max(
                            0.0,
                            co_stimulation["threshold"]
                            - co_stimulation["value"],
                        ),
                        "confidence": co_stimulation["confidence"],
                        "related_pamps": co_stimulation["related_pamp_count"],
                        "related_score": co_stimulation["related_pamp_score"],
                        "danger_score": co_stimulation["profile_danger_score"],
                        "pamp_danger": co_stimulation["pamp_danger_score"],
                        "damp_danger": co_stimulation["damp_danger_score"],
                        "damp_weight": co_stimulation["damp_danger_weight"],
                        "elapsed": wait_elapsed,
                        "wait_limit": self.state_wait_timeout_seconds,
                    },
                    verbosity=LOG_VERBOSITY_DECISIONS,
                )
                return match

        context = self._compute_context_signals(
            responsible_ip,
            observation_id,
            candidate,
            match,
            now,
        )
        cell = self._update_cell(
            cell,
            now,
            last_effector_score=context["effector_score"],
            last_memory_score=context["memory_score"],
            context={"co_stimulation": co_stimulation, "context": context},
        )

        if context["effector"]:
            if cell["state"] != STATE_EFFECTOR:
                cell = self._transition_cell(
                    cell=cell,
                    to_state=STATE_EFFECTOR,
                    reason="context_effector",
                    evidence=evidence,
                    observation_id=observation_id,
                    now=now,
                    match=match,
                    scores=context,
                )
            self._apply_effector(
                cell,
                evidence,
                match,
                context,
                now,
                responsible_ip,
            )
            return match

        if context["memory"]:
            if cell["state"] != STATE_MEMORY:
                cell = self._transition_cell(
                    cell=cell,
                    to_state=STATE_MEMORY,
                    reason="context_memory",
                    evidence=evidence,
                    observation_id=observation_id,
                    now=now,
                    match=match,
                    scores=context,
                )
            self._store_memory(cell, match, context, now)
            self._log_event(
                action="memory_stored",
                state=STATE_MEMORY,
                evidence=evidence,
                cell=cell,
                match=match,
                metrics={"memory_score": context["memory_score"]},
                verbosity=LOG_VERBOSITY_SUMMARY,
            )
            return match

        wait_elapsed = self._get_state_wait_elapsed(cell, now)
        if (
            cell["state"] == STATE_ACTIVATED
            and self._state_wait_expired(cell, now)
        ):
            self._transition_cell(
                cell=cell,
                to_state=STATE_MATURE,
                reason="context_timeout",
                evidence=evidence,
                observation_id=observation_id,
                now=now,
                match=match,
                scores={
                    **context,
                    "elapsed": wait_elapsed,
                    "wait_limit": self.state_wait_timeout_seconds,
                },
            )
            return match

        self._log_event(
            action="waiting_for_context",
            state=cell["state"],
            evidence=evidence,
            cell=cell,
            match=match,
            details=(
                "context is not strong enough yet for effector or memory; "
                "keeping the current state and reevaluating on future PAMPs"
            ),
            metrics={
                "effector_score": context["effector_score"],
                "effector_threshold": context["effector_threshold"],
                "memory_score": context["memory_score"],
                "memory_threshold": context["memory_threshold"],
                "novelty_score": context["novelty_score"],
                "related_pamps": context["recent_related_count"],
                "recent_pamp_pressure": context["recent_pamp_pressure"],
                "recent_damp_pressure": context["recent_damp_pressure"],
                "previous_pamp_pressure": context["previous_pamp_pressure"],
                "previous_damp_pressure": context["previous_damp_pressure"],
                "damp_weight": context["damp_danger_weight"],
                "trend_ratio": context["trend_ratio"],
                "elapsed": wait_elapsed,
                "wait_limit": self.state_wait_timeout_seconds,
            },
            verbosity=LOG_VERBOSITY_DECISIONS,
        )
        return match

    def _get_or_create_cell(
        self, profile_ip: str, regex_type: str, antigen_value: str, now: float
    ) -> dict:
        cell_key = self._make_cell_key(profile_ip, regex_type, antigen_value)
        cell = self.storage.get_cell(cell_key)
        if cell:
            return cell

        return {
            "cell_key": cell_key,
            "profile_ip": profile_ip,
            "regex_type": regex_type,
            "antigen_value": antigen_value,
            "state": STATE_MATURE,
            "state_name": STATE_INFO[STATE_MATURE]["label"],
            "matched_regex_hash": None,
            "matched_regex": None,
            "matched_value": None,
            "anergic_until": None,
            "effector_cooldown_until": None,
            "last_observation_id": None,
            "last_evidence_id": None,
            "last_transition_at": None,
            "last_co_stimulation": None,
            "last_effector_score": None,
            "last_memory_score": None,
            "context": {},
            "created_at": now,
            "updated_at": now,
        }

    def _transition_cell(
        self,
        cell: dict,
        to_state: int,
        reason: str,
        evidence,
        observation_id: int,
        now: float,
        match: RegexMatch | None = None,
        scores: dict | None = None,
        extra_updates: dict | None = None,
    ) -> dict:
        from_state = cell["state"]
        updates = {
            "state": to_state,
            "state_name": STATE_INFO[to_state]["label"],
            "last_observation_id": observation_id,
            "last_evidence_id": evidence.id,
            "last_transition_at": now,
        }
        if match:
            updates.update(
                {
                    "matched_regex_hash": match.regex_hash,
                    "matched_regex": match.regex,
                    "matched_value": match.value,
                }
            )
        if extra_updates:
            updates.update(extra_updates)

        cell = self._update_cell(cell, now, **updates)
        self.storage.insert_transition(
            {
                "cell_key": cell["cell_key"],
                "profile_ip": cell["profile_ip"],
                "regex_type": cell["regex_type"],
                "antigen_value": cell["antigen_value"],
                "evidence_id": evidence.id,
                "observation_id": observation_id,
                "from_state": from_state,
                "to_state": to_state,
                "reason": reason,
                "matched_regex_hash": cell.get("matched_regex_hash"),
                "matched_regex": cell.get("matched_regex"),
                "matched_value": cell.get("matched_value"),
                "scores": scores or {},
                "created_at": now,
            }
        )
        self._log_event(
            action=reason,
            state=to_state,
            evidence=evidence,
            cell=cell,
            match=match,
            metrics=scores,
            verbosity=LOG_VERBOSITY_SUMMARY,
        )
        return cell

    def _update_cell(self, cell: dict, now: float, **updates) -> dict:
        cell.update(updates)
        cell["updated_at"] = now
        self.storage.upsert_cell(cell)
        return cell

    def _compute_co_stimulation(
        self,
        profile_ip: str,
        observation_id: int,
        candidate: AntigenCandidate,
        match: RegexMatch,
        now: float,
    ) -> dict:
        pamp_observations = self.storage.get_recent_observations(
            profile_ip,
            now - self.related_lookback_seconds,
            evidence_signal="PAMP",
        )
        damp_observations = self.storage.get_recent_observations(
            profile_ip,
            now - self.related_lookback_seconds,
            evidence_signal="DAMP",
        )
        current_observation = self.storage.get_observation(observation_id) or {}
        confidence = float(current_observation.get("confidence", 0.0))
        related_pamp_count = self._count_related_observations(
            pamp_observations,
            candidate,
            match.regex_hash,
            exclude_observation_id=observation_id,
        )
        related_pamp_score = self._clamp01(
            related_pamp_count / self.related_pamps_saturation
        )
        danger_scores = self._compute_danger_scores(
            pamp_observations,
            damp_observations,
        )
        profile_danger_score = danger_scores["combined_score"]
        value = (
            self.co_stimulation_weights["confidence"] * confidence
            + self.co_stimulation_weights["related_pamps"] * related_pamp_score
            + self.co_stimulation_weights["danger"] * profile_danger_score
        )
        return {
            "value": value,
            "confidence": confidence,
            "related_pamp_count": related_pamp_count,
            "related_pamp_score": related_pamp_score,
            "profile_danger_score": profile_danger_score,
            "pamp_danger_score": danger_scores["pamp_score"],
            "damp_danger_score": danger_scores["damp_score"],
            "damp_danger_weight": self.damp_danger_weight,
            "threshold": self.co_stimulation_threshold,
        }

    def _compute_context_signals(
        self,
        profile_ip: str,
        observation_id: int,
        candidate: AntigenCandidate,
        match: RegexMatch,
        now: float,
    ) -> dict:
        recent_start = now - self.context_recent_window_seconds
        previous_start = now - (2 * self.context_recent_window_seconds)

        recent_pamp_observations = self.storage.get_recent_observations(
            profile_ip,
            recent_start,
            evidence_signal="PAMP",
        )
        recent_damp_observations = self.storage.get_recent_observations(
            profile_ip,
            recent_start,
            evidence_signal="DAMP",
        )
        previous_pamp_observations = self.storage.get_recent_observations(
            profile_ip,
            previous_start,
            until_ts=recent_start,
            evidence_signal="PAMP",
        )
        previous_damp_observations = self.storage.get_recent_observations(
            profile_ip,
            previous_start,
            until_ts=recent_start,
            evidence_signal="DAMP",
        )
        recent_related_count = self._count_related_observations(
            recent_pamp_observations,
            candidate,
            match.regex_hash,
            exclude_observation_id=observation_id,
        )
        recent_related_score = self._clamp01(
            recent_related_count / self.related_pamps_saturation
        )
        recent_danger = self._compute_danger_scores(
            recent_pamp_observations,
            recent_damp_observations,
        )
        previous_danger = self._compute_danger_scores(
            previous_pamp_observations,
            previous_damp_observations,
        )
        recent_pressure = recent_danger["combined_score"]
        previous_pressure = previous_danger["combined_score"]
        trend_ratio = recent_pressure / max(previous_pressure, 0.01)
        novelty_score = (
            1.0
            if self._is_novel_regex(
                profile_ip, match, observation_id, now
            )
            else 0.0
        )
        effector_score = (
            (0.45 * recent_pressure)
            + (0.25 * recent_related_score)
            + (0.30 * novelty_score)
        )
        decrease_score = self._clamp01(1.0 - trend_ratio)
        familiarity_score = 1.0 - novelty_score
        stability_score = self._clamp01(
            recent_related_count / self.memory_min_related_count
        )
        memory_score = (
            (0.60 * decrease_score)
            + (0.25 * familiarity_score)
            + (0.15 * stability_score)
        )
        effector = (
            novelty_score > 0
            and recent_related_count >= self.effector_min_related_count
            and effector_score >= self.effector_threshold
        )
        memory = (
            familiarity_score > 0
            and recent_related_count >= self.memory_min_related_count
            and trend_ratio <= self.memory_trend_ratio_max
            and memory_score >= self.memory_threshold
        )
        return {
            "novelty_score": novelty_score,
            "recent_pressure": recent_pressure,
            "previous_pressure": previous_pressure,
            "recent_pamp_pressure": recent_danger["pamp_score"],
            "recent_damp_pressure": recent_danger["damp_score"],
            "previous_pamp_pressure": previous_danger["pamp_score"],
            "previous_damp_pressure": previous_danger["damp_score"],
            "damp_danger_weight": self.damp_danger_weight,
            "trend_ratio": trend_ratio,
            "recent_related_count": recent_related_count,
            "recent_related_score": recent_related_score,
            "effector_score": effector_score,
            "memory_score": memory_score,
            "decrease_score": decrease_score,
            "familiarity_score": familiarity_score,
            "stability_score": stability_score,
            "effector_threshold": self.effector_threshold,
            "memory_threshold": self.memory_threshold,
            "effector": effector,
            "memory": memory,
        }

    def _is_novel_regex(
        self,
        profile_ip: str,
        match: RegexMatch,
        observation_id: int,
        now: float,
    ) -> bool:
        if self.storage.has_memory_for_regex(match.regex_hash):
            return False
        return not self.storage.has_recent_regex_activity(
            profile_ip,
            match.regex_hash,
            now - self.novelty_window_seconds,
            exclude_observation_id=observation_id,
        )

    def _apply_effector(
        self,
        cell: dict,
        evidence,
        match: RegexMatch,
        context: dict,
        now: float,
        responsible_ip: str,
    ):
        cooldown_until = cell.get("effector_cooldown_until") or 0
        if now < cooldown_until:
            self._log_event(
                action="effector_cooldown",
                state=STATE_EFFECTOR,
                evidence=evidence,
                cell=cell,
                match=match,
                metrics={"cooldown_until": cooldown_until},
                details=(
                    "effector already fired recently for this cell; "
                    "suppressing repeated blocking"
                ),
                verbosity=LOG_VERBOSITY_DECISIONS,
            )
            return

        blocking_data = {
            "ip": responsible_ip,
            "block": True,
            "tw": evidence.timewindow.number,
            "interface": utils.get_interface_of_ip(
                responsible_ip, self.db, self.args
            ),
        }
        next_cooldown = now + self.effector_cooldown_seconds
        self._update_cell(
            cell,
            now,
            effector_cooldown_until=next_cooldown,
            context={"context": context, "effector_payload": blocking_data},
        )

        if self._blocking_modules_available():
            self.db.publish("new_blocking", json.dumps(blocking_data))
            self._log_event(
                action="effector_published",
                state=STATE_EFFECTOR,
                evidence=evidence,
                cell=cell,
                match=match,
                metrics={"effector_score": context["effector_score"]},
                verbosity=LOG_VERBOSITY_SUMMARY,
            )
            return

        if self.simulate_effector_without_blocking:
            self._log_event(
                action="effector_simulated",
                state=STATE_EFFECTOR,
                evidence=evidence,
                cell=cell,
                match=match,
                details=json.dumps(blocking_data, sort_keys=True),
                metrics={"effector_score": context["effector_score"]},
                verbosity=LOG_VERBOSITY_SUMMARY,
            )
            return

        self._log_event(
            action="effector_unavailable",
            state=STATE_EFFECTOR,
            evidence=evidence,
            cell=cell,
            match=match,
            metrics={"effector_score": context["effector_score"]},
            details="blocking modules are not running and simulation is disabled",
            verbosity=LOG_VERBOSITY_SUMMARY,
        )

    def _store_memory(
        self, cell: dict, match: RegexMatch, context: dict, now: float
    ):
        self.storage.upsert_memory(
            {
                "cell_key": cell["cell_key"],
                "profile_ip": cell["profile_ip"],
                "regex_type": cell["regex_type"],
                "antigen_value": cell["antigen_value"],
                "regex_hash": match.regex_hash,
                "regex": match.regex,
                "matched_value": match.value,
                "context": context,
                "created_at": now,
                "updated_at": now,
            }
        )

    def _blocking_modules_available(self) -> bool:
        blocking_pid = self.db.get_pid_of("Blocking")
        arp_pid = self.db.get_pid_of("ARP Poisoner")
        return self._pid_is_running(blocking_pid) or self._pid_is_running(
            arp_pid
        )

    @staticmethod
    def _pid_is_running(pid) -> bool:
        if isinstance(pid, int):
            return pid > 0
        if isinstance(pid, str):
            return pid.isdigit() and int(pid) > 0
        return False

    def _find_best_regex_match(
        self, candidate: AntigenCandidate
    ) -> RegexMatch | None:
        regex_records = self.db.get_generated_regexes(
            regex_type=candidate.regex_type, status="accepted"
        )
        best_match = None
        best_key = None
        for record in regex_records or []:
            regex_text = str(record.get("regex", ""))
            if not regex_text:
                continue
            try:
                compiled_regex = re.compile(regex_text)
                if not compiled_regex.search(candidate.value):
                    continue
            except re.error:
                continue

            specificity_features = measure_regex_specificity(regex_text)
            specificity = float(
                specificity_features.get("specificity_ratio", 0.0)
            )
            wildcard_penalty = float(
                specificity_features.get("wildcard_penalty", 1.0)
            )
            match_strength = compute_match_strength(
                compiled_regex,
                candidate.value,
                regex_features=specificity_features,
            )
            created_at = float(record.get("created_at") or 0.0)
            sort_key = (
                match_strength,
                specificity,
                -wildcard_penalty,
                created_at,
            )
            if best_key is not None and sort_key <= best_key:
                continue

            best_key = sort_key
            best_match = RegexMatch(
                regex_type=candidate.regex_type,
                value=candidate.value,
                regex_hash=str(record.get("regex_hash", "")),
                regex=regex_text,
                created_at=created_at,
                specificity=specificity,
            )
        return best_match

    def _extract_antigen_candidates(self, evidence) -> list[AntigenCandidate]:
        candidates = {}

        for entity in (evidence.attacker, evidence.victim):
            self._extract_from_entity(entity, candidates)

        for uid in evidence.uid:
            flow = self._unwrap_flow_record(self.db.get_altflow_from_uid(uid))
            if not flow:
                continue

            flow_type = str(
                flow.get("flow_type") or flow.get("type_") or ""
            ).lower()
            if flow_type == "dns" or "query" in flow:
                self._add_candidate(
                    candidates, "dns_domain", self._normalize_domain(flow.get("query"))
                )
            if flow_type == "http" or "uri" in flow or "host" in flow:
                self._add_candidate(
                    candidates, "dns_domain", self._normalize_domain(flow.get("host"))
                )
                uri = self._normalize_uri(flow.get("uri"))
                self._add_candidate(candidates, "uri", uri)
                self._add_candidate(
                    candidates, "filename", self._extract_filename_from_uri(uri)
                )
            if flow_type == "ssl" or "server_name" in flow or "subject" in flow:
                self._add_candidate(
                    candidates,
                    "tls_sni",
                    self._normalize_domain(flow.get("server_name")),
                )
                self._add_candidate(
                    candidates,
                    "certificate_cn",
                    self._extract_cn(flow.get("subject")),
                )

        return [
            AntigenCandidate(regex_type=regex_type, value=value)
            for regex_type, value in sorted(candidates.keys())
        ]

    def _extract_from_entity(self, entity, candidates: dict):
        if not entity:
            return

        ioc_type = self._enum_name(getattr(entity, "ioc_type", None))
        if ioc_type == "DOMAIN":
            self._add_candidate(
                candidates, "dns_domain", self._normalize_domain(entity.value)
            )
        elif ioc_type == "URL":
            parsed = urlparse(str(entity.value or "").strip())
            self._add_candidate(
                candidates, "dns_domain", self._normalize_domain(parsed.hostname)
            )
            uri = self._normalize_uri(entity.value)
            self._add_candidate(candidates, "uri", uri)
            self._add_candidate(
                candidates, "filename", self._extract_filename_from_uri(uri)
            )

        self._add_candidate(
            candidates, "tls_sni", self._normalize_domain(getattr(entity, "SNI", ""))
        )

    @staticmethod
    def _enum_name(value) -> str:
        if hasattr(value, "name"):
            return str(value.name).upper()
        raw_value = str(value or "").strip()
        if "." in raw_value:
            raw_value = raw_value.rsplit(".", 1)[-1]
        return raw_value.upper()

    def _get_entity_ip(self, entity) -> str:
        if not entity:
            return ""
        if self._enum_name(getattr(entity, "ioc_type", None)) != "IP":
            return ""
        value = str(getattr(entity, "value", "") or "").strip()
        if not utils.is_valid_ip(value):
            return ""
        return value

    def _get_responsible_ip(self, evidence) -> str:
        attacker_ip = self._get_entity_ip(getattr(evidence, "attacker", None))
        if attacker_ip:
            return attacker_ip

        for entity in (
            getattr(evidence, "attacker", None),
            getattr(evidence, "victim", None),
        ):
            if self._enum_name(getattr(entity, "direction", None)) != "SRC":
                continue
            entity_ip = self._get_entity_ip(entity)
            if entity_ip:
                return entity_ip

        return str(getattr(getattr(evidence, "profile", None), "ip", "") or "")

    def _get_target_ip(self, evidence) -> str:
        victim_ip = self._get_entity_ip(getattr(evidence, "victim", None))
        if victim_ip:
            return victim_ip
        return ""

    def _count_related_observations(
        self,
        observations: list[dict],
        candidate: AntigenCandidate,
        regex_hash: str,
        exclude_observation_id: int,
    ) -> int:
        count = 0
        for observation in observations:
            if observation["id"] == exclude_observation_id:
                continue
            if self._is_related_observation(observation, candidate, regex_hash):
                count += 1
        return count

    @staticmethod
    def _is_related_observation(
        observation: dict, candidate: AntigenCandidate, regex_hash: str
    ) -> bool:
        for antigen in observation.get("antigens", []):
            if (
                antigen.get("regex_type") == candidate.regex_type
                and antigen.get("value") == candidate.value
            ):
                return True
        for match in observation.get("matched_regexes", []):
            if regex_hash and match.get("regex_hash") == regex_hash:
                return True
        return False

    @staticmethod
    def _sum_danger(observations: list[dict]) -> float:
        return sum(
            float(obs.get("threat_level_value", 0.0))
            * float(obs.get("confidence", 0.0))
            for obs in observations
        )

    def _compute_danger_scores(
        self,
        pamp_observations: list[dict],
        damp_observations: list[dict],
    ) -> dict:
        pamp_raw = self._sum_danger(pamp_observations)
        damp_raw = self._sum_danger(damp_observations)
        combined_raw = pamp_raw + (self.damp_danger_weight * damp_raw)
        return {
            "pamp_score": self._normalize_danger(pamp_raw),
            "damp_score": self._normalize_danger(damp_raw),
            "combined_score": self._normalize_danger(combined_raw),
        }

    def _normalize_danger(self, raw_value: float) -> float:
        return self._clamp01(raw_value / self.danger_saturation)

    @staticmethod
    def _clamp01(value: float) -> float:
        return max(0.0, min(1.0, float(value)))

    @staticmethod
    def _get_state_wait_elapsed(cell: dict, now: float) -> float:
        start_ts = (
            cell.get("last_transition_at")
            or cell.get("created_at")
            or now
        )
        try:
            start_ts = float(start_ts)
        except (TypeError, ValueError):
            start_ts = now
        return max(0.0, float(now) - start_ts)

    def _state_wait_expired(self, cell: dict, now: float) -> bool:
        return (
            self._get_state_wait_elapsed(cell, now)
            >= self.state_wait_timeout_seconds
        )

    @staticmethod
    def _make_cell_key(profile_ip: str, regex_type: str, antigen_value: str) -> str:
        return f"{profile_ip}|{regex_type}|{antigen_value}"

    @staticmethod
    def _unwrap_flow_record(flow_record) -> dict:
        if not isinstance(flow_record, dict):
            return {}
        if isinstance(flow_record.get("flow"), dict):
            flow = dict(flow_record["flow"])
            flow["flow_type"] = flow_record.get("flow_type") or flow.get(
                "flow_type"
            )
            return flow
        return dict(flow_record)

    @staticmethod
    def _add_candidate(candidates: dict, regex_type: str, value: str):
        normalized = str(value or "").strip()
        if regex_type not in SUPPORTED_REGEX_TYPES or not normalized:
            return
        candidates[(regex_type, normalized)] = True

    @staticmethod
    def _normalize_domain(value: str) -> str:
        domain = str(value or "").strip().rstrip(".").lower()
        if not domain or not utils.is_valid_domain(domain):
            return ""
        return domain

    @staticmethod
    def _normalize_uri(value: str) -> str:
        raw_value = str(value or "").strip()
        if not raw_value:
            return ""
        parsed = urlparse(raw_value)
        if parsed.scheme or parsed.netloc:
            uri = parsed.path or "/"
            if parsed.query:
                uri = f"{uri}?{parsed.query}"
            return uri
        return raw_value

    @staticmethod
    def _extract_cn(subject: str) -> str:
        match = re.search(r"(?:^|,)CN=([^,]+)", str(subject or ""))
        if not match:
            return ""
        return match.group(1).strip()

    @staticmethod
    def _extract_filename_from_uri(uri: str) -> str:
        value = str(uri or "").strip()
        if not value:
            return ""
        parsed = urlparse(value)
        path = parsed.path or value
        filename = path.rsplit("/", 1)[-1].strip()
        if not filename or "." not in filename:
            return ""
        return filename

    def _prune_observations(self, now: float):
        cutoff = now - self.observation_retention_seconds
        self.storage.prune_observations(cutoff)

    def _init_log_file(self):
        if not self.create_log_file:
            return
        os.makedirs(self.output_dir, exist_ok=True)
        with open(self.log_file_path, "w", encoding="utf-8") as log_file:
            log_file.write("")

    def _colorize_state(self, state: int) -> str:
        label = STATE_INFO[state]["label"]
        if not self.log_colors:
            return label
        return f"{STATE_INFO[state]['color']}{label}{COLOR_RESET}"

    def _log_event(
        self,
        action: str,
        evidence,
        state: int | None,
        cell: dict | None = None,
        match: RegexMatch | None = None,
        details: str | None = None,
        metrics: dict | None = None,
        verbosity: int = LOG_VERBOSITY_DECISIONS,
    ):
        if verbosity > self.log_verbosity:
            return
        parts = [
            utils.convert_ts_format(time.time(), utils.alerts_format),
            f"action={action}",
        ]
        if state is not None:
            parts.append(f"state={self._colorize_state(state)}")
        if evidence:
            parts.append(f"evidence={evidence.evidence_type.name}")
            parts.append(f"eid={evidence.id}")
            parts.append(f"profile={evidence.profile.ip}")
            responsible_ip = self._get_responsible_ip(evidence)
            if responsible_ip:
                parts.append(f"responsible={responsible_ip}")
            target_ip = self._get_target_ip(evidence)
            if target_ip:
                parts.append(f"target={target_ip}")
        if cell:
            parts.append(f"cell={cell['cell_key']}")
        if match:
            parts.append(f"regex={match.regex_hash}")
            parts.append(f"value={match.value}")
        if metrics:
            metric_text = ",".join(
                f"{key}={value:.3f}" if isinstance(value, float) else f"{key}={value}"
                for key, value in metrics.items()
            )
            parts.append(metric_text)
        if details:
            parts.append(details)
        self._log_detail(" | ".join(parts))

    def _log_detail(self, text: str):
        if not self.create_log_file:
            return
        with open(self.log_file_path, "a", encoding="utf-8") as log_file:
            log_file.write(f"{text}\n")
