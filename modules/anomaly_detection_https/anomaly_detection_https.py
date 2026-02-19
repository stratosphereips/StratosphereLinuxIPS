# SPDX-FileCopyrightText: 2026 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
import math
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Optional, Set, List

from slips_files.common.abstracts.imodule import IModule
from slips_files.common.flow_classifier import FlowClassifier
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from slips_files.core.structures.evidence import (
    Attacker,
    Direction,
    Evidence,
    EvidenceType,
    IoCType,
    Method,
    ProfileID,
    Proto,
    ThreatLevel,
    TimeWindow,
    Victim,
)


@dataclass
class EWMAStats:
    mean: float = 0.0
    var: float = 0.0
    m2: float = 0.0
    count: int = 0
    min_std_floor: float = 0.1
    residuals: List[float] = field(default_factory=list)
    residual_window_size: int = 64
    floor_update_beta: float = 0.05
    floor_scale: float = 1.0
    floor_min: float = 0.01
    floor_max: float = 1000000.0

    def _update_floor_from_residual(self, residual: float):
        self.residuals.append(float(abs(residual)))
        if len(self.residuals) > self.residual_window_size:
            self.residuals.pop(0)
        self.update_min_std_floor()

    def update_training(self, value: float):
        value = float(value)
        if self.count > 0:
            self._update_floor_from_residual(value - self.mean)

        # Welford online moments: fit all benign samples uniformly.
        if self.count == 0:
            self.count = 1
            self.mean = value
            self.m2 = 0.0
            self.var = 0.0
            return

        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self.m2 += delta * delta2
        self.var = self.m2 / max(1, self.count - 1)

    def update(self, value: float, alpha: float):
        value = float(value)
        if self.count > 0:
            self._update_floor_from_residual(value - self.mean)

        if self.count == 0:
            self.mean = value
            self.var = 0.0
            self.m2 = 0.0
            self.count = 1
            return

        delta = value - self.mean
        self.mean += alpha * delta
        self.var = (1 - alpha) * (self.var + alpha * delta * delta)
        self.m2 = self.var * max(0, self.count - 1)
        self.count += 1

    @staticmethod
    def _quantile(values: List[float], q: float) -> float:
        if not values:
            return 0.0
        q = min(1.0, max(0.0, float(q)))
        xs = sorted(values)
        if len(xs) == 1:
            return xs[0]
        pos = q * (len(xs) - 1)
        lo = int(math.floor(pos))
        hi = int(math.ceil(pos))
        if lo == hi:
            return xs[lo]
        frac = pos - lo
        return xs[lo] * (1.0 - frac) + xs[hi] * frac

    def update_min_std_floor(self):
        if len(self.residuals) < 5:
            return
        q10 = self._quantile(self.residuals, 0.10)
        med = self._quantile(self.residuals, 0.50)
        abs_dev = [abs(x - med) for x in self.residuals]
        mad = self._quantile(abs_dev, 0.50)
        sigma_mad = 1.4826 * mad
        candidate = self.floor_scale * max(q10, sigma_mad, self.floor_min)
        candidate = min(self.floor_max, max(self.floor_min, candidate))
        beta = min(1.0, max(0.0, self.floor_update_beta))
        self.min_std_floor = (1.0 - beta) * self.min_std_floor + beta * candidate

    def zscore(self, value: float) -> float:
        std = math.sqrt(max(self.var, self.min_std_floor * self.min_std_floor))
        return abs(float(value) - self.mean) / std


@dataclass
class HourBucket:
    start_ts: int
    ssl_flows: int = 0
    servers: Set[str] = field(default_factory=set)
    new_servers: Set[str] = field(default_factory=set)
    uids: Set[str] = field(default_factory=set)
    known_servers_total_bytes: float = 0.0
    known_servers_flow_count: int = 0
    flow_anomaly_count: int = 0


@dataclass
class HostState:
    bucket: Optional[HourBucket] = None
    known_servers: Set[str] = field(default_factory=set)
    known_ja3: Set[str] = field(default_factory=set)
    known_ja3s: Set[str] = field(default_factory=set)
    trained_hours: int = 0
    hourly_models: Dict[str, EWMAStats] = field(default_factory=dict)
    server_bytes_models: Dict[str, EWMAStats] = field(default_factory=dict)
    anomaly_history_ts: List[float] = field(default_factory=list)
    last_twid: int = 0


class AnomalyDetectionHTTPS(IModule):
    name = "Anomaly Detection HTTPS"
    description = (
        "HTTPS anomaly detector with hourly adaptive baselines and "
        "flow-level checks."
    )
    authors = ["Sebastian Garcia"]

    def init(self):
        self.c1 = self.db.subscribe("new_ssl")
        self.channels = {"new_ssl": self.c1}
        self.classifier = FlowClassifier()
        self.read_configuration()
        self.operational_log_path = os.path.join(
            self.output_dir, "anomaly_detection_https.log"
        )

        self.host_states: Dict[str, HostState] = {}
        self.log_event(
            1,
            "module_start",
            "HTTPS anomaly module started.",
            metrics={
                "training_hours": self.training_hours,
                "hourly_zscore_threshold": self.hourly_zscore_threshold,
                "flow_zscore_threshold": self.flow_zscore_threshold,
                "adaptation_score_threshold": self.adaptation_score_threshold,
                "baseline_alpha": self.baseline_alpha,
                "drift_alpha": self.drift_alpha,
                "suspicious_alpha": self.suspicious_alpha,
                "min_baseline_points": self.min_baseline_points,
                "max_small_flow_anomalies": self.max_small_flow_anomalies,
                "log_verbosity": self.log_verbosity,
                "log_emojis": self.log_emojis,
                "log_colors": self.log_colors,
            },
        )

    def read_configuration(self):
        conf = ConfigParser()
        self.training_hours = conf.https_anomaly_training_hours()
        self.hourly_zscore_threshold = conf.https_anomaly_hourly_zscore_thr()
        self.flow_zscore_threshold = conf.https_anomaly_flow_zscore_thr()
        self.adaptation_score_threshold = conf.https_anomaly_adapt_score_thr()
        self.baseline_alpha = conf.https_anomaly_baseline_alpha()
        self.drift_alpha = conf.https_anomaly_drift_alpha()
        self.suspicious_alpha = conf.https_anomaly_suspicious_alpha()
        self.min_baseline_points = conf.https_anomaly_min_baseline_points()
        self.max_small_flow_anomalies = (
            conf.https_anomaly_max_small_flow_anomalies()
        )
        self.log_verbosity = conf.https_anomaly_log_verbosity()
        # Operational logs always use emojis and colors.
        self.log_emojis = True
        self.log_colors = True

    def pre_main(self):
        utils.drop_root_privs_permanently()

    def shutdown_gracefully(self):
        # Flush all open hourly buckets at shutdown.
        for profileid, state in self.host_states.items():
            self.finalize_hour_bucket(profileid, state)
        self.log_event(
            1,
            "module_stop",
            "HTTPS anomaly module stopped.",
            metrics={"hosts_tracked": len(self.host_states)},
        )

    @staticmethod
    def _ts_to_iso(ts: Optional[float] = None) -> str:
        if ts is None:
            ts = time.time()
        return (
            datetime.fromtimestamp(float(ts), tz=timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )

    def should_log(self, level: int) -> bool:
        return self.log_verbosity >= level

    def get_color(self, event_type: str) -> str:
        colors = {
            "flow_arrival": "\033[36m",
            "hour_close": "\033[36m",
            "training_fit": "\033[34m",
            "drift_update": "\033[35m",
            "suspicious_update": "\033[35m",
            "model_update": "\033[34m",
            "flow_detection": "\033[31m",
            "hourly_detection": "\033[31m",
            "evidence_emit": "\033[33m",
            "module_start": "\033[32m",
            "module_stop": "\033[32m",
        }
        return colors.get(event_type, "")

    def get_emoji(self, event_type: str) -> str:
        emojis = {
            "flow_arrival": "📥",
            "hour_close": "🕐",
            "training_fit": "🎓",
            "drift_update": "🌊",
            "suspicious_update": "🐢",
            "model_update": "🧠",
            "flow_detection": "🚨",
            "hourly_detection": "🚨",
            "evidence_emit": "🧾",
            "module_start": "✅",
            "module_stop": "🛑",
        }
        return emojis.get(event_type, "ℹ️")

    def log_event(
        self,
        level: int,
        event_type: str,
        message: str,
        traffic_ts: Optional[float] = None,
        metrics: Optional[dict] = None,
    ):
        if not self.should_log(level):
            return
        metrics = metrics or {}
        emoji = self.get_emoji(event_type)
        color = self.get_color(event_type)
        reset = "\033[0m" if self.log_colors else ""
        wall_clock = self._ts_to_iso()
        traffic_clock = self._ts_to_iso(traffic_ts) if traffic_ts else "n/a"
        metrics_json = json.dumps(metrics, sort_keys=True)
        line = (
            f"{wall_clock} traffic_ts={traffic_clock} "
            f"{emoji} [{event_type}] {message} metrics={metrics_json}"
        )
        if color:
            line = f"{color}{line}{reset}"
        with open(self.operational_log_path, "a", encoding="utf-8") as log_file:
            log_file.write(f"{line}\n")

    @staticmethod
    def get_hour_start(ts: float) -> int:
        ts = int(float(ts))
        return ts - (ts % 3600)

    @staticmethod
    def to_float(value, default=0.0) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return float(default)

    def get_traffic_ts(self, flow, fallback_ts: Optional[float] = None) -> float:
        """
        Returns traffic timestamp from flow.starttime.
        Detection windows must use traffic time, not host wall-clock time.
        """
        default = 0.0 if fallback_ts is None else fallback_ts
        return self.to_float(getattr(flow, "starttime", None), default=default)

    def get_or_create_hourly_model(self, state: HostState, feature: str):
        if feature not in state.hourly_models:
            state.hourly_models[feature] = EWMAStats()
        return state.hourly_models[feature]

    def get_or_create_server_model(self, state: HostState, server: str):
        if server not in state.server_bytes_models:
            state.server_bytes_models[server] = EWMAStats()
        return state.server_bytes_models[server]

    def ensure_hour_bucket(self, profileid: str, ts: float) -> HostState:
        state = self.host_states.setdefault(profileid, HostState())
        hour_start = self.get_hour_start(ts)
        if state.bucket is None:
            state.bucket = HourBucket(start_ts=hour_start)
            return state

        if state.bucket.start_ts != hour_start:
            self.finalize_hour_bucket(profileid, state)
            state.bucket = HourBucket(start_ts=hour_start)
        return state

    def should_detect(self, state: HostState) -> bool:
        return state.trained_hours >= self.training_hours

    def prune_anomaly_history(self, state: HostState, now_ts: float):
        one_day = 24 * 3600
        state.anomaly_history_ts = [
            ts for ts in state.anomaly_history_ts if now_ts - ts <= one_day
        ]

    def get_persistence(self, state: HostState, now_ts: float) -> float:
        self.prune_anomaly_history(state, now_ts)
        window = 3 * 3600
        recent = [
            ts for ts in state.anomaly_history_ts if now_ts - ts <= window
        ]
        return min(1.0, len(recent) / 3.0)

    def get_baseline_quality(self, baseline_count: int) -> float:
        stable_points = max(10, self.min_baseline_points * 3)
        return min(1.0, max(0, baseline_count) / float(stable_points))

    @staticmethod
    def get_confidence_level(score: float) -> str:
        if score >= 0.80:
            return "high"
        if score >= 0.55:
            return "medium"
        return "low"

    @staticmethod
    def profile_ip(profileid: str) -> str:
        if profileid.startswith("profile_"):
            return profileid.split("profile_", 1)[1]
        return profileid

    @staticmethod
    def parse_twid_number(twid_raw) -> int:
        if twid_raw is None:
            return 0
        try:
            return int(twid_raw)
        except (TypeError, ValueError):
            pass
        twid_str = str(twid_raw)
        if twid_str.startswith("timewindow"):
            twid_str = twid_str.replace("timewindow", "", 1)
        try:
            return int(twid_str)
        except ValueError:
            return 0

    @staticmethod
    def evidence_ts_from_traffic_ts(ts: float) -> str:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime(
            utils.alerts_format
        )

    @staticmethod
    def threat_level_from_confidence_level(confidence_level: str) -> ThreatLevel:
        # Requested policy:
        # - confidence low/medium -> threat level low
        # - confidence high -> threat level medium
        if str(confidence_level).lower() == "high":
            return ThreatLevel.MEDIUM
        return ThreatLevel.LOW

    def build_victim(
        self, server: str, sni: str, daddr: str
    ) -> Optional[Victim]:
        if sni:
            return Victim(
                direction=Direction.DST,
                ioc_type=IoCType.DOMAIN,
                value=sni,
                SNI=sni,
            )
        if daddr and utils.is_valid_ip(daddr):
            return Victim(
                direction=Direction.DST,
                ioc_type=IoCType.IP,
                value=daddr,
                SNI=sni or None,
            )
        if server and server != "<unknown_server>":
            return Victim(
                direction=Direction.DST,
                ioc_type=IoCType.DOMAIN,
                value=server,
                SNI=sni or None,
            )
        return None

    def emit_anomaly_evidence(
        self,
        profileid: str,
        twid_number: int,
        traffic_ts: float,
        uid: Optional[str],
        confidence: dict,
        reasons: List[dict],
        kind: str,
        ssl_flow=None,
        server: str = "",
        sni: str = "",
        daddr: str = "",
        extra: Optional[dict] = None,
    ):
        srcip = self.profile_ip(profileid)
        if not srcip or not utils.is_valid_ip(srcip):
            self.log_event(
                1,
                "evidence_emit",
                "Skipped evidence emission due to invalid profile source IP.",
                traffic_ts=traffic_ts,
                metrics={"profileid": profileid, "srcip": srcip},
            )
            return

        confidence_score = self.to_float(confidence.get("score"), 0.0)
        threat_level = self.threat_level_from_confidence_level(
            str(confidence.get("level", "low"))
        )
        details = {
            "kind": kind,
            "confidence_level": confidence.get("level", "low"),
            "confidence_score": round(confidence_score, 4),
            "confidence_factors": {
                "severity": confidence.get("severity"),
                "persistence": confidence.get("persistence"),
                "baseline_quality": confidence.get("baseline_quality"),
                "multi_signal": confidence.get("multi_signal"),
                "max_z": confidence.get("max_z"),
            },
            "server": server,
            "sni": sni,
            "daddr": daddr,
        }
        if extra:
            details.update(extra)
        description = (
            "HTTPS anomaly detected. "
            f"kind={kind}, confidence={confidence.get('level')} "
            f"({confidence_score:.3f}), details={json.dumps(details, sort_keys=True)}, "
            f"reasons={json.dumps(reasons, sort_keys=True)}."
        )

        uid_list = [uid] if uid else []
        if kind == "hourly" and extra and "uids" in extra:
            uid_list = [u for u in extra["uids"] if isinstance(u, str)]
        if not uid_list:
            uid_list = [f"https_ad_{kind}_{int(traffic_ts)}"]

        dst_port = None
        src_port = None
        if ssl_flow is not None:
            try:
                dst_port = int(getattr(ssl_flow, "dport", 0))
            except (TypeError, ValueError):
                dst_port = None
            try:
                src_port = int(getattr(ssl_flow, "sport", 0))
            except (TypeError, ValueError):
                src_port = None

        evidence = Evidence(
            evidence_type=EvidenceType.MALICIOUS_FLOW,
            description=description,
            attacker=Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value=srcip,
            ),
            victim=self.build_victim(server=server, sni=sni, daddr=daddr),
            threat_level=threat_level,
            profile=ProfileID(ip=srcip),
            timewindow=TimeWindow(number=twid_number),
            uid=uid_list,
            timestamp=self.evidence_ts_from_traffic_ts(traffic_ts),
            proto=Proto.TCP,
            dst_port=dst_port,
            src_port=src_port,
            method=Method.STATISTICAL,
            confidence=confidence_score,
        )
        self.db.set_evidence(evidence)
        self.log_event(
            1,
            "evidence_emit",
            "Anomaly emitted as Slips evidence.",
            traffic_ts=traffic_ts,
            metrics={
                "profileid": profileid,
                "kind": kind,
                "evidence_type": str(evidence.evidence_type),
                "threat_level": str(evidence.threat_level),
                "confidence_score": confidence_score,
                "confidence_level": confidence.get("level"),
                "uid_count": len(uid_list),
            },
        )

    def get_host_baseline_count(self, state: HostState) -> int:
        counts = [model.count for model in state.hourly_models.values()]
        if not counts:
            return 0
        return min(counts)

    def score_confidence(
        self,
        state: HostState,
        ts: float,
        reasons: List[dict],
        baseline_count: int,
    ) -> Dict[str, float | str]:
        zscores = []
        for reason in reasons:
            if "zscore" in reason:
                zscores.append(self.to_float(reason["zscore"], 0.0))
            else:
                # novelty-style anomalies still carry anomaly weight
                zscores.append(2.0)

        max_z = max(zscores) if zscores else 0.0
        severity = 1.0 - math.exp(-max_z / 3.0)
        persistence = self.get_persistence(state, ts)
        baseline_quality = self.get_baseline_quality(baseline_count)
        multi_signal = min(1.0, len(reasons) / 3.0)

        score = (
            0.45 * severity
            + 0.25 * persistence
            + 0.20 * baseline_quality
            + 0.10 * multi_signal
        )
        score = min(1.0, max(0.0, score))
        return {
            "score": round(score, 4),
            "level": self.get_confidence_level(score),
            "severity": round(severity, 4),
            "persistence": round(persistence, 4),
            "baseline_quality": round(baseline_quality, 4),
            "multi_signal": round(multi_signal, 4),
            "max_z": round(max_z, 4),
        }

    def score_feature(self, model: EWMAStats, value: float) -> float:
        if model.count < self.min_baseline_points:
            return 0.0
        return model.zscore(value)

    def update_model(self, model: EWMAStats, value: float, alpha: float):
        if alpha <= 0:
            return
        model.update(value, alpha)

    def fit_benign_model(self, model: EWMAStats, value: float):
        model.update_training(value)

    def finalize_hour_bucket(self, profileid: str, state: HostState):
        bucket = state.bucket
        if not bucket:
            return

        unique_servers = float(len(bucket.servers))
        new_servers = float(len(bucket.new_servers))
        ssl_flows = float(bucket.ssl_flows)
        known_server_avg_bytes = 0.0
        if bucket.known_servers_flow_count > 0:
            known_server_avg_bytes = (
                bucket.known_servers_total_bytes
                / float(bucket.known_servers_flow_count)
            )

        features = {
            "ssl_flows": ssl_flows,
            "unique_servers": unique_servers,
            "new_servers": new_servers,
            "known_server_avg_bytes": known_server_avg_bytes,
        }
        self.log_event(
            2,
            "hour_close",
            "Closing hour bucket and evaluating host metrics.",
            traffic_ts=bucket.start_ts,
            metrics={
                "profileid": profileid,
                "hour_start": bucket.start_ts,
                "features": features,
                "flow_anomaly_count": bucket.flow_anomaly_count,
            },
        )

        hourly_anomalies = []
        hourly_score = 0.0
        if self.should_detect(state):
            for feature_name, value in features.items():
                model = self.get_or_create_hourly_model(state, feature_name)
                z = self.score_feature(model, value)
                if z >= self.hourly_zscore_threshold:
                    hourly_anomalies.append(
                        {
                            "feature": feature_name,
                            "value": value,
                            "mean": model.mean,
                            "zscore": round(z, 3),
                        }
                    )
                    hourly_score += z

            if hourly_anomalies:
                state.anomaly_history_ts.append(bucket.start_ts)
                confidence = self.score_confidence(
                    state=state,
                    ts=bucket.start_ts,
                    reasons=hourly_anomalies,
                    baseline_count=min(
                        self.get_or_create_hourly_model(state, fname).count
                        for fname in features
                    ),
                )
                self.log_event(
                    1,
                    "hourly_detection",
                    "Hourly anomaly detected for host.",
                    traffic_ts=bucket.start_ts,
                    metrics={
                        "profileid": profileid,
                        "confidence": confidence["level"],
                        "confidence_score": confidence["score"],
                        "confidence_factors": {
                            "severity": confidence["severity"],
                            "persistence": confidence["persistence"],
                            "baseline_quality": confidence["baseline_quality"],
                            "multi_signal": confidence["multi_signal"],
                            "max_z": confidence["max_z"],
                        },
                        "hour_start": bucket.start_ts,
                        "anomaly_score": round(hourly_score, 3),
                        "flow_anomaly_count": bucket.flow_anomaly_count,
                        "anomalies": hourly_anomalies,
                    },
                )
                self.emit_anomaly_evidence(
                    profileid=profileid,
                    twid_number=state.last_twid,
                    traffic_ts=bucket.start_ts,
                    uid=None,
                    confidence=confidence,
                    reasons=hourly_anomalies,
                    kind="hourly",
                    extra={
                        "hour_start": bucket.start_ts,
                        "anomaly_score": round(hourly_score, 3),
                        "flow_anomaly_count": bucket.flow_anomaly_count,
                        "uids": list(bucket.uids),
                    },
                )

        is_training_hour = not self.should_detect(state)
        update_mode = "training_fit"
        if is_training_hour:
            state.trained_hours += 1
            self.log_event(
                1,
                "training_fit",
                "Baseline training hour fitted (Welford benign fit).",
                traffic_ts=bucket.start_ts,
                metrics={
                    "profileid": profileid,
                    "trained_hours": state.trained_hours,
                    "target_training_hours": self.training_hours,
                    "fit_method": "welford_online_moments",
                },
            )
            update_alpha = None
        elif (
            hourly_score <= self.adaptation_score_threshold
            and bucket.flow_anomaly_count <= self.max_small_flow_anomalies
        ):
            # Small anomalies are treated as benign drift and adapted.
            update_alpha = self.drift_alpha
            update_mode = "drift_update"
            self.log_event(
                1,
                "drift_update",
                "Small anomalies treated as drift; model adapted.",
                traffic_ts=bucket.start_ts,
                metrics={
                    "profileid": profileid,
                    "hourly_score": round(hourly_score, 3),
                    "flow_anomaly_count": bucket.flow_anomaly_count,
                    "alpha": update_alpha,
                },
            )
        else:
            update_alpha = self.suspicious_alpha
            update_mode = "suspicious_update"
            self.log_event(
                1,
                "suspicious_update",
                "Suspicious hour; model update reduced to avoid poisoning.",
                traffic_ts=bucket.start_ts,
                metrics={
                    "profileid": profileid,
                    "hourly_score": round(hourly_score, 3),
                    "flow_anomaly_count": bucket.flow_anomaly_count,
                    "alpha": update_alpha,
                },
            )

        for feature_name, value in features.items():
            model = self.get_or_create_hourly_model(state, feature_name)
            if is_training_hour:
                self.fit_benign_model(model, value)
            else:
                self.update_model(model, value, update_alpha)
            self.log_event(
                3,
                "model_update",
                "Hourly feature model updated.",
                traffic_ts=bucket.start_ts,
                metrics={
                    "profileid": profileid,
                    "update_mode": update_mode,
                    "feature": feature_name,
                    "value": value,
                    "mean": round(model.mean, 6),
                    "var": round(model.var, 6),
                    "count": model.count,
                    "min_std_floor": round(model.min_std_floor, 6),
                    "alpha": update_alpha,
                    "fit_method": (
                        "welford_online_moments"
                        if update_mode == "training_fit"
                        else "ewma"
                    ),
                },
            )

        state.bucket = None

    def process_ssl_event(
        self,
        profileid: str,
        ssl_flow,
        conn_info: dict,
        twid_number: int,
    ):
        ts = self.get_traffic_ts(
            ssl_flow, fallback_ts=self.to_float(conn_info.get("starttime"), 0.0)
        )
        state = self.ensure_hour_bucket(profileid, ts)
        state.last_twid = twid_number
        bucket = state.bucket
        if bucket is None:
            return

        sni = getattr(ssl_flow, "server_name", "") or ""
        server = sni or conn_info.get("daddr", "") or "<unknown_server>"
        uid = getattr(ssl_flow, "uid", "")
        self.log_event(
            3,
            "flow_arrival",
            "SSL flow received for processing.",
            traffic_ts=ts,
            metrics={
                "profileid": profileid,
                "uid": uid,
                "sni": sni,
                "has_conn_bytes": bool(conn_info),
            },
        )

        ja3 = (getattr(ssl_flow, "ja3", "") or "").strip()
        ja3s = (getattr(ssl_flow, "ja3s", "") or "").strip()
        is_new_ja3 = bool(ja3) and ja3 not in state.known_ja3
        is_new_ja3s = bool(ja3s) and ja3s not in state.known_ja3s

        is_new_server = server not in state.known_servers
        if is_new_server:
            bucket.new_servers.add(server)

        bucket.ssl_flows += 1
        bucket.servers.add(server)
        if uid:
            bucket.uids.add(uid)

        bytes_total = conn_info.get("total_bytes")
        flow_anomalies = []
        if bytes_total is not None and not is_new_server:
            bucket.known_servers_total_bytes += bytes_total
            bucket.known_servers_flow_count += 1

            server_model = self.get_or_create_server_model(state, server)
            if (
                self.should_detect(state)
                and server_model.count >= self.min_baseline_points
            ):
                z = server_model.zscore(bytes_total)
                if z >= self.flow_zscore_threshold:
                    flow_anomalies.append(
                        {
                            "feature": "bytes_to_known_server",
                            "value": bytes_total,
                            "mean": server_model.mean,
                            "zscore": round(z, 3),
                        }
                    )

        if self.should_detect(state):
            if is_new_server:
                flow_anomalies.append(
                    {
                        "feature": "new_server",
                        "value": server,
                    }
                )
            if is_new_ja3:
                flow_anomalies.append(
                    {
                        "feature": "new_ja3",
                        "value": ja3,
                    }
                )
            if is_new_ja3s:
                flow_anomalies.append(
                    {
                        "feature": "new_ja3s",
                        "value": ja3s,
                    }
                )

        if flow_anomalies:
            bucket.flow_anomaly_count += 1
            state.anomaly_history_ts.append(ts)
            baseline_count = self.get_host_baseline_count(state)
            if bytes_total is not None:
                baseline_count = max(
                    baseline_count,
                    self.get_or_create_server_model(state, server).count,
                )
            confidence = self.score_confidence(
                state=state,
                ts=ts,
                reasons=flow_anomalies,
                baseline_count=baseline_count,
            )
            self.log_event(
                1,
                "flow_detection",
                "Flow-level anomaly detected.",
                traffic_ts=ts,
                metrics={
                    "profileid": profileid,
                    "confidence": confidence["level"],
                    "confidence_score": confidence["score"],
                    "confidence_factors": {
                        "severity": confidence["severity"],
                        "persistence": confidence["persistence"],
                        "baseline_quality": confidence["baseline_quality"],
                        "multi_signal": confidence["multi_signal"],
                        "max_z": confidence["max_z"],
                    },
                    "uid": uid,
                    "server": server,
                    "flow_anomalies": flow_anomalies,
                },
            )
            self.emit_anomaly_evidence(
                profileid=profileid,
                twid_number=twid_number,
                traffic_ts=ts,
                uid=uid,
                confidence=confidence,
                reasons=flow_anomalies,
                kind="flow",
                ssl_flow=ssl_flow,
                server=server,
                sni=sni,
                daddr=conn_info.get("daddr", ""),
                extra={"bytes_total": bytes_total},
            )

        if bytes_total is not None:
            server_model = self.get_or_create_server_model(state, server)
            if not self.should_detect(state):
                alpha = None
                self.fit_benign_model(server_model, bytes_total)
            elif not flow_anomalies:
                alpha = self.baseline_alpha
                self.update_model(server_model, bytes_total, alpha)
            elif len(flow_anomalies) <= self.max_small_flow_anomalies:
                alpha = self.drift_alpha
                self.update_model(server_model, bytes_total, alpha)
            else:
                alpha = self.suspicious_alpha
                self.update_model(server_model, bytes_total, alpha)
            self.log_event(
                3,
                "model_update",
                "Per-server bytes model updated.",
                traffic_ts=ts,
                metrics={
                    "profileid": profileid,
                    "server": server,
                    "value": bytes_total,
                    "mean": round(server_model.mean, 6),
                    "var": round(server_model.var, 6),
                    "count": server_model.count,
                    "min_std_floor": round(server_model.min_std_floor, 6),
                    "alpha": alpha,
                    "fit_method": (
                        "welford_online_moments"
                        if alpha is None
                        else "ewma"
                    ),
                },
            )

        state.known_servers.add(server)
        if ja3:
            state.known_ja3.add(ja3)
        if ja3s:
            state.known_ja3s.add(ja3s)

    def handle_new_ssl(self, msg: dict):
        payload = json.loads(msg["data"])
        profileid = payload.get("profileid", "")
        twid_number = self.parse_twid_number(payload.get("twid"))
        ssl_flow = self.classifier.convert_to_flow_obj(payload["flow"])

        conn_flow = None
        uid = getattr(ssl_flow, "uid", "")
        if uid:
            try:
                conn_flow = utils.get_original_conn_flow(ssl_flow, self.db)
            except (StopIteration, TypeError, KeyError, json.JSONDecodeError):
                conn_flow = None
            if conn_flow:
                self.log_event(
                    3,
                    "flow_arrival",
                    "SSL flow matched with conn flow from DB.",
                    traffic_ts=self.get_traffic_ts(ssl_flow),
                    metrics={"profileid": profileid, "uid": uid},
                )

        conn_info = {}
        if conn_flow:
            conn_info = {
                "uid": uid,
                "daddr": conn_flow.get("daddr", ""),
                "total_bytes": self.to_float(conn_flow.get("sbytes", 0))
                + self.to_float(conn_flow.get("dbytes", 0)),
                "starttime": self.to_float(conn_flow.get("starttime"), 0.0),
            }
        self.process_ssl_event(
            profileid=profileid,
            ssl_flow=ssl_flow,
            conn_info=conn_info,
            twid_number=twid_number,
        )

    def main(self):
        if msg := self.get_msg("new_ssl"):
            self.handle_new_ssl(msg)
