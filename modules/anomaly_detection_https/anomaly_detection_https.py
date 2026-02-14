# SPDX-FileCopyrightText: 2026 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
import math
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Optional, Set

from slips_files.common.abstracts.imodule import IModule
from slips_files.common.flow_classifier import FlowClassifier
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils


@dataclass
class EWMAStats:
    mean: float = 0.0
    var: float = 0.0
    count: int = 0

    def update(self, value: float, alpha: float):
        value = float(value)
        if self.count == 0:
            self.mean = value
            self.var = 0.0
            self.count = 1
            return

        delta = value - self.mean
        self.mean += alpha * delta
        self.var = (1 - alpha) * (self.var + alpha * delta * delta)
        self.count += 1

    def zscore(self, value: float, min_std: float = 0.1) -> float:
        std = math.sqrt(max(self.var, min_std * min_std))
        return abs(float(value) - self.mean) / std


@dataclass
class HourBucket:
    start_ts: int
    ssl_flows: int = 0
    servers: Set[str] = field(default_factory=set)
    new_servers: Set[str] = field(default_factory=set)
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


class AnomalyDetectionHTTPS(IModule):
    name = "Anomaly Detection HTTPS"
    description = (
        "HTTPS anomaly detector with hourly adaptive baselines and "
        "flow-level checks."
    )
    authors = ["Sebastian Garcia"]

    def init(self):
        self.c1 = self.db.subscribe("new_ssl")
        self.c2 = self.db.subscribe("new_flow")
        self.channels = {"new_ssl": self.c1, "new_flow": self.c2}
        self.classifier = FlowClassifier()
        self.read_configuration()
        self.operational_log_path = os.path.join(
            self.output_dir, "anomaly_detection_https.log"
        )

        self.host_states: Dict[str, HostState] = {}
        self.conn_cache: Dict[str, dict] = {}
        self.pending_ssl_by_uid: Dict[str, dict] = {}
        self.last_cache_cleanup_ts = time.time()
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
        self.log_emojis = conf.https_anomaly_log_emojis()
        self.log_colors = conf.https_anomaly_log_colors()

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
        if not self.log_colors:
            return ""
        colors = {
            "flow_arrival": "\033[36m",
            "hour_close": "\033[36m",
            "training_fit": "\033[34m",
            "drift_update": "\033[35m",
            "suspicious_update": "\033[35m",
            "model_update": "\033[34m",
            "flow_detection": "\033[31m",
            "hourly_detection": "\033[31m",
            "module_start": "\033[32m",
            "module_stop": "\033[32m",
        }
        return colors.get(event_type, "")

    def get_emoji(self, event_type: str) -> str:
        if not self.log_emojis:
            return ""
        emojis = {
            "flow_arrival": "📥",
            "hour_close": "🕐",
            "training_fit": "🎓",
            "drift_update": "🌊",
            "suspicious_update": "🐢",
            "model_update": "🧠",
            "flow_detection": "🚨",
            "hourly_detection": "🚨",
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

    def get_detection_confidence(self) -> str:
        # If the user disables warmup (training_hours=0), detections are
        # unsupervised from the beginning and should be treated with caution.
        if self.training_hours == 0:
            return "low"
        return "high"

    def score_feature(self, model: EWMAStats, value: float) -> float:
        if model.count < self.min_baseline_points:
            return 0.0
        return model.zscore(value)

    def update_model(self, model: EWMAStats, value: float, alpha: float):
        if alpha <= 0:
            return
        model.update(value, alpha)

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
                self.log_event(
                    1,
                    "hourly_detection",
                    "Hourly anomaly detected for host.",
                    traffic_ts=bucket.start_ts,
                    metrics={
                        "profileid": profileid,
                        "confidence": self.get_detection_confidence(),
                        "hour_start": bucket.start_ts,
                        "anomaly_score": round(hourly_score, 3),
                        "flow_anomaly_count": bucket.flow_anomaly_count,
                        "anomalies": hourly_anomalies,
                    },
                )

        update_mode = "training_fit"
        if not self.should_detect(state):
            update_alpha = self.baseline_alpha
            state.trained_hours += 1
            self.log_event(
                1,
                "training_fit",
                "Baseline training hour fitted.",
                traffic_ts=bucket.start_ts,
                metrics={
                    "profileid": profileid,
                    "trained_hours": state.trained_hours,
                    "target_training_hours": self.training_hours,
                    "alpha": update_alpha,
                },
            )
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
                    "alpha": update_alpha,
                },
            )

        state.bucket = None

    def clean_old_conn_cache(self):
        now = time.time()
        if now - self.last_cache_cleanup_ts < 30:
            return
        self.last_cache_cleanup_ts = now

        max_age = 300
        self.conn_cache = {
            uid: data
            for uid, data in self.conn_cache.items()
            if now - data["cache_ts"] <= max_age
        }
        self.pending_ssl_by_uid = {
            uid: data
            for uid, data in self.pending_ssl_by_uid.items()
            if now - data["cache_ts"] <= max_age
        }

    def process_ssl_event(self, profileid: str, ssl_flow, conn_info: dict):
        ts = self.get_traffic_ts(
            ssl_flow, fallback_ts=self.to_float(conn_info.get("starttime"), 0.0)
        )
        state = self.ensure_hour_bucket(profileid, ts)
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
            self.log_event(
                1,
                "flow_detection",
                "Flow-level anomaly detected.",
                traffic_ts=ts,
                metrics={
                    "profileid": profileid,
                    "confidence": self.get_detection_confidence(),
                    "uid": uid,
                    "server": server,
                    "flow_anomalies": flow_anomalies,
                },
            )

        if bytes_total is not None:
            server_model = self.get_or_create_server_model(state, server)
            if not self.should_detect(state) or not flow_anomalies:
                alpha = self.baseline_alpha
            elif len(flow_anomalies) <= self.max_small_flow_anomalies:
                alpha = self.drift_alpha
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
                    "alpha": alpha,
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
        ssl_flow = self.classifier.convert_to_flow_obj(payload["flow"])

        uid = getattr(ssl_flow, "uid", "")
        if not uid:
            self.process_ssl_event(profileid, ssl_flow, {})
            return

        conn_info = self.conn_cache.get(uid)
        if conn_info is not None:
            self.process_ssl_event(profileid, ssl_flow, conn_info)
            return

        self.pending_ssl_by_uid[uid] = {
            "profileid": profileid,
            "ssl_flow": ssl_flow,
            "cache_ts": time.time(),
        }

    def handle_new_flow(self, msg: dict):
        payload = json.loads(msg["data"])
        flow = self.classifier.convert_to_flow_obj(payload["flow"])
        if getattr(flow, "type_", "") != "conn":
            return

        uid = getattr(flow, "uid", "")
        if not uid:
            return

        conn_info = {
            "uid": uid,
            "daddr": getattr(flow, "daddr", ""),
            "total_bytes": self.to_float(getattr(flow, "sbytes", 0))
            + self.to_float(getattr(flow, "dbytes", 0)),
            "starttime": self.get_traffic_ts(flow),
            "cache_ts": time.time(),
        }
        self.conn_cache[uid] = conn_info
        self.log_event(
            3,
            "flow_arrival",
            "Conn flow received and cached for SSL correlation.",
            traffic_ts=conn_info["starttime"],
            metrics={
                "uid": uid,
                "daddr": conn_info["daddr"],
                "total_bytes": conn_info["total_bytes"],
            },
        )

        pending_ssl = self.pending_ssl_by_uid.pop(uid, None)
        if not pending_ssl:
            return

        self.process_ssl_event(
            pending_ssl["profileid"], pending_ssl["ssl_flow"], conn_info
        )

    def main(self):
        self.clean_old_conn_cache()

        if msg := self.get_msg("new_flow"):
            self.handle_new_flow(msg)

        if msg := self.get_msg("new_ssl"):
            self.handle_new_ssl(msg)
