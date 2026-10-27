"""Bounded SMB behavior correlation using Zeek metadata and capture timestamps."""

import ipaddress
import math
from collections import OrderedDict
from itertools import islice
from dataclasses import dataclass, field
from typing import Any

from .settings import Settings


@dataclass
class Finding:
    """An explained behavior with bounded supporting records."""

    kind: str
    flow: dict[str, Any]
    description: str
    uids: list[str]
    details: dict[str, Any]


@dataclass
class Source:
    """Distinct recent observations belonging to one source on one network."""

    events: OrderedDict = field(default_factory=OrderedDict)
    categories: set[str] = field(default_factory=set)
    last: float = 0
    evaluated: float = -math.inf
    scan_seen: float = -math.inf
    probe_updates: int = 0


class Detector:
    """Correlate SMB activity without Redis keys, disk queries or body inspection."""

    def __init__(self, settings: Settings) -> None:
        """Initialize resource-bounded state.

        :param settings: Validated thresholds and rule options.
        """
        settings.validate()
        self.settings = settings
        self.sources: OrderedDict = OrderedDict()
        self.sessions: OrderedDict = OrderedDict()
        self.cooldowns: OrderedDict = OrderedDict()
        self.seen: OrderedDict = OrderedDict()
        self.highwater = 0.0
        self.total_events = 0
        self.evictions = 0
        self.allowed = [
            ipaddress.ip_network(n, strict=False)
            for n in settings.external_allowed_networks
        ]

    @staticmethod
    def share(path: str) -> tuple[str, str]:
        """Split a UNC path without resolving the server name.

        :param path: SMB path supplied by Zeek.
        :return: Claimed server and share name, or empty strings.
        """
        parts = str(path or "").replace("/", "\\").lstrip("\\").split("\\")
        return (
            (parts[0].lower(), parts[1].lower())
            if len(parts) >= 2
            else ("", "")
        )

    def _remember(
        self,
        context: Source,
        category: str,
        key: str,
        ts: float,
        dst: str,
        label: str,
        uid: str,
    ) -> None:
        """Retain one distinct observation, bounded per source and globally.

        :param context: Source state.
        :param category: Behavior counter category.
        :param key: Distinct target, file or authentication identifier.
        :param ts: Capture timestamp.
        :param dst: Actual destination IP.
        :param label: Share, filename, account or status.
        :param uid: Supporting stored event ID or connection UID.
        """
        for old_key in list(islice(context.events, 8)):
            old = context.events[old_key]
            retention = (
                self.settings.correlation_seconds
                if old_key[0] in {"executable", "rpc"}
                else self.settings.window_seconds
            )
            if old[0] < self.highwater - retention:
                del context.events[old_key]
                self.total_events -= 1
        context.categories.add(category)
        index = (category, key)
        previous = context.events.get(index)
        if previous and previous[0] > ts:
            return
        self.total_events += int(index not in context.events)
        context.events[index] = (ts, dst, label, uid)
        context.events.move_to_end(index)
        while len(context.events) > self.settings.max_events_per_source:
            context.events.popitem(last=False)
            self.total_events -= 1
            self.evictions += 1
        while self.total_events > self.settings.max_total_events:
            oldest_key = next(iter(self.sources))
            oldest = self.sources[oldest_key]
            if not oldest.events:
                self.sources.pop(oldest_key)
                continue
            oldest.events.popitem(last=False)
            self.total_events -= 1
            self.evictions += 1

    def _recent(
        self,
        context: Source,
        category: str,
        ts: float,
        window: float | None = None,
    ) -> list[tuple]:
        """Return observations in the requested capture-time interval.

        :param context: Source state.
        :param category: Observation category.
        :param ts: Interval end in capture seconds.
        :param window: Optional interval duration.
        :return: Matching compact observations; future events are excluded.
        """
        if category not in context.categories:
            return []
        window = self.settings.window_seconds if window is None else window
        return [
            v
            for (kind, _), v in context.events.items()
            if kind == category and ts - window <= v[0] <= ts
        ]

    def _emit(
        self,
        output: list[Finding],
        scope: str,
        kind: str,
        flow: dict,
        text: str,
        records: list[tuple] | None = None,
        destination: str = "",
        **details: Any,
    ) -> None:
        """Rate-limit an explained finding independently for each rule and source.

        :param output: Findings produced during this event.
        :param scope: Capture network identity.
        :param kind: Evidence type.
        :param flow: Triggering record with original endpoint directions.
        :param text: Human-readable explanation.
        :param records: Compact supporting observations.
        :param destination: Optional per-server cooldown scope.
        :param details: Structured counts and decision context.
        """
        if not self.settings.rule(kind)[0]:
            return
        ts = float(flow["starttime"])
        key = (scope, flow["saddr"], kind, destination)
        previous = self.cooldowns.get(key, -math.inf)
        if ts < previous + self.settings.cooldown_seconds:
            return
        self.cooldowns[key] = ts
        self.cooldowns.move_to_end(key)
        while len(self.cooldowns) > self.settings.max_cooldowns:
            self.cooldowns.popitem(last=False)
        uids = [str(flow.get("record_id") or flow["uid"]), str(flow["uid"])]
        uids.extend(v[3] for v in (records or [])[-18:])
        output.append(
            Finding(
                kind,
                flow.copy(),
                text,
                list(dict.fromkeys(uids)),
                {
                    "window_seconds": self.settings.window_seconds,
                    "connection_uid": flow["uid"],
                    **details,
                },
            )
        )

    def _analyze(
        self, context: Source, scope: str, flow: dict
    ) -> list[Finding]:
        """Evaluate distinct-host, authentication and file-change behaviors.

        :param context: Source state.
        :param scope: Capture network identity.
        :param flow: Current triggering record.
        :return: Independent findings with observation-based explanations.
        """
        output: list[Finding] = []
        ts, src = float(flow["starttime"]), flow["saddr"]
        probes = self._recent(context, "probe", ts)
        failures = sum(v[2] == "failed" for v in probes)
        if (
            len(probes) >= self.settings.scan_min_hosts
            and failures / len(probes) >= self.settings.scan_min_failure_ratio
        ):
            context.scan_seen = max(context.scan_seen, ts)
            self._emit(
                output,
                scope,
                "SMB_SCAN",
                flow,
                f"{src} attempted SMB connections to {len(probes)} distinct hosts in {self.settings.window_seconds:g}s; {failures} did not establish a TCP session. This is SMB scanning behavior.",
                probes,
                distinct_hosts=len(probes),
                failed_hosts=failures,
            )
        shares = self._recent(context, "share", ts)
        hosts = {v[1] for v in shares}
        share_names = {v[2] for v in shares}
        if (
            len(hosts) >= self.settings.share_min_hosts
            or len(share_names) >= self.settings.share_min_names
        ):
            self._emit(
                output,
                scope,
                "SMB_SHARE_SWEEP",
                flow,
                f"{src} accessed {len(share_names)} distinct SMB share names across {len(hosts)} hosts in {self.settings.window_seconds:g}s. Broad share access may be enumeration or administration; a single IPC$ access is insufficient.",
                shares,
                distinct_hosts=len(hosts),
                distinct_share_names=len(share_names),
            )
        mismatches = self._recent(context, "mismatch", ts)
        by_claim: dict[str, list] = {}
        for record in mismatches:
            by_claim.setdefault(record[2], []).append(record)
        repeated = max(by_claim.values(), key=len, default=[])
        if len({v[1] for v in repeated}) >= self.settings.mismatch_min_hosts:
            self._emit(
                output,
                scope,
                "SMB_SHARE_PATH_MISMATCH",
                flow,
                f"{src} reused SMB path server {repeated[0][2]} while connecting to {len(repeated)} different actual destination IPs. Repeated mismatched path addresses can indicate crafted requests; aliases or translation can also explain them.",
                repeated,
                claimed_server=repeated[0][2],
                actual_hosts=len(repeated),
            )
            if (
                len(probes) >= self.settings.propagation_min_hosts
                or len(hosts) >= self.settings.propagation_min_hosts
            ):
                self._emit(
                    output,
                    scope,
                    "SMB_SUSPECTED_PROPAGATION",
                    flow,
                    f"Suspected SMB propagation by {src}: broad SMB probing/share access together with the same mismatched path address across {len(repeated)} servers. This identifies an attack-like sequence, not confirmed exploitation or a malware family.",
                    repeated + probes[-8:],
                    mismatch_hosts=len(repeated),
                    probed_hosts=len(probes),
                    share_hosts=len(hosts),
                )
        failures = self._recent(context, "auth", ts)
        accounts = {v[2] for v in failures if v[2]}
        auth_hosts = {v[1] for v in failures}
        if len(failures) >= self.settings.auth_min_failures:
            self._emit(
                output,
                scope,
                "SMB_PASSWORD_GUESSING",
                flow,
                f"{src} had {len(failures)} explicitly failed SMB authentication connections in {self.settings.window_seconds:g}s across {len(auth_hosts)} hosts and {len(accounts)} known accounts. Missing authentication results were not counted.",
                failures,
                failures=len(failures),
                accounts=len(accounts),
                hosts=len(auth_hosts),
            )
            if (
                len(accounts) >= self.settings.spray_min_accounts
                or len(auth_hosts) >= self.settings.spray_min_hosts
            ):
                self._emit(
                    output,
                    scope,
                    "SMB_PASSWORD_SPRAYING",
                    flow,
                    f"Possible SMB password spraying by {src}: {len(failures)} failed authentications across {len(accounts)} accounts and {len(auth_hosts)} hosts. Password values are unavailable, so reuse of one password is not proven.",
                    failures,
                    failures=len(failures),
                    accounts=len(accounts),
                    hosts=len(auth_hosts),
                )
        changes = self._recent(context, "change", ts)
        renames = list({v[1]: v for v in changes if v[2] == "RENAME"}.values())
        others = list(
            {v[1]: v for v in changes if v[2] in {"WRITE", "DELETE"}}.values()
        )
        distinct = {v[1] for v in changes}
        if len(distinct) >= self.settings.file_change_min_files:
            self._emit(
                output,
                scope,
                "SMB_RAPID_FILE_CHANGES",
                flow,
                f"{src} issued modification operations affecting {len(distinct)} distinct SMB files in {self.settings.window_seconds:g}s. Bulk writes, renames and deletions can come from backups or administration as well as malware; their success is not established.",
                changes,
                distinct_files=len(distinct),
                renames=len(renames),
                other_changes=len(others),
            )
        if (
            len(renames) >= self.settings.ransomware_min_renames
            and len(others) >= self.settings.ransomware_min_other_changes
        ):
            self._emit(
                output,
                scope,
                "SMB_RANSOMWARE_BEHAVIOR",
                flow,
                f"Possible ransomware activity by {src}: rapid renames of {len(renames)} distinct SMB files together with writes/deletions affecting {len(others)} distinct files. Content encryption and local-only file changes cannot be established from these records.",
                changes,
                renames=len(renames),
                other_changed_files=len(others),
            )
        return output

    def _transfer(
        self, scope: str, context: Source, session: dict
    ) -> list[Finding]:
        """Assess directional volume only after SMB protocol confirmation.

        :param scope: Capture network identity.
        :param context: Source's recent scanning context.
        :param session: Correlated connection and SMB metadata.
        :return: Ordinary volume finding and any stronger correlated finding.
        """
        output: list[Finding] = []
        flow = session.get("conn")
        if not flow:
            return output
        sent, received = float(flow.get("sbytes") or 0), float(
            flow.get("dbytes") or 0
        )
        confirmed = bool(session.get("mapped") or session.get("protocol"))
        if (
            not confirmed
            or max(sent, received) < self.settings.large_transfer_bytes
        ):
            return output
        ts = float(flow["starttime"])
        records = session.get("records", [])
        self._emit(
            output,
            scope,
            "SMB_LARGE_TRANSFER",
            flow,
            f"Established SMB session {flow['saddr']} → {flow['daddr']}: client sent {sent:,.0f} bytes and received {received:,.0f} bytes. A large SMB session alone is not an attack or proof that an individual file was transferred.",
            records,
            destination=flow["daddr"],
            sent_bytes=sent,
            received_bytes=received,
            smb_mapping_seen=bool(session.get("mapped")),
        )
        scan = abs(context.scan_seen - ts) <= self.settings.correlation_seconds
        mismatched_hosts = {
            v[1]
            for v in self._recent(
                context,
                "mismatch",
                max(ts, context.last),
                self.settings.correlation_seconds,
            )
            if v[2] == session.get("claimed")
        }
        repeated_mismatch = bool(
            session.get("mismatch")
            and len(mismatched_hosts) >= self.settings.mismatch_min_hosts
        )
        if sent >= self.settings.large_transfer_bytes and (
            scan or repeated_mismatch
        ):
            self._emit(
                output,
                scope,
                "SMB_SUSPICIOUS_TRANSFER",
                flow,
                f"Suspicious SMB data transfer from {flow['saddr']} to {flow['daddr']}: {sent:,.0f} client-to-server bytes after SMB was observed, with {'recent SMB scanning' if scan else 'repeated mismatched share paths across multiple servers'}. This combination may indicate propagation or payload delivery; successful code execution is not proven.",
                records,
                destination=flow["daddr"],
                sent_bytes=sent,
                received_bytes=received,
                scan_context=scan,
                mismatched_path=repeated_mismatch,
                connection_start=ts,
                connection_end=ts + float(flow.get("dur") or 0),
            )
        return output

    def process(
        self, flow: dict[str, Any], scope: str = "capture"
    ) -> list[Finding]:
        """Consume an original-direction Zeek connection or SMB-related record.

        :param flow: Normalized, timestamped record; raw body data is never used.
        :param scope: Network/interface identity, isolated between capture runs.
        :return: Findings supported by this event and bounded recent history.
        """
        if not self.settings.enabled:
            return []
        try:
            ts = float(flow["starttime"])
            src, dst = ipaddress.ip_address(
                flow["saddr"]
            ), ipaddress.ip_address(flow["daddr"])
            port = int(flow.get("dport") or 0)
        except (ValueError, TypeError, KeyError):
            return []
        kind = flow.get("type_")
        if kind not in {
            "conn",
            "smb_mapping",
            "smb_files",
            "smb_cmd",
            "ntlm",
            "dce_rpc",
        }:
            return []
        if (
            not math.isfinite(ts)
            or src.is_multicast
            or dst.is_multicast
            or src.is_unspecified
            or dst.is_unspecified
            or str(dst) == "255.255.255.255"
            or not flow.get("uid")
        ):
            return []
        if kind != "dce_rpc" and port not in self.settings.ports:
            return []
        if kind == "conn" and (
            str(flow.get("proto")).lower() != "tcp"
            or "^" in str(flow.get("history", ""))
        ):
            return []
        self.highwater = max(self.highwater, ts)
        if ts < self.highwater - self.settings.max_lateness_seconds:
            return []
        identity = (scope, flow.get("record_id") or (kind, flow["uid"]))
        if identity in self.seen:
            return []
        self.seen[identity] = ts
        while len(self.seen) > self.settings.max_total_events:
            self.seen.popitem(last=False)
        source_key = (scope, str(src))
        context = self.sources.setdefault(source_key, Source())
        context.last = max(context.last, ts)
        self.sources.move_to_end(source_key)
        while (
            len(self.sources) > self.settings.max_sources
            or self.total_events > self.settings.max_total_events
        ):
            _, dropped = self.sources.popitem(last=False)
            self.total_events -= len(dropped.events)
            self.evictions += 1
        session_key = (scope, flow["uid"])
        session = self.sessions.get(session_key, {"last": ts, "records": []})
        session["last"] = max(session["last"], ts)
        track_session = (
            kind != "conn"
            or session_key in self.sessions
            or float(flow.get("sbytes") or 0) + float(flow.get("dbytes") or 0)
            > 0
        )
        if track_session:
            self.sessions[session_key] = session
            self.sessions.move_to_end(session_key)
        while len(self.sessions) > self.settings.max_sessions:
            self.sessions.popitem(last=False)
            self.evictions += 1
        record_uid = str(flow.get("record_id") or flow["uid"])
        output: list[Finding] = []
        if kind == "conn":
            history = str(flow.get("history", ""))
            failed = flow.get("state") in {"S0", "REJ", "RSTOS0"}
            if "S" in history or flow.get("state") in {"S0", "REJ"}:
                self._remember(
                    context,
                    "probe",
                    str(dst),
                    ts,
                    str(dst),
                    "failed" if failed else "answered",
                    record_uid,
                )
                context.probe_updates += 1
            session["conn"] = flow.copy()
            session["protocol"] = (
                "smb" in str(flow.get("appproto", "")).lower().split(",")
                and float(flow.get("dbytes") or 0) > 0
            )
        elif kind == "smb_mapping":
            claimed, share = self.share(flow.get("path", ""))
            if share:
                self._remember(
                    context,
                    "share",
                    f"{dst}/{share}",
                    ts,
                    str(dst),
                    share,
                    record_uid,
                )
            session["mapped"] = True
            session["records"] = [(ts, str(dst), share, record_uid)]
            try:
                mismatch = ipaddress.ip_address(claimed) != dst
            except ValueError:
                mismatch = False
            if mismatch:
                session["mismatch"] = True
                session["claimed"] = claimed
                self._remember(
                    context,
                    "mismatch",
                    f"{claimed}/{dst}",
                    ts,
                    str(dst),
                    claimed,
                    record_uid,
                )
        elif kind == "smb_files":
            action = (
                str(flow.get("action", ""))
                .split("::")[-1]
                .removeprefix("FILE_")
            )
            path = str(flow.get("path", ""))
            name = str(flow.get("name", ""))
            filename_key = f"{dst}/{path.lower()}/{name.lower()}"
            alias = context.events.get(("alias", filename_key))
            handle_id = str(flow.get("file_id") or flow.get("fuid") or "")
            handle = (
                context.events.get(("handle", handle_id))
                if handle_id
                else None
            )
            file_key = (
                handle[2] if handle else alias[2] if alias else filename_key
            )
            if action == "RENAME" and flow.get("prev_name"):
                previous_key = (
                    f"{dst}/{path.lower()}/{str(flow['prev_name']).lower()}"
                )
                previous_alias = context.events.get(("alias", previous_key))
                file_key = (
                    handle[2]
                    if handle
                    else previous_alias[2] if previous_alias else previous_key
                )
            if action == "RENAME":
                self._remember(
                    context,
                    "alias",
                    filename_key,
                    ts,
                    str(dst),
                    file_key,
                    record_uid,
                )
            if handle_id and name:
                self._remember(
                    context,
                    "handle",
                    handle_id,
                    ts,
                    str(dst),
                    file_key,
                    record_uid,
                )
            if name and action in {"WRITE", "RENAME", "DELETE"}:
                self._remember(
                    context,
                    "change",
                    f"{file_key}/{action}",
                    ts,
                    file_key,
                    action,
                    record_uid,
                )
            if (
                action in {"READ", "WRITE", "CLOSE"}
                and float(flow.get("size") or 0)
                >= self.settings.large_file_bytes
            ):
                self._emit(
                    output,
                    scope,
                    "SMB_LARGE_FILE",
                    flow,
                    f"{src} accessed SMB file {path}\\{name} on {dst}, reported size {float(flow['size']):,.0f} bytes. File size is not a measurement of how many bytes were transferred.",
                    destination=str(dst),
                    name=name,
                    path=path,
                    reported_size=flow["size"],
                    action=action,
                )
            _, share = self.share(path)
            written = action == "WRITE" or (
                action == "CLOSE" and flow.get("write_seen") in (True, "T")
            )
            if (
                written
                and share in {s.lower() for s in self.settings.admin_shares}
                and any(
                    name.lower().endswith(ext.lower())
                    for ext in self.settings.executable_extensions
                )
            ):
                self._remember(
                    context,
                    "executable",
                    f"{dst}/{path}/{name}",
                    ts,
                    str(dst),
                    name,
                    record_uid,
                )
        elif kind in {"ntlm", "smb_cmd"}:
            status = (
                str(flow.get("status", ""))
                .upper()
                .removeprefix("NT_STATUS_")
                .removeprefix("STATUS_")
            )
            failure = kind == "ntlm" and flow.get("success") in (False, "F")
            failure = failure or (
                kind == "smb_cmd"
                and "SESSION_SETUP" in str(flow.get("command", "")).upper()
                and status in self.settings.authentication_failure_statuses
            )
            if failure:
                account = str(flow.get("username") or "").lower()
                # Both ntlm.log and smb_cmd.log can describe the same failed login.
                previous = context.events.get(("auth", flow["uid"]))
                account = account or (previous[2] if previous else "")
                self._remember(
                    context,
                    "auth",
                    flow["uid"],
                    ts,
                    str(dst),
                    account,
                    record_uid,
                )
        elif kind == "dce_rpc":
            operation = str(flow.get("operation", ""))
            if (
                str(flow.get("endpoint", "")).lower() == "svcctl"
                and operation in self.settings.remote_service_operations
            ):
                self._remember(
                    context,
                    "rpc",
                    record_uid,
                    ts,
                    str(dst),
                    operation,
                    record_uid,
                )
        if kind in {"dce_rpc", "smb_files"}:
            for rpc in self._recent(
                context, "rpc", context.last, self.settings.correlation_seconds
            ):
                executables = [
                    v
                    for v in self._recent(
                        context,
                        "executable",
                        rpc[0],
                        self.settings.correlation_seconds,
                    )
                    if v[1] == rpc[1]
                ]
                if executables:
                    trigger = {
                        **flow,
                        "starttime": max(ts, rpc[0]),
                        "daddr": rpc[1],
                    }
                    self._emit(
                        output,
                        scope,
                        "SMB_REMOTE_EXECUTION",
                        trigger,
                        f"{src} sent an executable write operation to an administrative SMB share on {rpc[1]}, then requested remote service operation {rpc[2]}. This sequence can indicate lateral movement or authorized deployment; the RPC result and successful execution are not established by the standard Zeek record.",
                        executables + [rpc],
                        destination=rpc[1],
                        operation=rpc[2],
                        files=[v[2] for v in executables[-8:]],
                    )
        if kind == "smb_mapping" or (
            kind == "conn" and session.get("protocol")
        ):
            if dst.is_global and not any(dst in n for n in self.allowed):
                self._emit(
                    output,
                    scope,
                    "SMB_EXTERNAL_CONNECTION",
                    flow,
                    f"{src} communicated using SMB with public server {dst}:{port}, outside the configured external SMB exceptions. External SMB can expose file-sharing or administration services; this alone does not establish an attack.",
                    destination=str(dst),
                )
        if (
            kind != "conn"
            or ts
            >= context.evaluated + self.settings.evaluation_interval_seconds
            or context.probe_updates % self.settings.scan_min_hosts == 0
        ):
            analysis_flow = {**flow, "starttime": context.last}
            output.extend(self._analyze(context, scope, analysis_flow))
            context.evaluated = max(context.evaluated, ts)
        output.extend(self._transfer(scope, context, session))
        # Small bounded housekeeping batches also run when sources become idle.
        cutoff = (
            self.highwater
            - self.settings.max_lateness_seconds
            - self.settings.correlation_seconds
        )
        for table in (self.sources, self.sessions, self.seen, self.cooldowns):
            for key in list(islice(table, 8)):
                value = table[key]
                last = (
                    value.last
                    if isinstance(value, Source)
                    else (
                        value.get("last", 0)
                        if isinstance(value, dict)
                        else value
                    )
                )
                if last < cutoff:
                    removed = table.pop(key)
                    if isinstance(removed, Source):
                        self.total_events -= len(removed.events)
        return output
