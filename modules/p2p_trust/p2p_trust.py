# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import errno
import ipaddress
import os
import shutil
import signal
import socket
import sqlite3
import subprocess
import netifaces
import psutil
import time
from pathlib import Path
from typing import Dict, Optional
import json

from slips_files.common.ips import IPV4_LOCALHOST, LOCALHOST_HOSTNAME
from slips_files.common.style import green
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from slips_files.common.abstracts.imodule import IModule
from slips_files.core.database.redis_db.redis_auth import (
    get_redis_auth_conf_path,
)
import modules.p2p_trust.trust.base_model as reputation_model
import modules.p2p_trust.utils.utils as p2p_utils
from modules.p2p_trust.trust.report_validation import (
    ReportValidator,
    observation_record,
    local_reputation_half_life,
)
from slips_files.core.database.sqlite_db.host_profiles import HostProfileStore
from modules.supported_module_names import Modules
from modules.p2p_trust.utils.go_director import GoDirector
from slips_files.core.structures.evidence import (
    dict_to_evidence,
    Evidence,
    ProfileID,
    TimeWindow,
    Attacker,
    ThreatLevel,
    EvidenceType,
    IoCType,
    Direction,
)

LOCALHOST = IPV4_LOCALHOST


def validate_slips_data(message_data: str) -> (str, int):
    """
    Check that message received from p2p_data_request channel has correct
    format:  json serialized {
                    'ip': str(saddr),
                    'profileid' : str(profileid),
                    'twid' :  str(twid),
                    'proto' : str(proto),
                    'ip_state' : 'srcip',
                    'stime': starttime,
                    'uid': uid,
                    'cache_age': cache_age
                }

    If the message is correct, the two values are
     returned as a tuple (str, int).
    If not, (None, None) is returned.
    :param message_data: data from slips request channel
    :return: the received msg or None tuple
    """

    try:
        message_data = json.loads(message_data)
        ip_address = message_data.get("ip")
        # time_since_cached = int(message_data.get('cache_age', 0))
        return message_data if p2p_utils.is_unicast_ip(ip_address) else None
    except ValueError:
        # message has wrong format
        print(
            f"The message received from p2p_data_request channel"
            f" has incorrect format: {message_data}"
        )
        return None


class Trust(IModule):
    name = "p2p_trust"
    description = "Enables sharing detection data with other Slips instances"
    authors = ["Dita", "Alya Gomaa"]
    pigeon_port = 6668
    rename_with_port = False
    # slips_update_channel = "ip_info_change"
    p2p_data_request_channel = "p2p_data_request"
    gopy_channel_raw = "p2p_gopy"
    pygo_channel_raw = "p2p_pygo"
    # weight given to Slips' own local opinion of an IP, vs. the
    # network's, when deciding whether to act on a peer's blame report.
    # 1 means the network's blame is ignored completely, 0 means only
    # the network's opinion matters.
    ips_weight = 0.5
    # the minimum combined (local + network) opinion an IP has to reach
    # before a blame report is forwarded to the blocking module. Uses
    # the same 0 (benign) to 1 (malicious) scale as evidence threat
    # levels.
    blame_threshold = 0.5
    start_pigeon = True
    active_p2p_connection_ttl = 300
    p2p_connection_heartbeat_interval = 60
    pigeon_socket_scan_interval = 5
    local_ip_check_interval = 5
    max_bootstrap_peers = 50
    report_min_interval = 300
    report_cache_limit = 4096
    # or make sure the binary is in $PATH
    pigeon_binary_dir = Path.cwd() / "p2p4slips"
    pigeon_binary = pigeon_binary_dir / "p2p4slips"
    pigeon_key_file = "pigeon.keys"
    rename_redis_ip_info = False
    override_p2p = False

    def init(self, *args, **kwargs):
        self.read_configuration()
        self.db.clear_peer_trust()
        # pigeon generate keys and stores them in the following dir, if this
        # is placed in the <output> dir,
        # when restarting slips, it will look for the old keys in the new
        # output dir! so it wont find them and will
        # generate new keys, and therefore new peerid!
        # store the keys in slips main dir so they don't change every run
        self.p2p_trust_runtime_dir = self.db.get_p2p_trust_dir()
        self.sql_db_name = self.db.get_p2p_trust_db_path()

        self.port = self.p2p_listen_port
        self.host = self.get_local_IP()
        self.last_local_ip_check = time.monotonic()
        str_port = str(self.port) if self.rename_with_port else ""

        self.gopy_channel = self.gopy_channel_raw + str_port
        self.pygo_channel = self.pygo_channel_raw + str_port
        # Older Pigeon binaries did not add the Slips version to messages.
        # Only this local, dedicated Go-to-Python channel accepts that format.
        self.unversioned_channels = frozenset({self.gopy_channel})
        self.storage_name = self.db.constants.IPS_INFO
        if self.rename_redis_ip_info:
            self.storage_name += str(self.port)

        # todo don't duplicate this dict, move it to slips_utils
        # all evidence slips detects has threat levels of strings
        # each string should have a corresponding int value to be able to calculate
        # the accumulated threat level and alert
        self.threat_levels = {
            "info": 0,
            "low": 0.2,
            "medium": 0.5,
            "high": 0.8,
            "critical": 1,
        }

        # flag to ensure slips prints multiaddress only once
        self.mutliaddress_printed = False
        self.last_log_rotation_time = time.time()
        self.rotation_period = 86400  # 1 day in seconds
        self.last_report_compaction_time = 0
        self.report_compaction_interval = 5
        self.report_compaction_batch_size = 1000
        self.last_sent_evidence_reports: dict[tuple[str, float], float] = {}
        self.last_p2p_connection_heartbeat_time = 0

    def subscribe_to_channels(self):
        self.c1 = self.db.subscribe("report_to_peers")
        # channel to send msgs to whenever slips needs
        # info from other peers about an ip
        self.c2 = self.db.subscribe(self.p2p_data_request_channel)
        # this channel receives peers requests/updates
        self.c3 = self.db.subscribe(self.gopy_channel)
        self.c_alert = self.db.subscribe("new_alert")
        self.channels = {
            "report_to_peers": self.c1,
            self.p2p_data_request_channel: self.c2,
            self.gopy_channel: self.c3,
            "new_alert": self.c_alert,
        }

    def _init_log_files(self):
        # should be called after reading configs
        self.pigeon_logfile_raw = self.get_module_specific_output_path(
            "p2p.log"
        )
        self.p2p_reports_logfile = self.get_module_specific_output_path(
            "p2p_reports.log"
        )
        if self.create_p2p_logfile:
            self.setup_pigeon_logfile_rotation()

    def setup_pigeon_logfile_rotation(self):
        str_port = str(self.port) if self.rename_with_port else ""
        self.pigeon_logfile = self.pigeon_logfile_raw + str_port
        self.print(f"Storing p2p in {self.pigeon_logfile}")

    def read_configuration(self):
        conf = ConfigParser()
        self.create_p2p_logfile: bool = conf.create_p2p_logfile()
        self.p2p_listen_port: int = conf.p2p_listen_port()
        self.local_reputation_half_life = local_reputation_half_life(
            conf.read_configuration(
                "local_p2p", "local_reputation_half_life_hours", 24
            )
        )
        self.rendezvous: str = conf.read_configuration(
            "local_p2p", "rendezvous", "slips"
        )

    def get_local_IP(self) -> str:
        """Return the capture interface's IPv4 address without Internet access.

        Returns:
            IPv4 address on the selected interface or default-route interface.
        """
        interface = self.args.interface
        if not interface:
            gateway = (
                netifaces.gateways().get("default", {}).get(netifaces.AF_INET)
            )
            interface = gateway[1] if gateway else None
        if interface:
            for address in netifaces.ifaddresses(interface).get(
                netifaces.AF_INET, []
            ):
                if address.get("addr"):
                    return address["addr"]
        raise ValueError(
            "Local P2P requires an interface with an IPv4 address."
        )

    def _configure(self):
        self.trust_db = self.db.trust_db
        self.report_validation = ReportValidator(
            Path(self.db.get_p2p_trust_dir()) / "report_validation.sqlite"
        )
        self.trust_db.execute("DELETE FROM opinion_cache")
        self.reputation_model = reputation_model.BaseModel(
            self.logger,
            self.trust_db,
            self.db,
            self.report_validation,
            self._network_identity,
            self.local_reputation_half_life,
        )

        self.go_director = GoDirector(
            self.logger,
            self.trust_db,
            self.db,
            self.storage_name,
            override_p2p=self.override_p2p,
            report_func=self.evaluate_blame_report,
            request_func=self.respond_to_message_request,
            blame_evaluator=self.evaluate_blame_report,
            gopy_channel=self.gopy_channel,
            pygo_channel=self.pygo_channel,
            p2p_reports_logfile=self.p2p_reports_logfile,
            is_slips_started_by_an_update=getattr(
                self.args, "is_slips_started_by_an_update", False
            ),
            report_validation=self.report_validation,
            network_identity=self._network_identity,
        )

    def _network_identity(self) -> str:
        """Identify the current network without reusing private IPs across networks.

        Returns:
            Gateway identity, or a run-scoped fallback.
        """
        interface = getattr(self.args, "interface", "")
        state = self.db.get_network_state(interface)
        return HostProfileStore.network_id_for_state(
            state if isinstance(state, dict) else {},
            f"{self.parent_output_dir}:{self.db.main_pid}",
        )

    def _review_observation(self, raw: dict) -> dict:
        """Resolve saved feedback without assigning old evidence to today's network.

        Parameters:
            raw: Durable evidence object.

        Returns:
            Validation snapshot with saved or historically resolved network.
        """
        record = observation_record(
            raw, f"run:{self.parent_output_dir}:{self.db.main_pid}"
        )
        if (
            record
            and not raw.get("detection_provenance")
            and not raw.get("peer_report")
        ):
            path = (
                self.report_validation.path.parent.parent
                / "host_profiles"
                / "hosts.sqlite"
            )
            network = HostProfileStore.network_for_observation(
                path, record["target"], record["observed_at"]
            ).get("network_id")
            if network and "," not in network:
                record["network_id"] = network
                record["target_key"] = f"{network}|{record['target']}"
        return record

    def _drain_review_feedback(self) -> None:
        """Apply durable web verdicts and invalidate stale network opinions."""
        validator = getattr(self, "report_validation", None)
        now = time.monotonic()
        if (
            not isinstance(validator, ReportValidator)
            or now - getattr(self, "last_feedback_check", 0) < 5
        ):
            return
        self.last_feedback_check = now
        try:
            validator.drain_reviews(self.db.sqlite.get_db_path())
            validator.import_reviews(
                self.db.sqlite.get_db_path(), self._review_observation
            )
            revision = validator.feedback_revision()
            network = self._network_identity()
            if (revision, network) != getattr(
                self, "last_feedback_context", None
            ):
                self.trust_db.execute("DELETE FROM opinion_cache")
                self.last_feedback_context = (revision, network)
            validator.prune()
        except (sqlite3.Error, OSError) as error:
            self.print(f"P2P feedback will be retried: {error}", 0, 1)

    def _should_rebuild_pigeon_binary(self) -> bool:
        """
        Check whether the p2p binary should be rebuilt after a Slips update.

        Returns:
            True when Slips was started by the update manager and local p2p
            is enabled, otherwise False.
        """
        return bool(
            self.start_pigeon
            and getattr(self.args, "is_slips_started_by_an_update", False)
            and self.conf.use_local_p2p()
        )

    def _rebuild_pigeon_binary_after_slips_update(self) -> bool:
        """
        Rebuild the p2p4slips binary after a live Slips update when needed.

        Returns:
            True when no rebuild is needed or the rebuild succeeds,
            otherwise False.
        """
        if not self._should_rebuild_pigeon_binary():
            return True

        return self._build_pigeon_binary("after Slips update")

    def _build_pigeon_binary(self, reason: str) -> bool:
        """
        Rebuild the p2p4slips binary.

        Parameters:
            reason: Human-readable reason included in log messages.

        Returns:
            True when the rebuild succeeds, otherwise False.
        """
        self.print(f"Rebuilding p2p4slips {reason}. This can take some time.")
        try:
            subprocess.run(
                ["go", "build", "-buildvcs=false"],
                cwd=self.pigeon_binary_dir,
                check=True,
                capture_output=True,
                text=True,
            )
        except OSError as error:
            self.print(
                f"Warning: Failed to rebuild p2p4slips {reason}. "
                f"Error: {error}"
            )
            return False
        except subprocess.CalledProcessError as error:
            error_output = (error.stderr or error.stdout or str(error)).strip()
            self.print(
                f"Warning: Failed to rebuild p2p4slips {reason}. "
                f"Error: {error_output}"
            )
            return False

        self.print(f"Done rebuilding p2p4slips {reason}.")
        return True

    def extract_confidence(self, evidence: Evidence) -> Optional[float]:
        """
        returns the confidence of the given evidence or None if no
        confidence was found
        """
        confidence: float = evidence.confidence

        if confidence:
            return confidence

        attacker_ip: str = evidence.attacker.value
        self.print(
            f"IP {attacker_ip} doesn't have a confidence. "
            f"not sharing to the network.",
            0,
            2,
        )
        return

    def extract_threat_level(
        self, evidence: Evidence
    ) -> Optional[ThreatLevel]:
        """
        returns the confidence of the given evidence or None if no
        confidence was found
        """
        threat_level: ThreatLevel = evidence.threat_level

        if threat_level:
            return threat_level

        attacker_ip: str = evidence.attacker.value
        self.print(
            f"IP {attacker_ip} doesn't have a threat_level. "
            f"not sharing to the network.",
            0,
            2,
        )

        return

    def should_share(self, evidence: Evidence) -> bool:
        """
        decides whether to report the given evidence to other
        peers
        """
        own_ips = utils.get_own_ips(ret="List", include_public=False)
        if evidence.attacker.value in own_ips:
            return False

        if evidence.evidence_type in {
            EvidenceType.P2P_REPORT,
            EvidenceType.MALICIOUS_IP_FROM_P2P_NETWORK,
        }:
            # we shouldn't re-share evidence reported by other peers
            return False

        if evidence.attacker.ioc_type != IoCType.IP.name:
            # we only share ips with other peers.
            return False

        if not p2p_utils.is_unicast_ip(evidence.attacker.value):
            return False

        confidence = self.extract_confidence(evidence)
        if not confidence:
            return False

        threat_level: ThreatLevel = self.extract_threat_level(evidence)
        if not threat_level or threat_level.value <= 0:
            return False

        return True

    def new_evidence_callback(self, msg: Dict[str, str]):
        """
        Decides to share an evidence generated by slips to other peers or not
        depending on whether we have info about this ip from the p2p
        network or not
        It is called whenever a msg arrives to the
        report_to_peers channel,
        """
        try:
            evidence: Dict[str, str] = json.loads(msg["data"])
        except json.decoder.JSONDecodeError:
            return
        evidence: Evidence = dict_to_evidence(evidence)
        validator = getattr(self, "report_validation", None)
        provenance = []
        if isinstance(validator, ReportValidator):
            record = observation_record(
                utils.to_dict(evidence), self._network_identity()
            )
            if record and not record.get("peer_id"):
                validator.observe_local(record)
                if record["provenance"].get("module") in {
                    item.value for item in Modules
                }:
                    provenance = [record["provenance"]]

        if not self.should_share(evidence):
            return

        # A cached peer opinion says nothing about whether this local
        # detection was shared. Bound repeats without suppressing updates
        # indefinitely or allowing the cache to grow for the whole run.
        now = time.monotonic()
        cache = getattr(self, "last_sent_evidence_reports", None)
        if cache is None:
            cache = self.last_sent_evidence_reports = {}
        key = (
            evidence.attacker.value,
            evidence.threat_level.value,
            evidence.evidence_type.name,
            provenance[0]["rule_version"] if provenance else "legacy",
            (
                record["network_id"]
                if isinstance(validator, ReportValidator) and record
                else ""
            ),
        )
        if now - cache.get(key, -self.report_min_interval) < (
            self.report_min_interval
        ):
            return
        cache.pop(key, None)
        cache[key] = now
        if len(cache) > self.report_cache_limit:
            cache.pop(next(iter(cache)))
        confidence = evidence.confidence
        if provenance:
            confidence *= validator.detector_weight(
                provenance[0]["evidence_type"],
                provenance[0]["rule_version"],
                record["network_id"] + "|",
            )
        arguments = [
            evidence.attacker.value,
            evidence.threat_level.value,
            confidence,
            "*",
            self.pygo_channel,
            self.db,
        ]
        if provenance:
            arguments.append(provenance)
        p2p_utils.send_evaluation_to_go(*arguments)

    def new_alert_callback(self, msg: Dict[str, str]) -> None:
        """Broadcast one locally detected malicious host as a blame.

        Parameters:
            msg: The serialized ``new_alert`` Redis message.
        """
        try:
            alert = json.loads(msg["data"])
            ip = str(alert["profile"]["ip"])
            last_evidence_type = alert["last_evidence"]["evidence_type"]
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            return
        if last_evidence_type in (
            EvidenceType.P2P_REPORT.name,
            EvidenceType.MALICIOUS_IP_FROM_P2P_NETWORK.name,
        ):
            return
        if not p2p_utils.is_unicast_ip(ip) or ip in utils.get_own_ips(
            ret="List", include_public=False
        ):
            return
        score, confidence = p2p_utils.get_ip_info_from_slips(ip, self.db)
        if score is None or confidence is None or score <= 0:
            return
        provenance = []
        validator = getattr(self, "report_validation", None)
        if isinstance(validator, ReportValidator):
            rows = self.db.alert_evidence_records(str(alert.get("id", "")))
            for raw in rows:
                record = observation_record(raw, self._network_identity())
                if record and not record.get("peer_id"):
                    validator.observe_local(record)
            score, confidence, provenance = validator.local_report(
                f"{self._network_identity()}|{ip}"
            )
            if score is None or confidence is None:
                return
        arguments = [
            ip,
            min(1.0, max(0.0, score)),
            min(1.0, max(0.0, confidence)),
            self.pygo_channel,
            self.db,
        ]
        if provenance:
            arguments.append(provenance)
        p2p_utils.send_blame_to_go(*arguments)

    def gopy_callback(self, msg: Dict):
        """
        this function is called whenever slips receives peers requests/updates
        happens when a msg is sent in the gopy_channel.
        """
        # try:
        data: str = msg["data"]
        data: dict = json.loads(data)
        self.go_director.handle_gopy_data(data)
        # except Exception as e:
        #     self.printer.print(f'Exception in gopy_callback: {e} ', 0, 1)

    def is_msg_version_compatible(self, message: dict, channel: str) -> bool:
        """Validate Go envelopes separately from versioned Slips messages.

        Parameters:
            message: Redis message from a subscribed channel.
            channel: Channel on which the message was received.

        Returns:
            Whether the message matches the channel's expected protocol.
        """
        if message and channel == self.gopy_channel:
            try:
                payload = json.loads(message["data"])
            except (KeyError, TypeError, ValueError):
                return False
            return (
                isinstance(payload, dict)
                and payload.get("message_type")
                in ("peer_update", "connection_update", "go_data")
                and isinstance(payload.get("message_contents"), dict)
            )
        return super().is_msg_version_compatible(message, channel)

    # def update_callback(self, msg: Dict):
    #     try:
    #         data = msg["data"]
    #         self.print(f"IP info was updated in slips for ip: {data}")
    #         self.handle_update(data)
    #     except Exception as e:
    #         self.printer.print(f"Exception {e} in update_callback")

    def data_request_callback(self, msg: Dict):
        try:
            # ignore subscribe msgs (first 2 msgs sent in redis channel)
            if msg and not isinstance(msg["data"], int):
                self.handle_data_request(msg["data"])
        except Exception as e:
            self.print(
                f"Exception: {e} .. msg: {msg} in " f"data_request_callback()",
                0,
                1,
            )

    def set_evidence_malicious_ip(
        self, ip_info: dict, threat_level: float, confidence: float
    ) -> None:
        """
        Set an evidence for a malicious IP met in the timewindow
        ip_info format is json serialized {
                     'ip': the source/dst ip
                     'profileid' : profile where the alert was generated.
                        It includes the src ip
                     'twid' : name of the timewindow when it happened.
                     'proto' : protocol
                     'ip_state' : is basically the answer to "which one is the
                                   blacklisted IP"?'can be 'srcip' or
                                    'dstip',
                     'stime': Exact time when the evidence happened
                     'uid': Zeek uid of the flow that generated the evidence,
                     'cache_age': How old is the info about this ip
                 }
        :param threat_level: the threat level we learned form the network
        :param confidence: how confident the network opinion is about this opinion
        """
        attacker_ip: str = ip_info.get("ip")
        report_after_id = ip_info.get("report_after_id")
        peer_ids = sorted(
            self.trust_db.get_reporter_peerids_for_ip(
                attacker_ip, report_after_id
            )
        )
        peer_labels = []
        for peer_id in peer_ids:
            _last_seen, peer_ip = self.trust_db.get_ip_of_peer(peer_id)
            peer_labels.append(
                f"{peer_id} ({peer_ip})" if peer_ip else peer_id
            )
        peer_source = (
            f" Replied to this lookup, peer{'s' if len(peer_ids) != 1 else ''}: "
            f"{', '.join(peer_labels)}."
            if peer_ids
            else " No peer reply was recorded for this lookup."
        )
        profileid = ip_info.get("profileid")
        saddr = profileid.split("_")[-1]

        threat_level: str = utils.threat_level_to_string(threat_level)
        threat_level: ThreatLevel = ThreatLevel[threat_level.upper()]
        twid_int = int(ip_info.get("twid").replace("timewindow", ""))

        if "src" in ip_info.get("ip_state"):
            description = (
                f"Connection from blacklisted IP {attacker_ip} "
                f"to {saddr} Source: Slips P2P network.{peer_source}"
            )
        else:
            description = (
                f"Connection to blacklisted IP {attacker_ip} "
                f"from {saddr} Source: Slips P2P network.{peer_source}"
            )

        evidence = Evidence(
            evidence_type=EvidenceType.MALICIOUS_IP_FROM_P2P_NETWORK,
            attacker=Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value=attacker_ip,
            ),
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=attacker_ip),
            timewindow=TimeWindow(number=twid_int),
            uid=[ip_info.get("uid")],
            timestamp=str(ip_info.get("stime")),
        )
        self.db.set_evidence(evidence)

    def handle_data_request(self, message_data: str) -> None:
        """
        Process the request from Slips, ask the network and
        process the network response.

        Three `arguments` are expected in the redis channel:
            ip_address: str,
            cache_age: int [seconds]
        The return value is sent to the redis channel
         `p2p_data_response` in the format:
            ip_address: str,
            timestamp: int [time of assembling the response],
            network_opinion: float,
            network_confidence: float,
            network_competence: float,
            network_trust: float

        This method will check if any data not older than `cache_age`
        is saved in cache. If yes, this data is returned.
        If not, the database is checked.
        An ASK query is sent to the network and responses
        are collected and saved into the redis database.

        :param message_data: The data received from the redis
         channel `p2p_data_response`
        :return: None, the result is saved into the redis
            database under key `p2p4slips`
        """
        # make sure that IP address is valid
        # and cache age is a valid timestamp from the past
        ip_info = validate_slips_data(message_data)
        if ip_info is None:
            # IP address is not valid, aborting
            # print(f"DEBUGGING: IP address is not valid:
            # {ip_info}, not asking the network")
            return
        # ip_info is {
        #             'ip': str(saddr),
        #             'profileid' : str(profileid),
        #             'twid' :  str(twid),
        #             'proto' : str(proto),
        #             'ip_state' : 'srcip',
        #             'stime': starttime,
        #             'uid': uid,
        #             'cache_age': cache_age
        #         }
        ip_address = ip_info.get("ip")
        cache_age = ip_info.get("cache_age")
        # if data is in cache and is recent enough,
        # nothing happens and Slips should just check the database
        (
            cached_score,
            cached_confidence,
            cached_network_score,
            cached_timestamp,
        ) = self.trust_db.get_cached_network_opinion("ip", ip_address)
        if (
            cached_score is not None
            and time.time() - cached_timestamp < cache_age
        ):
            # cached value is ok, do nothing
            # print("DEBUGGING:  cached value is ok, not asking the network.")
            return

        # since cached value is old, ask the peers

        # TODO: in some cases, it is not necessary to wait, specify
        #  that and implement it
        #       I do not remember writing this comment. I have no idea
        #       in which cases there is no need to wait? Maybe
        #       when everybody responds asap?
        report_after_id = self.trust_db.get_latest_report_id()
        p2p_utils.send_request_to_go(ip_address, self.pygo_channel, self.db)
        self.print(
            f"[Slips -> The Network] request about {ip_address}",
            log_to_logfiles_only=True,
        )

        # go will send a reply in no longer than 10s (or whatever the
        # timeout there is set to). The reply will be
        # processed by an independent process in this module and
        # database will be updated accordingly
        time.sleep(2)

        # get data from db, processed by the trust model
        # this score and confidence are the network's opinion
        (
            combined_score,
            combined_confidence,
        ) = self.reputation_model.get_opinion_on_ip(
            ip_address, report_after_id
        )

        ip_info["report_after_id"] = report_after_id

        self.process_network_response(
            ip_address,
            combined_score,
            combined_confidence,
            ip_info,
        )

    def process_network_response(
        self,
        ip,
        combined_score,
        combined_confidence,
        ip_info,
    ):
        """
        stores the reported score and confidence about the ip and adds an
        evidence if necessary like when the peers report a malicious ip
        """
        if not p2p_utils.is_unicast_ip(ip):
            return
        # no data in db - this happens when testing,
        # if there is not enough data on peers
        if combined_score is None or combined_confidence is None:
            self.print(
                f"No data received from the network about {ip}\n",
                0,
                2,
                log_to_logfiles_only=True,
            )
            return

        self.print(
            f"The Network shared some data about {ip}, "
            f"Shared data: score={combined_score}, "
            f"confidence={combined_confidence} saving it now!\n",
            0,
            2,
            log_to_logfiles_only=True,
        )

        if combined_score * combined_confidence > 0:
            self.set_evidence_malicious_ip(
                ip_info, combined_score, combined_confidence
            )

    def respond_to_message_request(self, key, reporter):
        # todo do you mean another peer is asking me about
        #  an ip? yes. in override mode
        """
        Handle data request from a peer (in overriding p2p mode) (set to false by defualt)
        :param key: The ip requested by the peer
        :param reporter: The peer that sent the request
        return a json response

        """
        pass

    def _pigeon_supports_flag(self, flag: str) -> bool:
        """Check whether the installed Pigeon binary accepts a CLI flag.

        Parameters:
            flag: Command-line flag to look for in Pigeon's help output.

        Returns:
            True when the binary advertises the flag, otherwise False.
        """
        try:
            result = subprocess.run(
                [str(self.pigeon_binary), "-help"],
                capture_output=True,
                check=False,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return flag in f"{result.stdout}\n{result.stderr}"

    def _get_pigeon_command(self) -> list[str]:
        """Build a command compatible with the installed Pigeon binary.

        Returns:
            Sanitized Pigeon command and arguments.
        """
        params = {
            "-port": str(self.port),
            "-host": "0.0.0.0",
            "-rendezvous": self.rendezvous,
            "-key-file": self.pigeon_key_file,
            "-peerstore-file": "pigeon.peerstore.json",
            "--redis-db": f"{LOCALHOST_HOSTNAME}:{self.redis_port}",
            "-redis-auth-conf": get_redis_auth_conf_path(),
            "-redis-channel-pygo": self.pygo_channel_raw,
            "-redis-channel-gopy": self.gopy_channel_raw,
        }
        if self._pigeon_supports_flag("-slips-version"):
            params["-slips-version"] = self.slips_version
        else:
            self.print(
                "Warning: The installed p2p4slips binary does not support "
                "-slips-version; starting in legacy compatibility mode."
            )

        bootstrap_peers = self._get_bootstrap_peer_addresses()
        if bootstrap_peers and self._pigeon_supports_flag("-bootstrap-peers"):
            params["-bootstrap-peers"] = ",".join(bootstrap_peers)

        return [str(self.pigeon_binary)] + [
            utils.sanitize(item) for pair in params.items() for item in pair
        ]

    def _get_bootstrap_peer_addresses(self) -> list[str]:
        """Build authenticated peer endpoints from this network's history.

        Returns:
            Recent peer multiaddresses on the monitored IPv4 subnet.
        """
        trust_db = getattr(self, "trust_db", None)
        if trust_db is None:
            return []

        try:
            subnets = self._get_local_subnets()
        except (OSError, ValueError):
            subnets = set()

        addresses: dict[str, str] = {}
        try:
            known_addresses = trust_db.get_recent_peer_addresses(
                self.max_bootstrap_peers
            )
        except (AttributeError, TypeError):
            known_addresses = []
        if isinstance(known_addresses, (list, tuple)):
            for peer_id, address, port, _timestamp in known_addresses:
                self._add_bootstrap_address(
                    addresses, str(peer_id), str(address), port, subnets
                )

        try:
            known_ips = trust_db.get_recent_peer_ips(self.max_bootstrap_peers)
        except (AttributeError, TypeError):
            known_ips = []
        if isinstance(known_ips, (list, tuple)):
            for peer_id, address, _timestamp in known_ips:
                self._add_bootstrap_address(
                    addresses, str(peer_id), str(address), self.port, subnets
                )

        return list(addresses.values())[: self.max_bootstrap_peers]

    def _add_bootstrap_address(
        self,
        addresses: dict[str, str],
        peer_id: str,
        address: str,
        port: int,
        subnets: set[ipaddress.IPv4Network],
    ) -> None:
        """Add a valid peer endpoint once, if it belongs to this subnet.

        Parameters:
            addresses: Output mapping keyed by peer ID.
            peer_id: Authenticated P2P identity.
            address: Last observed IPv4 address.
            port: Last observed P2P listening port.
            subnet: Current monitored subnet, when available.
        """
        if peer_id in addresses:
            return
        try:
            peer_ip = ipaddress.IPv4Address(address)
            peer_port = int(port)
        except (ipaddress.AddressValueError, TypeError, ValueError):
            return
        if peer_port < 1 or peer_port > 65535:
            return
        if subnets and not any(peer_ip in subnet for subnet in subnets):
            return
        if address == getattr(self, "host", ""):
            return
        addresses[peer_id] = f"/ip4/{peer_ip}/tcp/{peer_port}/p2p/{peer_id}"

    def _get_local_subnets(self) -> set[ipaddress.IPv4Network]:
        """Return directly connected IPv4 networks on local interfaces.

        Returns:
            IPv4 subnets for non-loopback interfaces with usable netmasks.
        """
        subnets = set()
        for interface in netifaces.interfaces():
            if interface == "lo0":
                continue
            for entry in netifaces.ifaddresses(interface).get(
                netifaces.AF_INET, []
            ):
                address, netmask = entry.get("addr"), entry.get("netmask")
                if not address or not netmask:
                    continue
                local_ip = ipaddress.IPv4Address(address)
                if local_ip.is_loopback or local_ip.is_link_local:
                    continue
                subnets.add(
                    ipaddress.ip_network(f"{address}/{netmask}", strict=False)
                )
        return subnets

    def evaluate_blame_report(
        self, reporter: str, report_time: int, data: dict
    ) -> None:
        """
        Decide whether a peer's "blame" (a request to block an IP)
        should be forwarded to the blocking module.

        - Implements the trust model from the original Dovecot/Omega-Trust
        thesis (Hollmannova, 2020): a single peer's report is never enough
        on its own to trigger a block.

        - called only after a "blame" message has been validated and stored in the
        trust db like any other report, so it already counts towards
        the network's opinion on this IP.


        We combine Slips' own local opinion of the IP with the
        network's trust-weighted opinion (Omega-score * Omega-confidence,
        aggregated over every peer that has reported on this IP so
        far, weighted by how much we trust each reporter):
            prediction = ips_weight * local_opinion
                         + (1 - ips_weight) * network_opinion
        and only forward the blame to the blocking pipeline if that
        combined prediction reaches blame_threshold.

        :param reporter: The peer that sent the report
        :param report_time: Time of receiving the report, provided by the go part
        :param data: Report data
        """
        if data.get("message_type") != "blame":
            return

        key = data["key"]
        if not p2p_utils.is_unicast_ip(key):
            return

        # the network's trust-weighted opinion on this IP, aggregated
        # over every peer that reported on it so far (not just this
        # one reporter)
        network_score, network_confidence = (
            self.reputation_model.get_opinion_on_ip(key)
        )
        if network_score is None or network_confidence is None:
            self.print(
                f"No aggregated network opinion on {key} yet. "
                f"Not forwarding this blame report.",
                0,
                2,
                log_to_logfiles_only=True,
            )
            return
        network_opinion = network_score * network_confidence

        local_score, local_confidence = p2p_utils.get_ip_info_from_slips(
            key, self.db
        )
        local_opinion = (
            0 if local_score is None else local_score * local_confidence
        )
        validator = getattr(self, "report_validation", None)
        if isinstance(validator, ReportValidator):
            local_score, local_confidence, provenance = validator.local_report(
                f"{self._network_identity()}|{key}"
            )
            local_opinion = (
                0 if local_score is None else local_score * local_confidence
            )
            details = getattr(self.reputation_model, "last_corroboration", {})
            if (
                isinstance(details, dict)
                and details.get("target")
                == f"{self._network_identity()}|{key}"
                and provenance
            ):
                family = provenance[0].get("family")
                units = details.get("families", {})
                if family in units and not units[family].get("validated"):
                    independent = [
                        unit for name, unit in units.items() if name != family
                    ]
                    network_opinion = (
                        (
                            sum(unit["score"] for unit in independent)
                            * sum(unit["confidence"] for unit in independent)
                            / len(independent) ** 2
                        )
                        if independent
                        else 0
                    )

        prediction = (
            self.ips_weight * local_opinion
            + (1 - self.ips_weight) * network_opinion
        )

        corroboration = getattr(
            self.reputation_model, "last_corroboration", {}
        )
        peer_support = (
            float(corroboration.get("support", 0))
            if (
                isinstance(corroboration, dict)
                and isinstance(validator, ReportValidator)
                and corroboration.get("target")
                == f"{self._network_identity()}|{key}"
            )
            else 0
        )
        if prediction < self.blame_threshold and peer_support < 0.85:
            self.print(
                f"Blame report about {key} from {reporter} doesn't meet "
                f"the blame_threshold ({prediction} < "
                f"{self.blame_threshold}). Not blocking it.",
                0,
                2,
                log_to_logfiles_only=True,
            )
            return

        self.print(
            f"Blame report about {key} confirmed by the network "
            f"(prediction={prediction}, independent blame support={peer_support}). Forwarding {key} to the blocking "
            f"module.",
            0,
            2,
            log_to_logfiles_only=True,
        )
        # give the report to evidenceProcess to decide whether to block or not
        self.db.publish("new_blame", json.dumps(data))

    def _start_pigeon(self) -> None:
        """
        Start the p2p4slips process when local p2p is enabled.

        Returns:
            None.
        """
        self.pigeon = None
        if not self.start_pigeon:
            return

        if not self._rebuild_pigeon_binary_after_slips_update():
            return

        if not shutil.which(self.pigeon_binary):
            self.print(
                f"Warning: P2p4slips binary not found in "
                f'"{self.pigeon_binary}". '
                f"Did you include it in PATH?. Exiting process."
            )
            return

        executable = self._get_pigeon_command()

        if self.create_p2p_logfile:
            pigeon_log_path = self.pigeon_logfile
        else:
            pigeon_log_path = os.devnull
        outfile = open(pigeon_log_path, "+w")

        try:
            self.pigeon = subprocess.Popen(
                executable,
                cwd=self.p2p_trust_runtime_dir,
                stdout=outfile,
                stderr=subprocess.STDOUT,
            )
        except OSError as error:
            if error.errno != errno.ENOEXEC:
                self.print(
                    f"Warning: Failed to start p2p4slips. Error: {error}"
                )
                return

            self.print(
                "Warning: p2p4slips binary is not executable on this "
                "system. Trying to rebuild it locally."
            )
            if not self._build_pigeon_binary("for this system"):
                return

            try:
                executable = self._get_pigeon_command()
                self.pigeon = subprocess.Popen(
                    executable,
                    cwd=self.p2p_trust_runtime_dir,
                    stdout=outfile,
                    stderr=subprocess.STDOUT,
                )
            except OSError as retry_error:
                self.print(
                    "Warning: Failed to start p2p4slips after rebuilding. "
                    f"Error: {retry_error}"
                )
                return

        time.sleep(0.1)
        return_code = self.pigeon.poll()
        if return_code is not None:
            self.print(
                "Warning: p2p4slips exited during startup with return code "
                f"{return_code}. Check {pigeon_log_path}."
            )
            self.pigeon = None
            return

        self.print(f"P2P is listening on {self.host} port {self.port}.")

    def _record_pigeon_connections(self) -> None:
        """Mark exact live Pigeon sockets so capture skips Slips P2P traffic."""
        pigeon = getattr(self, "pigeon", None)
        if pigeon is None or pigeon.poll() is not None:
            return
        if not isinstance(getattr(pigeon, "pid", None), int):
            return
        now = time.monotonic()
        if now - getattr(self, "_last_pigeon_socket_scan", 0) < (
            self.pigeon_socket_scan_interval
        ):
            return
        self._last_pigeon_socket_scan = now
        try:
            connections = psutil.Process(pigeon.pid).net_connections(
                kind="inet"
            )
        except (psutil.Error, OSError):
            return
        for connection in connections:
            if not connection.laddr or not connection.raddr:
                continue
            protocol = (
                "tcp"
                if connection.type == socket.SOCK_STREAM
                else "udp" if connection.type == socket.SOCK_DGRAM else ""
            )
            if not protocol:
                continue
            local_ip, local_port = connection.laddr[:2]
            remote_ip, remote_port = connection.raddr[:2]
            try:
                local_ip = str(ipaddress.ip_address(local_ip))
                remote_ip = str(ipaddress.ip_address(remote_ip))
            except ValueError:
                continue
            if ipaddress.ip_address(remote_ip).is_loopback:
                continue
            # Zeek can record either endpoint as the flow origin.
            self.db.record_slips_own_connection(
                self.db.main_pid,
                protocol,
                local_ip,
                local_port,
                remote_ip,
                remote_port,
            )
            self.db.record_slips_own_connection(
                self.db.main_pid,
                protocol,
                remote_ip,
                remote_port,
                local_ip,
                local_port,
            )

    def shutdown_gracefully(self) -> None:
        """Stop and reap the Go peer before closing its trust database."""
        self._stop_pigeon()
        self.db.clear_authenticated_p2p_connections()
        self.db.store_connected_peers([])
        if hasattr(self, "trust_db"):
            self.trust_db.__del__()

    def _stop_pigeon(self) -> None:
        """
        Stop the p2p4slips child and wait until it has exited.

        This method is idempotent so it can run during both normal cleanup and
        the final safeguard around an unexpected module exit.
        """
        pigeon = getattr(self, "pigeon", None)
        if pigeon is None:
            return

        if pigeon.poll() is None:
            pigeon.send_signal(signal.SIGINT)
            try:
                pigeon.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.print(
                    "Warning: p2p4slips did not stop after SIGINT; "
                    "terminating it."
                )
                pigeon.terminate()
                try:
                    pigeon.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.print(
                        "Warning: p2p4slips did not terminate; killing it."
                    )
                    pigeon.kill()
                    pigeon.wait()

        self.pigeon = None

    def _local_network_identity(self) -> tuple[tuple[str, str, str], ...]:
        """Read the monitored interfaces' subnet and gateway identities.

        Returns:
            Stable network identities, excluding host-address and DNS changes.
        """
        interface = getattr(self.args, "interface", None)
        interfaces = [interface] if isinstance(interface, str) else []
        access_point = getattr(self.args, "access_point", None)
        if not interfaces and isinstance(access_point, str):
            interfaces = access_point.split(",")
        identities = []
        for interface in interfaces:
            state = self.db.get_network_state(interface.strip())
            if not isinstance(state, dict) or not state.get("connected"):
                continue
            identities.append(
                (
                    interface.strip(),
                    state.get("local_network", ""),
                    state.get("gateway_mac", ""),
                )
            )
        return tuple(sorted(identities))

    def _refresh_pigeon_address(self) -> None:
        """Restart Pigeon when the monitored address or network changes.

        Wi-Fi and Ethernet interfaces can change addresses while Slips is
        running. Pigeon binds to its startup address and advertises that
        address through mDNS, so it must be restarted to join the new network.
        """
        now = time.monotonic()
        if (
            now - getattr(self, "last_local_ip_check", 0)
            < self.local_ip_check_interval
        ):
            return
        self.last_local_ip_check = now

        if not hasattr(self, "host"):
            return

        try:
            current_ip = self.get_local_IP()
        except (OSError, ValueError):
            return

        network_identity = self._local_network_identity()
        previous_network = getattr(
            self, "_pigeon_network_identity", network_identity
        )
        network_changed = network_identity != previous_network
        self._pigeon_network_identity = network_identity
        if (
            current_ip == self.host
            and not network_changed
            and getattr(self, "pigeon", None) is not None
        ):
            return

        if current_ip != self.host or network_changed:
            self.print(
                f"Monitored network changed (IP {self.host} -> "
                f"{current_ip}); restarting Pigeon to reconnect to local peers."
            )
            self._stop_pigeon()
            self.db.clear_authenticated_p2p_connections()
            self.db.store_connected_peers([])
            self.host = current_ip
            self.mutliaddress_printed = False

        self._start_pigeon()

    def run(self) -> None:
        """Run p2p_trust and guarantee its Go child cannot be orphaned."""
        try:
            super().run()
        finally:
            self._stop_pigeon()

    def pre_main(self):
        utils.drop_root_privs_permanently()
        self._init_log_files()
        self._configure()
        self._pigeon_network_identity = self._local_network_identity()
        self.db.clear_authenticated_p2p_connections()
        self.db.store_connected_peers([])
        self._start_pigeon()
        # check if it was possible to start up pigeon
        if self.start_pigeon and self.pigeon is None:
            self.print(
                "Module was supposed to start up pigeon but it was not"
                " possible to start pigeon! Exiting..."
            )
            return 1

        # should call self.update_callback
        # self.c4 = self.db.subscribe(self.slips_update_channel)

    def should_stop(self) -> bool:
        """Stop peer callbacks as soon as Slips begins shutting down.

        Returns:
            True when the shared termination event is set.
        """
        return self.termination_event.is_set()

    def _sample_peer_trust(self, now: float) -> None:
        """Save current trust once a minute, including while the UI is closed.

        Parameters:
            now: Current Unix timestamp.
        """
        if now - getattr(self, "_last_trust_sample", 0) < 60:
            return
        self._last_trust_sample = now
        network = self._network_identity()
        samples = []
        seen = set()
        validator = getattr(self, "report_validation", None)
        connections = sorted(
            self.db.get_authenticated_p2p_connections(),
            key=lambda row: str(row.get("remote_ip") or ""),
        )
        for connection in connections:
            peer = connection.get("peer_id")
            ip = connection.get("remote_ip")
            if (
                not peer
                or peer in seen
                or connection.get("connected") is False
                or not p2p_utils.is_unicast_ip(ip)
            ):
                continue
            seen.add(peer)
            reliability = self.trust_db.get_reporter_reliability(peer)
            if reliability is None:
                continue
            score, confidence = self.trust_db.get_reporter_reputation(ip)
            if isinstance(validator, ReportValidator):
                score, confidence, _ = validator.local_report(
                    f"{network}|{ip}",
                    max_age=None,
                    decay_half_life=self.local_reputation_half_life,
                )
            score = 0.5 if score is None else score
            confidence = 0.0 if confidence is None else confidence
            trust = self.reputation_model.compute_peer_trust(
                reliability, score, confidence
            )
            samples.append((peer, ip, network, trust, reliability))
        self.trust_db.store_peer_trust_samples(
            samples,
            now,
            ConfigParser().detection_history_policy()["active_days"],
        )

    def main(self):
        self._drain_review_feedback()
        if self.create_p2p_logfile:
            # rotates p2p.log file every 1 day
            now = time.time()
            if now - self.last_log_rotation_time >= self.rotation_period:
                open(self.pigeon_logfile, "w").close()
                self.last_log_rotation_time = now

        if msg := self.get_msg("report_to_peers"):
            self.new_evidence_callback(msg)

        if msg := self.get_msg("new_alert"):
            self.new_alert_callback(msg)

        if msg := self.get_msg(self.p2p_data_request_channel):
            self.data_request_callback(msg)

        if msg := self.get_msg(self.gopy_channel):
            try:
                self.gopy_callback(msg)
            except Exception as error:
                self.print(
                    "Warning: Ignoring malformed p2p_gopy message after "
                    f"processing failed: {error}",
                    0,
                    1,
                )

        self._refresh_pigeon_address()
        self._record_pigeon_connections()

        if self.pigeon is None:
            self.termination_event.wait(0.05)
            return

        ret_code = self.pigeon.poll()
        if ret_code not in (None, 0):
            # The pigeon stopped with some error
            self.print(
                f"Pigeon process suddenly terminated with "
                f"return code {ret_code}. Stopping module."
            )
            return 1

        try:
            if not self.mutliaddress_printed:
                # give the pigeon time to put the multiaddr in the db
                time.sleep(2)
                multiaddr = self.db.get_multiaddr()
                self.print(f"You Multiaddress is: {green(multiaddr)}\n")
                self.mutliaddress_printed = True

        except Exception:
            pass

        now = time.time()
        try:
            self._sample_peer_trust(now)
        except sqlite3.OperationalError as error:
            self.print(f"Deferring P2P trust sampling: {error}", 0, 1)
        if now - getattr(
            self, "last_p2p_connection_heartbeat_time", 0
        ) >= getattr(self, "p2p_connection_heartbeat_interval", 60):
            self.db.refresh_authenticated_p2p_connections(
                getattr(self, "active_p2p_connection_ttl", 300)
            )
            self.last_p2p_connection_heartbeat_time = now

        if now - getattr(self, "last_report_compaction_time", now) >= getattr(
            self, "report_compaction_interval", 5
        ):
            try:
                self.trust_db.compact_reports(
                    getattr(self, "report_compaction_batch_size", 1000)
                )
            except sqlite3.OperationalError as error:
                if "locked" not in str(error).lower():
                    raise
                self.print(f"Deferring P2P report compaction: {error}", 0, 1)
            self.last_report_compaction_time = now

        # Channel reads are nonblocking. Yield between polls so an idle
        # P2P module does not consume a CPU core.
        self.termination_event.wait(0.05)
