# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import sys
import time
import os
import subprocess
import json
import shutil
import ipaddress
import math
from collections import deque
from urllib.parse import urlsplit
from typing import (
    Dict,
    List,
)
from uuid import uuid4

from slips_files.common.slips_utils import utils
from slips_files.common.abstracts.imodule import IModule
from slips_files.core.structures.evidence import (
    Evidence,
    ProfileID,
    TimeWindow,
    Attacker,
    Proto,
    ThreatLevel,
    EvidenceType,
    IoCType,
    Direction,
    Victim,
    EvidenceSignal,
)


class LeakDetector(IModule):
    # Name: short name of the module. Do not use spaces
    name = "leak_detector"
    description = "Detects leaks of data in the traffic"
    authors = ["Alya Gomaa"]

    def init(self):
        # this module is only loaded when a pcap is given get the pcap path
        try:
            self.pcap = utils.sanitize(sys.argv[sys.argv.index("-f") + 1])
        except ValueError:
            # this error is raised when we start this module in the unit tests so there's no argv
            # ignore it
            pass
        self.yara_rules_path = "modules/leak_detector/yara_rules/rules/"
        self.compiled_yara_rules_path = self.get_module_specific_output_path(
            "compiled_yara_rules"
        )
        self.packet_details = {}
        self._geolocation_packets = deque(maxlen=1024)
        self.bin_found = False
        if self.is_yara_installed():
            self.bin_found = True

    def subscribe_to_channels(self):
        self.channels = {}

    def is_yara_installed(self) -> bool:
        """
        Checks if yara bin is installed
        """
        cmd = "yara -h > /dev/null 2>&1"
        returncode = os.system(cmd)
        if returncode in [256, 0]:
            # it is installed
            return True
        # elif returncode == 32512:
        self.print(
            "yara is not installed. install it using:\nsudo apt-get install yara"
        )
        return False

    def fix_json_packet(self, json_packet):
        """
        in very large pcaps, tshark gets killed before it's done processing,
        but the first packet info is printed in a corrupted json format
        this function fixes the printed packet
        """
        json_packet = json_packet.replace("Killed", "")
        json_packet += "}]"
        try:
            return json.loads(json_packet)
        except json.decoder.JSONDecodeError:
            return False

    def get_packet_info(self, offset: int):
        """
        Parse pcap and determine the packet at this offset
        returns  a tuple with packet info (srcip, dstip, proto, sport, dport, ts) or False if not found
        """
        self.packet_details = {}
        offset = int(offset)
        with open(self.pcap, "rb") as f:
            # every pcap header is 24 bytes
            f.read(24)
            packet_number = 0

            packet_data_length = True
            while packet_data_length:
                # the number of the packet we're currently working with,
                # since packets start from 1 in tshark,
                # the first packet should be 1
                packet_number += 1
                # this offset is exactly when the packet starts
                start_offset = f.tell() + 1
                # get the Packet header, every packet header is exactly 16 bytes long
                packet_header = f.read(16)
                # get the length of the Packet Data field
                # (the second last 4 bytes of the header),
                # [::-1] for little endian
                packet_data_length = packet_header[8:12][::-1]
                # convert the hex into decimal
                packet_length_in_decimal = int.from_bytes(
                    packet_data_length, "big"
                )

                # read until the end of this packet
                f.read(packet_length_in_decimal)
                # this offset is exactly when the packet ends
                end_offset = f.tell()
                if offset <= end_offset and offset >= start_offset:
                    # sanitize tshark params
                    self.pcap = utils.sanitize(self.pcap)
                    try:
                        int(packet_number)
                    except ValueError:
                        self.print(
                            f"Invalid packet number: {packet_number} "
                            f"for offset: {offset} for {self.pcap}"
                        )
                        return

                    # use tshark to get packet info
                    cmd = [
                        "tshark",
                        "-n",
                        "-r",
                        self.pcap,
                        "-c",
                        str(packet_number),
                        "-T",
                        "json",
                        "-Y",
                        f"frame.number=={packet_number}",
                    ]
                    tshark_proc = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                        stdin=subprocess.PIPE,
                    )

                    result, error = tshark_proc.communicate()
                    if error:
                        self.print(
                            f"tshark error {tshark_proc.returncode}: {error.strip()}"
                        )
                        return

                    json_packet: str = result.decode()

                    try:
                        json_packet: List[Dict[str, str]] = json.loads(
                            json_packet
                        )
                    except json.decoder.JSONDecodeError:
                        json_packet = self.fix_json_packet(json_packet)

                    if json_packet:
                        # sometime tshark can't find the desired packet?
                        json_packet = json_packet[0]["_source"]["layers"]

                        # get ip family and used protocol
                        used_protocols = json_packet["frame"][
                            "frame.protocols"
                        ]
                        ip_family = (
                            "ipv6" if "ipv6" in used_protocols else "ip"
                        )
                        if "tcp" in used_protocols:
                            proto = "tcp"
                        elif "udp" in used_protocols:
                            proto = "udp"
                        else:
                            # probably ipv6.hopopt
                            return

                        try:
                            ts = json_packet["frame"]["frame.time_epoch"]
                            srcip = json_packet[ip_family][f"{ip_family}.src"]
                            dstip = json_packet[ip_family][f"{ip_family}.dst"]
                            sport = json_packet[proto][f"{proto}.srcport"]
                            dport = json_packet[proto][f"{proto}.dstport"]
                        except KeyError:
                            return

                        self.packet_details = {
                            "frame_number": packet_number,
                            "geolocation": self.ip_geolocation_response(
                                json_packet
                            ),
                        }
                        return srcip, dstip, proto, sport, dport, ts

        return False

    @staticmethod
    def ip_geolocation_response(layers: dict) -> dict | None:
        """Recognize an IP-geolocation JSON reply from its HTTP request context.

        Parameters:
            layers: Dissected packet protocol layers from tshark.

        Returns:
            Validated lookup coordinates and queried IP, or None.
        """
        http = layers.get("http", {})
        if not isinstance(http, dict) or str(http.get("http.response")) != "1":
            return None
        try:
            uri = urlsplit(str(http.get("http.response_for.uri") or ""))
            host = uri.hostname
        except ValueError:
            return None
        if (
            uri.scheme not in {"http", "https"}
            or host not in {"ip-api.com", "pro.ip-api.com"}
            or not (uri.path == "/json" or uri.path.startswith("/json/"))
        ):
            return None
        raw = http.get("http.file_data", "")
        if not isinstance(raw, str) or len(raw) > 65536:
            return None
        try:
            payload = json.loads(bytes.fromhex(raw.replace(":", "")).decode())
            if (
                not isinstance(payload, dict)
                or payload.get("status") != "success"
            ):
                return None
            query_ip = str(ipaddress.ip_address(payload["query"]))
            latitude, longitude = float(payload["lat"]), float(payload["lon"])
            if not (
                math.isfinite(latitude)
                and math.isfinite(longitude)
                and -90 <= latitude <= 90
                and -180 <= longitude <= 180
            ):
                return None
        except (ValueError, KeyError, TypeError, UnicodeError):
            return None
        return {
            "host": host,
            "query_ip": query_ip,
            "latitude": latitude,
            "longitude": longitude,
        }

    def packet_timewindow(
        self, ip: str, timestamp: float
    ) -> TimeWindow | None:
        """Wait briefly in this worker for profiling to create a packet's window.

        Parameters:
            ip: Evidence profile address.
            timestamp: Packet timestamp in seconds.

        Returns:
            Recorded time window, or None when unavailable or stopping.
        """
        deadline = time.monotonic() + 4
        while True:
            twid = self.db.get_tw_of_ts(f"profile_{ip}", timestamp)
            if twid:
                return TimeWindow(
                    number=int(twid[0].replace("timewindow", ""))
                )
            if time.monotonic() >= deadline or self.termination_event.wait(
                0.1
            ):
                return None

    def set_evidence_yara_match(self, info: dict) -> None:
        """Attach one YARA packet finding to its real connection when available.

        Parameters:
            info: Rule, packet byte offset and matched coordinate text.
        """
        packet_info = self.get_packet_info(info["offset"])
        if not packet_info:
            return
        srcip, dstip, proto, sport, dport, ts = packet_info
        packet = {
            "saddr": srcip,
            "daddr": dstip,
            "proto": proto,
            "sport": int(sport),
            "dport": int(dport),
            "timestamp": float(ts),
        }
        context = self.db.get_flow_for_packet(packet)
        context = context if isinstance(context, dict) else {}
        uid = [context["uid"]] if context.get("uid") else []
        details = {
            "packet": packet,
            "pcap_offset": int(info["offset"]),
            "frame_number": self.packet_details.get("frame_number"),
            "rule": info["rule"],
            "matched_text": info.get("strings_matched", ""),
        }
        interface = context.get("flow", {}).get("interface", self.pcap)
        geolocation = self.packet_details.get("geolocation")
        if geolocation:
            identity = (srcip, dstip, sport, dport, float(ts))
            if identity in self._geolocation_packets:
                return
            window = self.packet_timewindow(dstip, float(ts))
            if window is None:
                return
            details["geolocation"] = geolocation
            description = (
                f"IP geolocation response from {srcip}:{sport} to {dstip}:{dport} "
                f"via {geolocation['host']}. Queried IP: {geolocation['query_ip']}; "
                f"latitude: {geolocation['latitude']}, longitude: {geolocation['longitude']}."
            )
            self.db.set_evidence(
                Evidence(
                    evidence_type=EvidenceType.IP_GEOLOCATION_RESPONSE,
                    attacker=Attacker(
                        direction=Direction.SRC,
                        ioc_type=IoCType.IP,
                        value=dstip,
                    ),
                    victim=Victim(
                        direction=Direction.DST,
                        ioc_type=IoCType.IP,
                        value=srcip,
                    ),
                    threat_level=ThreatLevel.INFO,
                    confidence=0.9,
                    description=description,
                    profile=ProfileID(ip=dstip),
                    timewindow=window,
                    uid=uid,
                    timestamp=utils.convert_ts_format(ts, utils.alerts_format),
                    proto=Proto(proto.lower()),
                    src_port=int(dport),
                    dst_port=int(sport),
                    interface=interface,
                    evidence_signal=EvidenceSignal.DAMP,
                    detection_details=details,
                )
            )
            self._geolocation_packets.append(identity)
            return
        window = self.packet_timewindow(srcip, float(ts))
        if window is None:
            return
        portproto = f"{dport}/{proto}"
        port_info = self.db.get_port_info(portproto)
        description = (
            f"Coordinates observed in a packet from {srcip}:{sport} to {dstip}:{dport} "
            f"using {proto.upper()} {port_info or ''}. Matched: {info.get('strings_matched', '')}"
        )
        ids = [str(uuid4()), str(uuid4())]
        for index, (
            ip,
            direction,
            opposite,
            opposite_direction,
            level,
        ) in enumerate(
            (
                (srcip, Direction.SRC, dstip, Direction.DST, ThreatLevel.LOW),
                (dstip, Direction.DST, srcip, Direction.SRC, ThreatLevel.HIGH),
            )
        ):
            self.db.set_evidence(
                Evidence(
                    id=ids[index],
                    rel_id=[ids[1 - index]],
                    evidence_type=EvidenceType.NETWORK_GPS_LOCATION_LEAKED,
                    attacker=Attacker(
                        direction=direction, ioc_type=IoCType.IP, value=ip
                    ),
                    victim=Victim(
                        direction=opposite_direction,
                        ioc_type=IoCType.IP,
                        value=opposite,
                    ),
                    threat_level=level,
                    confidence=0.9,
                    description=description,
                    profile=ProfileID(ip=ip),
                    timewindow=window,
                    uid=uid,
                    timestamp=utils.convert_ts_format(ts, utils.alerts_format),
                    proto=Proto(proto.lower()),
                    src_port=int(sport),
                    dst_port=int(dport),
                    interface=interface,
                    detection_details=details,
                )
            )

    def compile_and_save_rules(self):
        """
        Compile and save all yara rules in the compiled_yara_rules_path
        """

        try:
            os.mkdir(self.compiled_yara_rules_path)
        except FileExistsError:
            pass

        for yara_rule in os.listdir(self.yara_rules_path):
            compiled_rule_path = os.path.join(
                self.compiled_yara_rules_path, f"{yara_rule}_compiled"
            )
            # if we already have the rule compiled, don't compile again
            if os.path.exists(compiled_rule_path):
                # we already have the rule compiled
                continue

            # get the complete path of the .yara rule
            rule_path = os.path.join(self.yara_rules_path, yara_rule)

            rule_path = utils.sanitize(rule_path)
            compiled_rule_path = utils.sanitize(compiled_rule_path)
            # compile
            cmd = f"yarac {rule_path} {compiled_rule_path} >/dev/null 2>&1"
            return_code = os.system(cmd)
            if return_code != 0:
                self.print(f"Error compiling {yara_rule}.")
                return False
        return True

    def delete_compiled_rules(self):
        """
        delete old YARA compiled rules when a new version of yara is being used
        """
        shutil.rmtree(self.compiled_yara_rules_path)
        os.mkdir(self.compiled_yara_rules_path)

    def find_matches(self):
        """Run yara rules on the given pcap and find matches"""
        for compiled_rule in os.listdir(self.compiled_yara_rules_path):
            compiled_rule_path = os.path.join(
                self.compiled_yara_rules_path, compiled_rule
            )
            compiled_rule_path = utils.validate_safe_path(compiled_rule_path)
            self.pcap = utils.sanitize(self.pcap)

            # -p 7 means use 7 threads for faster analysis
            # -f to stop searching for strings when they were already found
            # -s prints the found string
            cmd = f'yara -C {compiled_rule_path} "{self.pcap}" -p 7 -f -s '
            yara_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
                shell=True,
            )

            lines, error = yara_proc.communicate()
            lines = lines.decode()
            if error:
                if (
                    b"rules were compiled with a different version of YARA"
                    in error.strip()
                ):
                    self.delete_compiled_rules()
                    # will re-compile and save rules again and try to find matches
                    self.run()
                else:
                    self.print(
                        f"YARA error {yara_proc.returncode}: {error.strip()}"
                    )
                    return

            if not lines:
                # no match
                return

            lines = lines.splitlines()
            matching_rule = lines[0].split()[0]
            # each match (line) should be a separate detection(yara match)
            for line in lines[1:]:
                # example of a line: 0x4e15c:$rgx_gps_loc: ll=00.000000,-00.000000
                line = line.split(":")
                # offset: pcap index where the rule was matched
                offset = int(line[0], 16)
                # var is either $rgx_gps_loc, $rgx_gps_lon or $rgx_gps_lat
                var = line[1].replace("$", "")
                # strings_matched is exactly the string that was found that triggered this detection
                # starts from the var until the end of the line
                strings_matched = " ".join(list(line[2:]))
                self.set_evidence_yara_match(
                    {
                        "rule": matching_rule,
                        "vars_matched": var,
                        "strings_matched": strings_matched,
                        "offset": offset,
                    }
                )

    def pre_main(self):
        utils.drop_root_privs_permanently()

        if not self.bin_found:
            # yara is not installed
            return 1

        # if we we don't have compiled rules, compile them
        if self.compile_and_save_rules():
            # run the yara rules on the given pcap
            self.find_matches()

    def main(self):
        # nothing runs in a loop in this module
        # exit module
        return 1
