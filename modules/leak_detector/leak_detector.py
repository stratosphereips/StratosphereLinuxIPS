# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import sys
import base64
import time
import binascii
import os
import subprocess
import json
import shutil
from typing import (
    Dict,
    List,
)
from uuid import uuid4

from slips_files.common.slips_utils import utils
from slips_files.common.abstracts.module import IModule
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
)


class LeakDetector(IModule):
    # Name: short name of the module. Do not use spaces
    name = "Leak Detector"
    description = "Detect leaks of data in the traffic"
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
        self.compiled_yara_rules_path = (
            "modules/leak_detector/yara_rules/compiled/"
        )
        self.bin_found = False
        if self.is_yara_installed():
            self.bin_found = True

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
                    # print(f"Found a match. Packet number in wireshark: {packet_number+1}")
                    # use tshark to get packet info
                    cmd = f'tshark -r "{self.pcap}" -T json -Y frame.number=={packet_number}'
                    tshark_proc = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                        stdin=subprocess.PIPE,
                        shell=True,
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

                        return srcip, dstip, proto, sport, dport, ts

        return False

    def set_evidence_yara_match(self, info: dict):
        """
        This function is called when yara finds a match
        :param info: a dict with info about the matched rule,
         example keys 'vars_matched', 'index',
        'rule', 'srings_matched'
        """
        rule = info.get("rule").replace("_", " ")
        offset = info.get("offset")
        # vars_matched = info.get('vars_matched')
        strings_matched = info.get("strings_matched")
        # we now know there's a match at offset x, we need
        # to know offset x belongs to which packet
        packet_info = self.get_packet_info(offset)
        if not packet_info:
            return

        srcip, dstip, proto, _, dport, ts = (
            packet_info[0],
            packet_info[1],
            packet_info[2],
            packet_info[3],
            packet_info[4],
            packet_info[5],
        )

        portproto = f"{dport}/{proto}"
        port_info = self.db.get_port_info(portproto)

        # generate a random uid
        uid = base64.b64encode(binascii.b2a_hex(os.urandom(9))).decode("utf-8")
        profileid = f"profile_{srcip}"
        # sometimes this module tries to find the profile before it's created. so
        # wait a while before alerting.
        time.sleep(4)

        description = (
            f"{rule} to destination address: {dstip} "
            f"port: {portproto} {port_info or ''}. "
            f"Leaked location: {strings_matched}"
        )

        # in which tw is this ts?
        twid = self.db.get_tw_of_ts(profileid, ts)
        # convert ts to a readable format
        ts = utils.convert_format(ts, utils.alerts_format)

        if not twid:
            return

        twid_number = int(twid[0].replace("timewindow", ""))
        # to add a correlation between the 2 evidence in alerts.json
        evidence_id_of_dstip_as_the_attacker = str(uuid4())
        evidence_id_of_srcip_as_the_attacker = str(uuid4())
        evidence = Evidence(
            id=evidence_id_of_srcip_as_the_attacker,
            rel_id=[evidence_id_of_dstip_as_the_attacker],
            evidence_type=EvidenceType.NETWORK_GPS_LOCATION_LEAKED,
            attacker=Attacker(
                direction=Direction.SRC, ioc_type=IoCType.IP, value=srcip
            ),
            threat_level=ThreatLevel.LOW,
            confidence=0.9,
            description=description,
            profile=ProfileID(ip=srcip),
            timewindow=TimeWindow(number=twid_number),
            uid=[uid],
            timestamp=ts,
            proto=Proto(proto.lower()),
            dst_port=int(dport),
        )

        self.db.set_evidence(evidence)

        evidence = Evidence(
            id=evidence_id_of_dstip_as_the_attacker,
            rel_id=[evidence_id_of_srcip_as_the_attacker],
            evidence_type=EvidenceType.NETWORK_GPS_LOCATION_LEAKED,
            attacker=Attacker(
                direction=Direction.DST, ioc_type=IoCType.IP, value=dstip
            ),
            threat_level=ThreatLevel.HIGH,
            confidence=0.9,
            description=description,
            profile=ProfileID(ip=dstip),
            timewindow=TimeWindow(number=twid_number),
            uid=[uid],
            timestamp=ts,
            proto=Proto(proto.lower()),
            dst_port=int(dport),
        )

        self.db.set_evidence(evidence)

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
        utils.drop_root_privs()

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
