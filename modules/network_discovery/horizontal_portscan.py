# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from math import log10

from slips_files.core.structures.flow_attributes import Protocol

from slips_files.common.slips_utils import utils
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
from slips_files.core.structures.flow_attributes import State


class HorizontalPortscan:
    """
    Horizontal scanning sends requests to the same port
    on different hosts.
    """

    def __init__(self, db):
        self.db = db
        # to keep track of the max dports reported per timewindow
        self.cached_thresholds_per_tw = {}
        # The minimum amount of scanned dstips to trigger an evidence
        # is increased exponentially every evidence, and is reset each timewindow
        self.minimum_dstips_to_set_evidence = 5

    def should_set_evidence(
        self, current_threshold: int, last_threshold: int
    ) -> bool:
        """
        Makes sure the current threshold exceeds the threshold of last
        evidence in this tw. to force the log scale.
        """
        return current_threshold > last_threshold

    @staticmethod
    def log(n: int) -> int:
        if n <= 0:
            return 0
        return int(log10(n))

    def check_if_enough_dstips_to_trigger_an_evidence(
        self, profileid, twid, dport, total_pkts: int
    ) -> bool:
        """
        checks if the pkts used so far are enough to trigger a new
        evidence

        Returns True only when log10(pkts) exceeds the logarithmic
        bucket of the last reported evidence.

        The goal is to never get an evidence that's
         1 or 2 ports more than the previous one so we dont
         have so many portscan evidence
        """
        if not dport:
            return False

        twid_identifier = f"{profileid}_{twid}:dport:{dport}"

        last_threshold = self.cached_thresholds_per_tw.get(twid_identifier, 0)
        current_threshold = self.log(total_pkts)

        if self.should_set_evidence(current_threshold, last_threshold):
            # keep track of the reported evidence's log(pkts)
            self.cached_thresholds_per_tw[twid_identifier] = current_threshold
            return True
        return False

    def set_evidence_horizontal_portscan(self, evidence: dict):
        threat_level = ThreatLevel.HIGH
        confidence = utils.calculate_confidence(evidence["pkts_sent"])
        srcip = evidence["profileid"].split("_")[-1]

        attacker = Attacker(
            direction=Direction.SRC, ioc_type=IoCType.IP, value=srcip
        )
        portproto = f'{evidence["dport"]}/{evidence["protocol"]}'
        port_info = self.db.get_port_info(portproto) or ""
        description = (
            f"Horizontal port scan to port {port_info} {portproto}. "
            f'From {srcip} to {evidence["amount_of_dips"]} '
            f"unique destination IPs. "
            f'Total packets sent: {evidence["pkts_sent"]}. '
            f"Confidence: {confidence}. by Slips"
        )

        evidence = Evidence(
            evidence_type=EvidenceType.HORIZONTAL_PORT_SCAN,
            attacker=attacker,
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=srcip),
            timewindow=TimeWindow(
                number=int(evidence["twid"].replace("timewindow", ""))
            ),
            uid=evidence["uids"],
            timestamp=evidence["first_timestamp"],  # TODO use last_timestamp
            proto=Proto(evidence["protocol"].lower()),
            dst_port=evidence["dport"],
        )

        self.db.set_evidence(evidence)

    def check(self, profileid: ProfileID, twid: TimeWindow):
        if not utils.are_detection_modules_interested_in_this_ip(profileid.ip):
            return False

        # if you're portscaning a port that is open it's gonna be established
        # the amount of open ports we find is gonna be so small
        # theoretically this is incorrect bc we'll be ignoring
        # established evidence,
        # but usually open ports are very few compared to the whole range
        # so, practically using not established only this is correct to
        # avoid FP
        for protocol in (Protocol.TCP, Protocol.UDP):
            # For each port, see if the amount is over the threshold
            for (
                dport,
                total_pkts,
            ) in self.db.get_dstports_of_not_established_flows(
                profileid, twid, protocol
            ):
                dport, total_pkts = int(dport), int(total_pkts)
                amount_of_dstips: int = (
                    self.db.get_total_dstips_for_not_estab_flows_on_port(
                        profileid, twid, protocol, dport
                    )
                )
                if self.check_if_enough_dstips_to_trigger_an_evidence(
                    profileid, twid, dport, total_pkts
                ):
                    first_timestamp = self.db.get_attack_starttime(
                        profileid, twid, protocol, dport
                    )
                    evidence = {
                        "protocol": protocol.name.lower(),
                        "profileid": str(profileid),
                        "twid": str(twid),
                        "uids": [],
                        "dport": dport,
                        "pkts_sent": total_pkts,
                        "first_timestamp": first_timestamp,
                        "state": State.NOT_EST.name.lower(),
                        "amount_of_dips": amount_of_dstips,
                    }

                    self.set_evidence_horizontal_portscan(evidence)
        return
