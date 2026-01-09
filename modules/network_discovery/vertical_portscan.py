# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
from typing import Dict
from math import log10

from slips_files.common.slips_utils import utils
from slips_files.core.structures.evidence import (
    Evidence,
    ProfileID,
    TimeWindow,
    Attacker,
    ThreatLevel,
    EvidenceType,
    IoCType,
    Direction,
    Victim,
    Proto,
)
from slips_files.core.structures.flow_attributes import (
    State,
    Protocol,
)


class VerticalPortscan:
    """
    Here's how the detection of vertical portscans is done
    1. Slips retrieves all destination IPs of the not
    established flows on TCP and UDP protocols
    2. For each dst IP, slips checks the amount of
    destination ports we connected to
    3. The first evidence will be triggered if the amount of
    destination ports for 1 IP is 5+
    4. then we set evidence on 20+,35+. etc

    The result of this combining of evidence is that the dst ports
     scanned in each evidence will be = the previous scanned ports +15

    this combining is done to avoid duplicate evidence
    the downside to this is that if you do more than 1 portscan
    in the same timewindow, all portscans starting
    from the second portscan will be ignored if they don't exceed
    the number of dports of the first portscan

    so as a rule, each evidence should have X ports scanned. this
    X should ALWAYS be the last portscan+15,
    if this X is the last portscan +14, we don't
    set the evidence.

    5. Once the timewindow ends, Slips resets
     all counters, we go back to step 1
    """

    def __init__(self, db):
        self.db = db
        # to keep track of the max dports reported per timewindow
        self.cached_thresholds_per_tw = {}
        # The minimum amount of scanned ports to trigger an evidence
        # is increased exponentially every evidence, and is reset each timewindow
        self.minimum_dports_to_set_evidence = 5

    def set_evidence_vertical_portscan(self, evidence: dict):
        """Sets the vertical portscan evidence in the db"""
        threat_level = ThreatLevel.HIGH
        saddr = evidence["profileid"].split("_")[-1]
        confidence = utils.calculate_confidence(evidence["pkts_sent"])
        description = (
            f'new vertical port scan to IP {evidence["dstip"]} from {saddr}. '
            f'Total {evidence["amount_of_dports"]} '
            f'{evidence["protocol"].upper()} ports were scanned. '
            f'Total packets sent to all ports: {evidence["pkts_sent"]}. '
            f"Confidence: {confidence}. by Slips"
        )

        attacker = Attacker(
            direction=Direction.SRC, ioc_type=IoCType.IP, value=saddr
        )
        victim = Victim(
            direction=Direction.DST,
            ioc_type=IoCType.IP,
            value=evidence["dstip"],
        )
        twid = int(evidence["twid"].replace("timewindow", ""))
        evidence = Evidence(
            evidence_type=EvidenceType.VERTICAL_PORT_SCAN,
            attacker=attacker,
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid),
            uid=evidence["uid"],
            timestamp=evidence["timestamp"],
            proto=Proto(evidence["protocol"].lower()),
            victim=victim,
        )

        self.db.set_evidence(evidence)

    @staticmethod
    def log(n: int) -> int:
        if n <= 0:
            return 0
        return int(log10(n))

    def should_set_evidence(
        self, current_threshold: int, last_threshold: int
    ) -> bool:
        """
        Makes sure the given dports are more than the dports of
        the last evidence
        """
        return current_threshold > last_threshold

    def check_if_enough_pkts_to_trigger_an_evidence(
        self, profileid, twid, dstip, total_pkts_sent_to_all_dports: int
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
        if not dstip:
            return False

        twid_identifier = f"{profileid}:{twid}:dstip:{dstip}"

        last_threshold = self.cached_thresholds_per_tw.get(twid_identifier, -1)
        current_threshold = self.log(total_pkts_sent_to_all_dports)

        if self.should_set_evidence(current_threshold, last_threshold):
            # keep track of the reported log(dstport)
            # in the last evidence in this twid
            self.cached_thresholds_per_tw[twid_identifier] = current_threshold
            return True
        return False

    def check(self, profileid: ProfileID, twid: TimeWindow):
        """
        sets an evidence if a vertical portscan is detected
        """
        # When scanning an open port, the connection will appear as
        # ESTABLISHED.
        # Open ports are typically very few compared to the full port range.
        # Ignoring ESTABLISHED connections is theoretically inaccurate because
        # it misses scans hitting open ports, but in practice this is
        # negligible. Focusing on non-ESTABLISHED states significantly
        # reduces false positives while preserving the port-scan signal.
        for protocol in (Protocol.TCP, Protocol.UDP):
            # For each dstip, see if the amount of ports
            # connections is over the threshold
            for (
                dstip,
                metadata,
            ) in self.db.get_dstips_with_not_established_flows(
                profileid, twid, protocol
            ):
                if not (
                    utils.are_detection_modules_interested_in_this_ip(dstip)
                ):
                    continue
                # Get the total amount of pkts sent to all
                # ports on the same host
                amount_of_dports, total_pkts_sent_to_all_dports = (
                    self.db.get_info_about_not_established_flows(
                        profileid, twid, protocol, dstip
                    )
                )
                amount_of_dports, total_pkts_sent_to_all_dports = int(
                    amount_of_dports
                ), int(total_pkts_sent_to_all_dports)

                if self.check_if_enough_pkts_to_trigger_an_evidence(
                    profileid, twid, dstip, total_pkts_sent_to_all_dports
                ):
                    metadata: Dict[str, float] = json.loads(metadata)
                    evidence_details = {
                        "timestamp": metadata["first_seen"],
                        "pkts_sent": total_pkts_sent_to_all_dports,
                        "protocol": protocol.name.lower(),
                        "profileid": str(profileid),
                        "twid": str(twid),
                        "uid": [],
                        "amount_of_dports": amount_of_dports,
                        "dstip": dstip,
                        "state": State.NOT_EST.name.lower(),
                    }

                    self.set_evidence_vertical_portscan(evidence_details)
