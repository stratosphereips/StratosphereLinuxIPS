# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from typing import List, Protocol


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

    def get_not_estab_dst_ports(
        self, protocol: str, state: str, profileid: str, twid: str
    ) -> dict:
        """
        Get the list of dstports that we tried to connect
         to (not established flows)
         here, the profileid given is the client.
         :return: the following dict
         #TODO this is wrong, fix it
         {
             dst_ip: {
                 totalflows: total flows seen by the profileid
                 totalpkt: total packets seen by the profileid
                 totalbytes: total bytes sent by the profileid
                 stime: timestamp of the first flow seen from this
                    profileid -> this dstip
                 uid: list of uids where the given profileid was
                        contacting the dst_ip on this dstport
                 dstports: dst ports seen in all flows where the given
                    profileid was srcip
                     {
                         <str port>: < int spkts sent to this port>
                     }
             }
        """
        # Get the list of dports that we connected as client
        # using TCP not established
        direction = "Dst"
        role = "Client"
        type_data = "Ports"
        dports: dict = self.db.get_data_from_profile_tw(
            profileid, twid, direction, state, protocol, role, type_data
        )
        return dports

    def get_twid_identifier(self, profileid: str, twid: str, dport) -> str:
        if not dport:
            return False

        return f"{profileid}:{twid}:dport:{dport}"

    def are_dstips_greater_or_eq_minimum_dstips(self, dstips) -> bool:
        return dstips >= self.minimum_dstips_to_set_evidence

    @staticmethod
    def are_ips_greater_or_eq_last_evidence(
        dstips: int, ips_reported_last_evidence: int
    ) -> bool:
        """
        Makes sure the amount of dports reported
         each evidence is higher than the previous one +15
        so the first alert will always report 5 dstips,
        and then 20+,35+. etc

        :param dstips: dstips to report in the current evidence
        :param ips_reported_last_evidence: the amount of
            ips reported in the last evidence in the current
            evidence's timewindow
        """
        # the goal is to never get an evidence that's 1 or 2 ports
        #  more than the previous one so we dont have so many
        #  portscan evidence
        if ips_reported_last_evidence == 0:
            # first portscan evidence in this threshold, no past evidence
            # to compare with
            return True

        return dstips >= ips_reported_last_evidence + 15

    def should_set_evidence(self, dstips: int, twid_threshold: int) -> bool:
        more_than_min = self.are_dstips_greater_or_eq_minimum_dstips(dstips)
        exceeded_twid_threshold = self.are_ips_greater_or_eq_last_evidence(
            dstips, twid_threshold
        )
        return more_than_min and exceeded_twid_threshold

    def check_if_enough_dstips_to_trigger_an_evidence(
        self, twid_identifier: str, amount_of_dips: int
    ) -> bool:
        """
        checks if the scanned dst ips are enough to trigger and
        evidence
        to make sure the amount of scanned dst ips reported each
        evidence is higher than the previous one +15
        """
        twid_threshold = self.cached_thresholds_per_tw.get(twid_identifier, 0)

        if self.should_set_evidence(amount_of_dips, twid_threshold):
            self.cached_thresholds_per_tw[twid_identifier] = amount_of_dips
            return True
        return False

    def get_uids(self, dstips: dict) -> List[str]:
        """
        returns all the uids of flows sent on a sigle port
        to different destination IPs
        """
        return [uid for dstip in dstips for uid in dstips[dstip]["uid"]]

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
            timestamp=evidence["timestamp"],
            proto=Proto(evidence["protocol"].lower()),
            dst_port=evidence["dport"],
        )

        self.db.set_evidence(evidence)

    @staticmethod
    def is_valid_twid(twid: str) -> bool:
        return not (twid in ("", None) or "timewindow" not in twid)

    def check(self, profileid: ProfileID, twid: TimeWindow):
        if not utils.are_scan_detection_modules_interested_in_this_ip(
            profileid.ip
        ):
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

                amount_of_dstips: int = (
                    self.db.get_amount_of_dstips_for_not_established_flows_on_port(
                        profileid, twid, protocol, dport
                    )
                )
                if self.check_if_enough_dstips_to_trigger_an_evidence(
                    profileid, twid, dport, amount_of_dstips
                ):
                    evidence = {
                        "protocol": protocol.name.lower(),
                        "profileid": str(profileid),
                        "twid": str(twid),
                        "uids": [],
                        "dport": dport,
                        "pkts_sent": total_pkts,
                        "timestamp": "",  # TODO,
                        "state": State.NOT_EST.name.lower(),
                        "amount_of_dips": amount_of_dstips,
                    }

                    self.set_evidence_horizontal_portscan(evidence)
        return
