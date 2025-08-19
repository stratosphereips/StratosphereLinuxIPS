# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from typing import List
from slips_files.core.structures.evidence import (
    Evidence,
    ProfileID,
    TimeWindow,
    Victim,
    Attacker,
    ThreatLevel,
    EvidenceType,
    IoCType,
    Direction,
)
from modules.arp.filter import ARPEvidenceFilter
from slips_files.core.database.database_manager import DBManager


class ARPSetEvidenceHelper:
    """
    PS: if you wanna use the ARP poisoner filter (the discards Slips
    generated ARP evidence) then use self.decide_setting_evidence(evidence)
    If you dont, then use self.db.set_evidence(evidence)
    this evidence filter should only be used here:D
    """

    def __init__(self, db: DBManager):
        self.db = db
        self.evidence_filter = ARPEvidenceFilter(self.conf, self.args, self.db)

    def dstip_outside_localnet(self, flow, twid):
        # comes here if the IP isn't in any of the local networks
        confidence: float = 0.6
        threat_level: ThreatLevel = ThreatLevel.LOW
        description: str = (
            f"{flow.saddr} sending ARP packet to a destination "
            f"address outside of local network: {flow.daddr}. "
        )

        attacker: Attacker = Attacker(
            direction=Direction.SRC,
            ioc_type=IoCType.IP,
            value=flow.saddr,
        )
        victim = Victim(
            direction=Direction.DST,
            ioc_type=IoCType.IP,
            value=flow.daddr,
        )

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.ARP_OUTSIDE_LOCALNET,
            attacker=attacker,
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=flow.saddr),
            timewindow=TimeWindow(number=int(twid.replace("timewindow", ""))),
            uid=[flow.uid],
            timestamp=flow.starttime,
            victim=victim,
        )
        # no need to go through the arp filter here,
        # because the filter is only to filter attacks that can be done
        # using the arp_poisoner, but this one isnt done there.
        self.db.set_evidence(evidence)

    def unsolicited_arp(self, flow, twid):
        # We're sure this is unsolicited arp
        # it may be arp spoofing
        confidence: float = 0.8
        threat_level: ThreatLevel = ThreatLevel.LOW
        description: str = "broadcasting unsolicited ARP reply."

        attacker = Attacker(
            direction=Direction.SRC,
            ioc_type=IoCType.IP,
            value=flow.saddr,
        )

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.UNSOLICITED_ARP_REPLY,
            attacker=attacker,
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=flow.saddr),
            timewindow=TimeWindow(number=int(twid.replace("timewindow", ""))),
            uid=[flow.uid],
            timestamp=flow.starttime,
        )

        self._decide_setting_evidence(evidence)

    def arp_scan(self, ts, profileid, twid, uids: List[str]):
        confidence: float = 0.8
        threat_level: ThreatLevel = ThreatLevel.LOW
        saddr: str = profileid.split("_")[1]

        description: str = f"performing an arp scan. Confidence {confidence}."
        attacker: Attacker = Attacker(
            direction=Direction.SRC, ioc_type=IoCType.IP, value=saddr
        )

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.ARP_SCAN,
            attacker=attacker,
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=int(twid.replace("timewindow", ""))),
            uid=uids,
            timestamp=ts,
        )

        self._decide_setting_evidence(evidence)
        # after we set evidence, clear the dict so we can detect if it
        # does another scan
        try:
            self.cache_arp_requests.pop(f"{profileid}_{twid}")
        except KeyError:
            # when a tw is closed, we clear all its' entries from the
            # cache_arp_requests dict
            # having keyerr is a result of closing a timewindow before
            # setting an evidence
            # ignore it
            pass

    def mitm_arp_attack(self, flow, twid, original_ip):
        # From our db we know that:
        # original_IP has src_MAC
        # now saddr has src_MAC and saddr isn't the same as original_IP
        # so this is either a MITM arp attack or the IP
        # address of this src_mac simply changed
        # todo how to find out which one is it??
        # Assuming that 'threat_level' and 'category'
        # are from predefined enums or constants
        confidence: float = 0.2  # low confidence for now
        threat_level: ThreatLevel = ThreatLevel.CRITICAL

        attackers_ip = flow.saddr
        victims_ip = original_ip

        gateway_ip = self.db.get_gateway_ip()
        gateway_mac = self.db.get_gateway_mac()
        if flow.saddr == gateway_ip:
            saddr = f"The gateway {flow.saddr}"
        else:
            saddr = flow.saddr

        if flow.smac == gateway_mac:
            src_mac = f"of the gateway {flow.smac}"
        else:
            src_mac = flow.smac

        original_ip = f"IP {original_ip}"
        if original_ip == gateway_ip:
            original_ip = f"the gateway IP {original_ip}"

        attacker: Attacker = Attacker(
            direction=Direction.SRC,
            ioc_type=IoCType.IP,
            value=attackers_ip,
        )

        victim = Victim(
            direction=Direction.DST,  #  TODO not really dst
            ioc_type=IoCType.IP,
            value=victims_ip,
        )

        description = (
            f"{saddr} performing a MITM ARP attack. "
            f"The MAC {src_mac}, now belonging to "
            f"{saddr}, was seen before for {original_ip}."
        )

        evidence: Evidence = Evidence(
            evidence_type=EvidenceType.MITM_ARP_ATTACK,
            attacker=attacker,
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            profile=ProfileID(ip=attackers_ip),
            timewindow=TimeWindow(number=int(twid.replace("timewindow", ""))),
            uid=[flow.uid],
            timestamp=flow.starttime,
            victim=victim,
        )

        self.set_evidence(evidence)

    async def _decide_setting_evidence(self, evidence: Evidence):
        """the goal of this function is to discard evidence of other slips
        peers doing arp scans because that's slips attacking back attackers"""
        if self.evidence_filter.should_discard_evidence(evidence.profile.ip):
            return
        await self.db.set_evidence(evidence)
