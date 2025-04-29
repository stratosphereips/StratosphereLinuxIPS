# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
import ipaddress
import os
import time
import threading
from multiprocessing import Queue
from typing import List

from slips_files.common.flow_classifier import FlowClassifier
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from slips_files.common.abstracts.module import IModule
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


class ARP(IModule):
    # Name: short name of the module. Do not use spaces
    name = "ARP"
    description = "Detect ARP attacks"
    authors = ["Alya Gomaa"]

    def init(self):
        self.c1 = self.db.subscribe("new_arp")
        self.c2 = self.db.subscribe("tw_closed")
        self.channels = {
            "new_arp": self.c1,
            "tw_closed": self.c2,
        }
        self.read_configuration()
        self.classifier = FlowClassifier()
        # this dict will categorize arp requests by profileid_twid
        self.cache_arp_requests = {}
        # Threshold to use to detect a port scan. How many arp minimum
        # are required?
        self.arp_scan_threshold = 5
        self.delete_arp_periodically = False
        self.arp_log_creation_time = 0
        self.period_before_deleting = 0
        if self.delete_zeek_files and not self.store_zeek_files_copy:
            self.delete_arp_periodically = True
            # first time arp.log is created
            self.arp_log_creation_time = time.time()
            # thats one hour in seconds
            self.period_before_deleting = 3600
        self.timer_thread_arp_scan = threading.Thread(
            target=self.wait_for_arp_scans,
            daemon=True,
            name="timer_thread_arp_scan",
        )
        self.pending_arp_scan_evidence = Queue()
        self.alerted_once_arp_scan = False
        # wait 10s for mmore arp scan evidence to come
        self.time_to_wait = 10
        self.is_zeek_running: bool = self.is_running_zeek()

    def read_configuration(self):
        conf = ConfigParser()
        self.home_network = conf.home_network_ranges
        self.delete_zeek_files = conf.delete_zeek_files()
        if self.delete_zeek_files:
            self.print(
                "Warning: Slips will delete Zeek log files after "
                "the analysis is done. and will delete arp.log every 1h. "
                "You can modify this by changing "
                "delete_zeek_files in the config file."
            )
        self.store_zeek_files_copy = conf.store_zeek_files_copy()

    def is_running_zeek(self) -> bool:
        return (
            self.db.get_input_type() == "pcap" or self.db.is_running_non_stop()
        )

    def wait_for_arp_scans(self):
        """
        This thread waits for 10s then checks if more
        arp scans happened to reduce the number of alerts
        """
        # this evidence is the one that triggered this thread
        scans_ctr = 0
        while not self.should_stop():
            try:
                evidence: dict = self.pending_arp_scan_evidence.get(
                    timeout=0.5
                )
            except Exception:
                # nothing in queue
                time.sleep(5)
                continue
            # unpack the evidence that triggered the thread
            (ts, profileid, twid, uids) = evidence

            # wait 10s if a new evidence arrived
            time.sleep(self.time_to_wait)

            while True:
                try:
                    new_evidence = self.pending_arp_scan_evidence.get(
                        timeout=0.5
                    )
                except Exception:
                    # queue is empty
                    break

                (ts2, profileid2, twid2, uids2) = new_evidence
                if profileid == profileid2 and twid == twid2:
                    # this should be combined with the past alert
                    ts = ts2
                    uids += uids2
                else:
                    # this is an ip performing arp scan in a diff
                    # profile or a diff twid, we shouldn't accumulate its
                    # evidence  store it back in the queue until we're done
                    # with the current one
                    scans_ctr += 1
                    self.pending_arp_scan_evidence.put(new_evidence)
                    if scans_ctr == 3:
                        scans_ctr = 0
                        break

            self.set_evidence_arp_scan(ts, profileid, twid, uids)

    def check_arp_scan(self, profileid, twid, flow):
        """
        Check if the profile is doing an arp scan
        If IP X sends arp requests to 3 or more different
        IPs within 30 seconds, then this IP X is doing arp scan
        The key profileid_twid is used to group requests
        from the same saddr
        arp flows don't have uids, the uids received are
        randomly generated by slips
        """

        # ARP scans are always requests always? mostly? from 00:00:00:00:00:00
        if (
            "request" not in flow.operation
            or "00:00:00:00:00:00" not in flow.dst_hw
        ):
            return False

        def get_uids():
            """
            get the uids causing this evidence
            """
            res = []
            for daddr, daddr_info in cached_requests.items():
                for uid in daddr_info["uids"]:
                    res.append(uid)
            return res

        # The Gratuitous arp is sent as a broadcast, as a way for a
        # node to announce or update its IP to MAC mapping
        # to the entire network. It shouldn't be marked as an arp scan
        # Don't detect arp scan from the GW router
        if self.db.get_gateway_ip() == flow.saddr:
            return False

        # What is this?
        if flow.saddr == "0.0.0.0":
            return False

        daddr_info = {flow.daddr: {"uids": [flow.uid], "ts": flow.starttime}}
        try:
            # Get together all the arp requests to IPs in this TW
            cached_requests = self.cache_arp_requests[f"{profileid}_{twid}"]
            # Append the arp request, and when it happened
            if flow.daddr in cached_requests:
                cached_requests[flow.daddr]["uids"].append(flow.uid)
                cached_requests[flow.daddr]["ts"] = flow.starttime
                self.cache_arp_requests[f"{profileid}_{twid}"] = (
                    cached_requests
                )
            else:
                cached_requests.update(daddr_info)
        except KeyError:
            # create the key for this profileid_twid if it doesn't exist
            self.cache_arp_requests[f"{profileid}_{twid}"] = daddr_info

            return True

        # the list of daddrs that are scanned by the current
        # proffileid in the curr tw
        daddrs = list(cached_requests.keys())

        # The minimum amount of arp packets to send to be
        # considered as scan is 5
        if len(daddrs) >= self.arp_scan_threshold:
            # check if these requests happened within 30 secs
            # get the first and the last request of the 10
            first_daddr = daddrs[0]
            last_daddr = daddrs[-1]
            starttime = cached_requests[first_daddr]["ts"]
            endtime = cached_requests[last_daddr]["ts"]
            # todo do we need mac addresses?
            self.diff = utils.get_time_diff(starttime, endtime)

            # in seconds
            if self.diff <= 30.00:
                uids = get_uids()
                # we are sure this is an arp scan
                if not self.alerted_once_arp_scan:
                    self.alerted_once_arp_scan = True
                    self.set_evidence_arp_scan(
                        flow.starttime, profileid, twid, uids
                    )
                else:
                    # after alerting once, wait 10s to see
                    # if more evidence are coming
                    self.pending_arp_scan_evidence.put(
                        (flow.starttime, profileid, twid, uids)
                    )

                return True
        return False

    def set_evidence_arp_scan(self, ts, profileid, twid, uids: List[str]):
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

        self.db.set_evidence(evidence)
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

    def check_dstip_outside_localnet(self, twid, flow):
        """Function to setEvidence when daddr is outside the local network"""

        if "0.0.0.0" in flow.saddr or "0.0.0.0" in flow.daddr:
            # this is the case of arp probe, not an
            # arp outside of local network, don't alert
            return False

        daddr_as_obj = ipaddress.IPv4Address(flow.daddr)
        if daddr_as_obj.is_multicast or daddr_as_obj.is_link_local:
            # The arp to ‘outside’ the network should
            # not detect multicast or link-local addresses.
            return False

        for network in self.home_network:
            if daddr_as_obj in network:
                # IP is in this local network, don't alert
                return False

        # to prevent arp alerts from one IP to itself
        first_octet = flow.saddr.split(".")[0]
        if not flow.daddr.startswith(first_octet):
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
                timewindow=TimeWindow(
                    number=int(twid.replace("timewindow", ""))
                ),
                uid=[flow.uid],
                timestamp=flow.starttime,
                victim=victim,
            )
            self.db.set_evidence(evidence)
            return True

        return False

    def detect_unsolicited_arp(self, twid: str, flow):
        """
        Unsolicited arp is used to update the neighbours'
        arp caches but can also be used in arp spoofing
        """
        if (
            flow.dmac == "ff:ff:ff:ff:ff:ff"
            and flow.dst_hw == "ff:ff:ff:ff:ff:ff"
            and flow.smac != "00:00:00:00:00:00"
            and flow.src_hw != "00:00:00:00:00:00"
        ):
            # We're sure this is unsolicited arp
            # it may be arp spoofing
            confidence: float = 0.8
            threat_level: ThreatLevel = ThreatLevel.LOW
            description: str = "broadcasting unsolicited ARP"

            attacker = Attacker(
                direction=Direction.SRC,
                ioc_type=IoCType.IP,
                value=flow.saddr,
            )

            evidence: Evidence = Evidence(
                evidence_type=EvidenceType.UNSOLICITED_ARP,
                attacker=attacker,
                threat_level=threat_level,
                confidence=confidence,
                description=description,
                profile=ProfileID(ip=flow.saddr),
                timewindow=TimeWindow(
                    number=int(twid.replace("timewindow", ""))
                ),
                uid=[flow.uid],
                timestamp=flow.starttime,
            )

            self.db.set_evidence(evidence)
            return True

    def detect_mitm_arp_attack(self, twid: str, flow):
        """
        Detects when a MAC with IP A, is trying to tell others that
        now that MAC is also for IP B (arp cache attack)
        """
        # Todo in rare cases, the vendor and IP of this mac is known AFTER
        #  returning from this function so detection is missed

        # to test this add these 2 flows to arp.log
        # {"ts":1636305825.755132,"operation":"reply",
        # "src_mac":"2e:a4:18:f8:3d:02", "dst_mac":"ff:ff:ff:ff:ff:ff",
        # "orig_h":"172.20.7.40","resp_h":"172.20.7.40",
        # "orig_hw":"2e:a4:18:f8:3d:02", "resp_hw":"00:00:00:00:00:00"}
        # {"ts":1636305825.755132,"operation":"reply",
        # "src_mac":"2e:a4:18:f8:3d:02", "dst_mac":"ff:ff:ff:ff:ff:ff",
        # "orig_h":"172.20.7.41","resp_h":"172.20.7.41",
        # "orig_hw":"2e:a4:18:f8:3d:02", "resp_hw":"00:00:00:00:00:00"}

        # todo will we get FPs when an ip changes?
        # todo what if the ip of the attacker came to us
        #  first and we stored it in the db?
        #  the original IP of this src mac is now the IP of the attacker?

        # get the original IP of the src mac from the database
        original_ip: str = self.db.get_ip_of_mac(flow.smac)
        if original_ip is None:
            return

        # original_IP is a serialized list
        original_ip: str = json.loads(original_ip)[0]
        original_ip = original_ip.replace("profile_", "")

        # is this saddr trying to tell everyone that this
        # it owns this flow.smac even though we know this
        # src_mac is associated
        # with another IP (original_IP)?
        if flow.saddr != original_ip:
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
                timewindow=TimeWindow(
                    number=int(twid.replace("timewindow", ""))
                ),
                uid=[flow.uid],
                timestamp=flow.starttime,
                victim=victim,
            )

            self.db.set_evidence(evidence)
            return True

    def check_if_gratutitous_arp(self, flow):
        """
        Check if an ARP packet is gratuitous

        The Gratuitous arp is sent as a broadcast, as a way for a
        node to announce or update
        its IP to MAC mapping to the entire network.
        Gratuitous ARP shouldn't be marked as an arp scan
        Check https://www.practicalnetworking.net/series/arp/gratuitous-arp/
        dst_mac is the real MAC used to deliver the packet
        src_mac is the real MAC used to deliver the packet
        dst_hw is the MAC in the headers of the ARP packet
        src_hw is the MAC in the headers of the ARP packet
        saddr is the IP in the headers of the ARP packet
        daddr is the IP in the headers of the ARP packet

        Gratuitous ARP can be used for (1) Updating ARP Mapping,
        (2) Announcing a Node’s Existence,
        (3) Redundancy, (4) MITM. Which is similar to an
        'unrequested' load balancing
         The saddr and daddr are the ones being avertised.
         The supposed purpose of the Gratuitous ARP
        """
        # It should be a reply
        # The dst_mac should be ff:ff:ff:ff:ff:ff or 00:00:00:00:00:00
        return "reply" in flow.operation and flow.dst_hw in [
            "ff:ff:ff:ff:ff:ff",
            "00:00:00:00:00:00",
        ]

    def clear_arp_logfile(self):
        if not self.delete_arp_periodically:
            return

        if not self.is_zeek_running:
            # we only clear arp.log if it's growing, aka zeek is running in
            # real time and generating logs constantly. like
            # interfaces/pcaps and growing zeek dirs
            return

        if (
            time.time()
            >= self.arp_log_creation_time + self.period_before_deleting
        ):
            arp_log_file_path = os.path.join(
                self.db.get_output_dir(), "zeek_files/arp.log"
            )
            open(arp_log_file_path, "w").close()
            # update ts of the new arp.log
            self.arp_log_creation_time = time.time()

    def pre_main(self):
        """runs once before the main() is executed in a loop"""
        utils.drop_root_privs()
        utils.start_thread(self.timer_thread_arp_scan, self.db)

    def main(self):
        self.clear_arp_logfile()

        if msg := self.get_msg("new_arp"):
            msg = json.loads(msg["data"])
            profileid = msg["profileid"]
            twid = msg["twid"]
            # this is the actual arp flow
            flow = self.classifier.convert_to_flow_obj(msg["flow"])
            # PS: arp flows don't have uids by zeek. the uids received
            # are randomly generated by slips

            if self.check_if_gratutitous_arp(flow):
                # for MITM arp attack, the arp has to be gratuitous
                # and it has to be a reply operation, not a request.
                # A gratuitous ARP is always a reply. A MITM attack
                # happens when there is a reply without a request
                self.detect_mitm_arp_attack(twid, flow)
            else:
                # not gratuitous and request, may be an arp scan
                self.check_arp_scan(profileid, twid, flow)

            if "request" in flow.operation:
                self.check_dstip_outside_localnet(twid, flow)
            elif "reply" in flow.operation:
                # Unsolicited ARPs should be of type reply only, not request
                self.detect_unsolicited_arp(twid, flow)

        # if the tw is closed, remove all its entries from the cache dict
        if msg := self.get_msg("tw_closed"):
            profileid_tw = msg["data"]
            # when a tw is closed, this means that it's too
            # old so we don't check for arp scan in this time
            # range anymore
            # this copy is made to avoid dictionary
            # changed size during iteration err
            cache_copy = self.cache_arp_requests.copy()
            for key in cache_copy:
                if profileid_tw in key:
                    self.cache_arp_requests.pop(key)
                    # don't break, keep looking for more
                    # keys that belong to the same tw
