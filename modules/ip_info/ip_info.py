# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import asyncio
import ipaddress
import json
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import Any, Callable
from uuid import uuid4

import maxminddb

from modules.ip_info.asn_info import ASN
from modules.ip_info.domain_info import DomainInfo
from modules.ip_info.gateway_info import GatewayInfo
from modules.ip_info.host_info import HostIdentityArchiver
from modules.ip_info.jarm import JARM
from modules.ip_info.mac_vendor_info import MACVendor
from modules.ip_info.rdns_info import RDNS
from slips_files.common.abstracts.iasync_module import IAsyncModule
from slips_files.common.flow_classifier import FlowClassifier
from slips_files.common.slips_utils import utils
from slips_files.common.style import green
from slips_files.core.helpers.whitelist.whitelist import Whitelist
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


class IPInfo(IAsyncModule):
    # Name: short name of the module. Do not use spaces
    name = "ip_info"
    description = (
        "Get info about IPs, MACs and domains, "
        "and archive host identity across runs"
    )
    authors = ["Alya Gomaa", "Sebastian Garcia"]

    def init(self):
        """This will be called when initializing this module"""
        self.lookup_executor = ThreadPoolExecutor(
            max_workers=4, thread_name_prefix="ip-info"
        )
        self.lookup_semaphore = asyncio.Semaphore(4)
        # a thread of its own, so a host archive batch never waits behind
        # slow lookups, and two batches never overlap
        self.host_archive_executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="host-archive"
        )
        self.pending_ip_lookups: set[str] = set()
        self.asn = ASN(self.db)
        self.JARM = JARM()
        self.rdns = RDNS(self.db)
        self.mac_vendor = MACVendor(self.db)
        self.classifier = FlowClassifier()
        self.whitelist = Whitelist(self.logger, self.db, self.bloom_filters)
        self.domain_info = DomainInfo(self.db, self.whitelist)
        self.gateway = GatewayInfo(
            self.db, self.args, self.db.is_running_non_stop()
        )
        self.host_identity_archiver = HostIdentityArchiver(self.db)
        self.is_running_in_ap_mode: bool = (
            True if self.args.access_point else False
        )

    def subscribe_to_channels(self):
        self.c1 = self.db.subscribe("new_ip")
        self.c2 = self.db.subscribe("new_MAC")
        self.c3 = self.db.subscribe("new_dns")
        self.c4 = self.db.subscribe("check_jarm_hash")
        self.channels = {
            "new_ip": self.c1,
            "new_MAC": self.c2,
            "new_dns": self.c3,
            "check_jarm_hash": self.c4,
        }

    def open_dbs(self) -> None:
        """Function to open the different offline databases used in this
        module. ASN, Country etc.."""
        # Open the maxminddb ASN offline db
        try:
            self.asn_db = maxminddb.open_database(
                "databases/GeoLite2-ASN.mmdb"
            )
        except Exception:
            self.print(
                "Error opening the geolite2 db in databases/GeoLite2-ASN.mmdb. "
                "Please download it from "
                "https://dev.maxmind.com/geoip/docs/databases/asn?lang=en "
                "Please note it must be the MaxMind DB version."
            )

        # Open the maminddb Country offline db
        try:
            self.country_db = maxminddb.open_database(
                "databases/GeoLite2-Country.mmdb"
            )
        except Exception:
            self.print(
                "Error opening the geolite2 db in databases/GeoLite2-Country.mmdb. "
                "Please download it from "
                "https://dev.maxmind.com/geoip/geolite2-free-geolocation-data?lang=en. "
                "Please note it must be the MaxMind DB version."
            )
        self._start_mac_db_reader()

    def _start_mac_db_reader(self) -> None:
        """
        Schedule the MAC vendor database reader on the active event loop.
        """
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return

        self.reading_mac_db_task = self.create_task(
            self.mac_vendor.read_mac_db
        )

    # GeoInfo functions
    def get_geocountry(self, ip) -> dict:
        """
        Get ip geocountry from geolite database
        :param ip: str
        """
        if not hasattr(self, "country_db"):
            return False

        if utils.is_private_ip(ipaddress.ip_address(ip)):
            # Try to find if it is a local/private IP
            data = {"geocountry": "Private"}
        elif geoinfo := self.country_db.get(ip):
            try:
                countrydata = geoinfo["country"]
                countryname = countrydata["names"]["en"]
                data = {"geocountry": countryname}
            except KeyError:
                data = {"geocountry": "Unknown"}

        else:
            data = {"geocountry": "Unknown"}
        self.db.set_ip_info(ip, data)
        return data

    async def gather_tasks_and_shutdown_gracefully(self) -> None:
        """Stop the optional MAC database retry before draining lookups."""
        mac_db_reader_task = getattr(self, "reading_mac_db_task", None)
        if (
            isinstance(mac_db_reader_task, asyncio.Task)
            and not mac_db_reader_task.done()
        ):
            mac_db_reader_task.cancel()
            await asyncio.gather(mac_db_reader_task, return_exceptions=True)
        await super().gather_tasks_and_shutdown_gracefully()

    async def shutdown_gracefully(self):
        try:
            await self.host_identity_archiver.flush_async(
                self.run_host_archive_step
            )
        finally:
            self.host_archive_executor.shutdown(wait=True)
            if hasattr(self, "asn_db"):
                self.asn_db.close()
            if hasattr(self, "country_db"):
                self.country_db.close()
            self.lookup_executor.shutdown(wait=True, cancel_futures=True)
            self.domain_info.clear_caches()
            self.rdns.clear_caches()

    async def run_lookup(self, func, *args):
        """
        Run a blocking lookup in the bounded thread pool.

        :param func: Callable to execute.
        :param args: Positional arguments for the callable.
        :return: Callable result.
        """
        async with self.lookup_semaphore:
            loop = asyncio.get_running_loop()
            bound_func = partial(func, *args)
            return await loop.run_in_executor(self.lookup_executor, bound_func)

    async def run_host_archive_step(
        self, func: Callable[..., Any], *args: Any
    ) -> Any:
        """Run blocking host archive work in its own thread.

        Reading and writing SQLite on the event loop would freeze every
        lookup of this module for as long as the disk takes.

        Parameters:
            func: Blocking callable to execute.
            args: Positional arguments for the callable.

        Returns:
            Callable result.
        """
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self.host_archive_executor, partial(func, *args)
        )

    async def handle_new_ip_async(self, ip: str):
        """
        Enrich a newly seen IP without blocking the event loop.

        :param ip: IP address to enrich.
        :return: None.
        """
        try:
            ip_addr = ipaddress.ip_address(ip)
        except ValueError:
            return

        if ip_addr.is_multicast:
            return

        if (
            ip in self.pending_ip_lookups
            or len(self.pending_ip_lookups) >= 1024
        ):
            return
        self.pending_ip_lookups.add(ip)
        try:
            geocountry = self.db.get_ip_info(ip, "geocountry")
            if not geocountry:
                self.get_geocountry(ip)

            # A slow or failed remote ASN lookup must not prevent rDNS.
            if not self.db.get_rdns_info(ip):
                await self.rdns.get_rdns_async(ip, self.run_lookup)

            asn = self.db.get_asn_info(ip)
            if self.asn.should_update_asn(asn):
                await self.asn.get_asn_async(ip, self.run_lookup)
        finally:
            self.pending_ip_lookups.discard(ip)

    async def handle_new_mac_async(self, mac_addr: str, profileid: str):
        """
        Enrich a newly seen MAC without blocking the event loop.

        :param mac_addr: MAC address to enrich.
        :param profileid: Profile associated with the MAC.
        :return: None.
        """
        await self.mac_vendor.get_vendor_async(
            mac_addr, profileid, self.run_lookup
        )
        self.mac_vendor.check_if_we_have_pending_offline_mac_queries()

    async def handle_new_dns_async(self, domain: str):
        """
        Enrich a newly seen domain without blocking the event loop.

        :param domain: Domain to enrich.
        :return: None.
        """
        await self.domain_info.get_domain_info_async(domain, self.run_lookup)

    @staticmethod
    def _is_dns(flow: Any) -> bool:
        return str(flow.dport) == "53" and flow.proto.lower() == "udp"

    def register_private_dns_server(self, flow: Any) -> bool:
        """
        Store and announce a private DNS server seen in analyzed DNS traffic.

        :return: True when the destination IP was accepted as a private DNS
            server.
        """
        if not self._is_dns(flow):
            return False

        try:
            daddr_obj = ipaddress.ip_address(flow.daddr)
        except ValueError:
            return False

        if not utils.is_private_ip(daddr_obj):
            return False

        if self.db.is_official_dns_server(flow.daddr):
            return True

        self.db.store_official_dns_server(flow.daddr)
        self.print(
            f"Detected DNS server by traffic heuristic: "
            f"{green(flow.daddr)}"
        )
        return True

    def wait_for_dbs(self) -> None:
        """
        wait for update manager to finish updating the mac db and open the
        rest of dbs before starting this module
        """
        self.open_dbs()

    def set_evidence_malicious_jarm_hash(
        self,
        flow: dict,
        twid: str,
    ):
        dport: int = flow["dport"]
        dstip: str = flow["daddr"]
        saddr: str = flow["saddr"]
        timestamp = flow["starttime"]
        protocol: str = flow["proto"]

        portproto = f"{dport}/{protocol}"
        port_info = self.db.get_port_info(portproto) or ""
        port_info = f"({port_info.upper()})" if port_info else ""

        description = (
            f"Malicious JARM hash detected for destination IP: {dstip}"
            f" on port: {portproto} {port_info}. "
        )
        twid_number = int(twid.replace("timewindow", ""))
        # to add a correlation between the 2 evidence in alerts.json
        evidence_id_of_dstip_as_the_attacker = str(uuid4())
        evidence_id_of_srcip_as_the_attacker = str(uuid4())
        evidence = Evidence(
            id=evidence_id_of_dstip_as_the_attacker,
            rel_id=[evidence_id_of_srcip_as_the_attacker],
            evidence_type=EvidenceType.MALICIOUS_JARM,
            attacker=Attacker(
                direction=Direction.DST, ioc_type=IoCType.IP, value=dstip
            ),
            threat_level=ThreatLevel.MEDIUM,
            confidence=0.7,
            description=description,
            profile=ProfileID(ip=dstip),
            timewindow=TimeWindow(number=twid_number),
            uid=[flow["uid"]],
            timestamp=timestamp,
            proto=Proto(protocol.lower()),
        )

        self.db.set_evidence(evidence)

        evidence = Evidence(
            id=evidence_id_of_srcip_as_the_attacker,
            rel_id=[evidence_id_of_dstip_as_the_attacker],
            evidence_type=EvidenceType.MALICIOUS_JARM,
            attacker=Attacker(
                direction=Direction.SRC, ioc_type=IoCType.IP, value=saddr
            ),
            threat_level=ThreatLevel.LOW,
            confidence=0.7,
            description=description,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid_number),
            uid=[flow["uid"]],
            timestamp=timestamp,
            proto=Proto(protocol.lower()),
            dst_port=443,
        )

        self.db.set_evidence(evidence)

    def pre_main(self) -> None:
        # root has to create the permanent host store. once root is
        # dropped, this module can't create it in a root owned permanent dir
        self.db.init_host_profile_store()
        utils.drop_root_privs_permanently()
        self.wait_for_dbs()
        # the following method only works when running on an interface
        if gw_ips := self.gateway.get_gateway_ip_if_interface():
            for interface, gw_ip in gw_ips.items():
                self.db.set_default_gateway("IP", gw_ip, interface)

            # whether we found the gw ip using dhcp in profiler
            # or using ip route here (self.get_gateway_ip())
            # now that it's found, get and store the mac addr of it
            if gw_macs := self.gateway.get_gateway_mac(gw_ips):
                for interface, gw_mac in gw_macs.items():
                    self.db.set_default_gateway("MAC", gw_mac, interface)

    def handle_new_ip(self, ip: str):
        try:
            # make sure its a valid ip
            ip_addr = ipaddress.ip_address(ip)
        except ValueError:
            # not a valid ip skip
            return

        if ip_addr.is_multicast:
            return

        # Do we have cached info about this ip in redis?
        # If yes, load it
        geocountry = self.db.get_ip_info(ip, "geocountry")
        if not geocountry:
            self.get_geocountry(ip)

        # only update the ASN for this IP if more than 1 month
        # passed since last ASN update on this IP
        asn = self.db.get_asn_info(ip)
        if self.asn.should_update_asn(asn):
            self.asn.get_asn(ip)

        if not self.db.get_rdns_info(ip):
            self.rdns.get_rdns(ip)

    async def main(self):
        if msg := self.get_msg("new_MAC"):
            data = json.loads(msg["data"])
            mac_addr: str = data["MAC"]
            profileid: str = data["profileid"]

            self.create_task(self.handle_new_mac_async, mac_addr, profileid)

        if msg := self.get_msg("new_dns"):
            msg = json.loads(msg["data"])
            flow = self.classifier.convert_to_flow_obj(msg["flow"])
            self.register_private_dns_server(flow)
            if domain := flow.query:
                self.create_task(self.handle_new_dns_async, domain)

        if msg := self.get_msg("new_ip"):
            ip = utils.get_msg_payload(msg)
            self.create_task(self.handle_new_ip_async, ip)

        if msg := self.get_msg("check_jarm_hash"):
            # example of a msg
            # {'attacker_type': 'ip',
            # 'profileid': 'profile_192.168.1.9', 'twid': 'timewindow1',
            # 'flow': {'starttime': 1700828217.923668,
            # 'uid': 'CuTCcR1Bbp9Je7LVqa', 'saddr': '192.168.1.9',
            # 'daddr': '45.33.32.156', 'dur': 0.20363497734069824,
            # 'proto': 'tcp', 'appproto': '', 'sport': 50824, 'dport': 443,
            # 'spkts': 1, 'dpkts': 1, 'sbytes': 0, 'dbytes': 0,
            # 'smac': 'c4:23:60:3d:fd:d3', 'dmac': '50:78:b3:b0:08:ec',
            # 'state': 'REJ', 'history': 'Sr', 'type_': 'conn', 'dir_': '->'},
            # 'uid': 'CuTCcR1Bbp9Je7LVqa'}

            msg: dict = json.loads(msg["data"])
            flow: dict = msg["flow"]
            if msg["attacker_type"] == "ip":
                jarm_hash: str = self.JARM.JARM_hash(
                    flow["daddr"], flow["dport"]
                )

                if self.db.is_blacklisted_jarm(jarm_hash):
                    self.set_evidence_malicious_jarm_hash(flow, msg["twid"])

        if self.host_identity_archiver.claim_due_batch():
            self.create_task(
                self.host_identity_archiver.archive_batch_async,
                self.run_host_archive_step,
            )
