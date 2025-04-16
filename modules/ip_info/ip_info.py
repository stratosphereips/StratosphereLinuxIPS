# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import platform
from asyncio import Task
from typing import (
    Union,
    Optional,
)
from uuid import uuid4
import datetime
import maxminddb
import ipaddress
import whois
import socket
import requests
import json
from contextlib import redirect_stdout, redirect_stderr
import subprocess
import re
import time
import asyncio
import multiprocessing
from functools import lru_cache


from modules.ip_info.jarm import JARM
from slips_files.common.flow_classifier import FlowClassifier
from slips_files.core.helpers.whitelist.whitelist import Whitelist
from .asn_info import ASN
from slips_files.common.abstracts.async_module import AsyncModule
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


class IPInfo(AsyncModule):
    # Name: short name of the module. Do not use spaces
    name = "IP Info"
    description = "Get different info about an IP/MAC address"
    authors = ["Alya Gomaa", "Sebastian Garcia"]

    def init(self):
        """This will be called when initializing this module"""
        self.pending_mac_queries = multiprocessing.Queue()
        self.asn = ASN(self.db)
        self.JARM = JARM()
        self.classifier = FlowClassifier()
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
        self.whitelist = Whitelist(self.logger, self.db)
        self.is_running_non_stop: bool = self.db.is_running_non_stop()
        self.valid_tlds = whois.validTlds()

    async def open_dbs(self):
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
        self.reading_mac_db_task: Task = self.create_task(self.read_mac_db)

    async def read_mac_db(self):
        """
        waits 10 mins for the update manager to download the mac db and
        opens it for reading. retries opening every 3s
        """
        trials = 0
        while True:
            if trials >= 60:
                # that's 10 mins of waiting for the macdb (600s)
                # dont wait forever
                return

            try:
                self.mac_db = open("databases/macaddress-db.json", "r")
                return True
            except OSError:
                # update manager hasn't downloaded it yet
                try:
                    time.sleep(10)
                    trials += 1
                except KeyboardInterrupt:
                    return False

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

    # RDNS functions
    def get_ip_family(self, ip):
        """
        returns the family of the IP, AF_INET or AF_INET6
        :param ip: str
        """
        return socket.AF_INET6 if ":" in ip else socket.AF_INET

    def get_rdns(self, ip: str) -> dict:
        """
        get reverse DNS of an ip
        returns RDNS of the given ip or False if not found
        :param ip: str
        """
        data = {}
        try:
            # works with both ipv4 and ipv6
            reverse_dns: str = socket.gethostbyaddr(ip)[0]
            # if there's no reverse dns record for this ip, reverse_dns will be an ip.
            try:
                # check if the reverse_dns value is a valid IP address
                socket.inet_pton(self.get_ip_family(reverse_dns), reverse_dns)
                # reverse_dns is an ip. there's no reverse dns. don't store
                return False
            except socket.error:
                # reverse_dns is a valid hostname, store it
                data["reverse_dns"] = reverse_dns
                self.db.set_ip_info(ip, data)
        except (socket.gaierror, socket.herror, OSError):
            # not an ip or multicast, can't get the reverse dns record of it
            return False
        return data

    # MAC functions
    def get_vendor_online(self, mac_addr):
        # couldn't find vendor using offline db, search online

        # If there is no match in the online database,
        # you will receive an empty response with a status code
        # of HTTP/1.1 204 No Content
        url = "https://api.macvendors.com"
        try:
            response = requests.get(f"{url}/{mac_addr}", timeout=2)
            if response.status_code == 200:
                # this online db returns results in an array like str [{results}],
                # make it json
                if vendor := response.text:
                    return vendor
            return False
        except (
            requests.exceptions.ReadTimeout,
            requests.exceptions.ConnectionError,
            json.decoder.JSONDecodeError,
        ):
            return False

    @staticmethod
    @lru_cache(maxsize=700)
    def _get_vendor_offline_cached(oui, mac_db_content):
        """
        Static helper to perform the actual lookup based on OUI and cached content.
        """
        for line in mac_db_content:
            if oui in line:
                line = json.loads(line)
                return line["vendorName"]
        return False

    def get_vendor_offline(self, mac_addr, profileid):
        """
        Gets vendor from Slips' offline database at databases/macaddr-db.json.
        """
        if not hasattr(self, "mac_db") or self.mac_db is None:
            # when update manager is done updating the mac db, we should ask
            # the db for all these pending queries
            self.pending_mac_queries.put((mac_addr, profileid))
            return False

        oui = mac_addr[:8].upper()
        self.mac_db.seek(0)
        mac_db_content = self.mac_db.readlines()

        return self._get_vendor_offline_cached(oui, tuple(mac_db_content))

    def get_vendor(self, mac_addr: str, profileid: str) -> dict:
        """
        Returns the vendor info of a MAC address and stores it in slips db
        either from an offline or an online database
        """
        if not utils.is_ignored_ip(profileid.split("_")[-1]):
            # dont try to get the MAC vendor of private profiles, the MAC
            # here is irrelevant (might be the gateway's)
            return False

        if (
            "ff:ff:ff:ff:ff:ff" in mac_addr.lower()
            or "00:00:00:00:00:00" in mac_addr.lower()
        ):
            return False

        # don't look for the vendor again if we already have it for this
        # profileid
        if self.db.get_mac_vendor_from_profile(profileid):
            return True

        mac_info: dict = {"MAC": mac_addr}

        if vendor := self.get_vendor_offline(mac_addr, profileid):
            mac_info["Vendor"] = vendor
            self.db.set_mac_vendor_to_profile(profileid, mac_addr, vendor)
        elif vendor := self.get_vendor_online(mac_addr):
            mac_info["Vendor"] = vendor
            self.db.set_mac_vendor_to_profile(profileid, mac_addr, vendor)
        else:
            mac_info["Vendor"] = "Unknown"

        return mac_info

    def has_cached_info(self, domain) -> bool:
        cached_data = self.db.get_domain_data(domain)
        if cached_data and ("Age" in cached_data and "Org" in cached_data):
            # we already have info about this domain
            return True
        return False

    def is_valid_domain(self, domain: str) -> bool:
        if domain.endswith(".arpa") or domain.endswith(".local"):
            return False

        domain_tld: str = self.whitelist.domain_analyzer.get_tld(domain)
        if domain_tld not in self.valid_tlds:
            return False
        return True

    def query_whois(self, domain: str):
        try:
            with (
                open("/dev/null", "w") as f,
                redirect_stdout(f),
                redirect_stderr(f),
            ):
                return whois.query(domain, timeout=2.0)
        except Exception:
            return None

    def get_domain_info(self, domain):
        """
        Gets the age and org of a domain using whois
        """
        if not self.is_valid_domain(domain) or self.has_cached_info(domain):
            return

        res = self.query_whois(domain)
        if res:
            if res.creation_date:
                age = utils.get_time_diff(
                    res.creation_date,
                    datetime.datetime.now(),
                    return_type="days",
                )
                self.db.set_info_for_domains(domain, {"Age": age})
            if hasattr(res, "registrant") and res.registrant:
                self.db.set_info_for_domains(domain, {"Org": res.registrant})
                return

        # usually support.microsoft.com doesnt have a registrant,
        # but microsoft.com does
        sld = utils.extract_hostname(domain)
        sld_res = self.query_whois(sld)
        if sld_res and hasattr(res, "registrant") and sld_res.registrant:
            self.db.set_info_for_domains(domain, {"Org": sld_res.registrant})

    async def shutdown_gracefully(self):
        if hasattr(self, "asn_db"):
            self.asn_db.close()
        if hasattr(self, "country_db"):
            self.country_db.close()
        if hasattr(self, "mac_db"):
            self.mac_db.close()
        await self.reading_mac_db_task

    # GW
    def get_gateway_ip_if_interface(self):
        """
        Slips tries different ways to get the ip of the default gateway
        this method tries to get the default gateway IP address using ip route
        only works when running on an interface
        """
        if not self.is_running_non_stop:
            # only works if running on an interface
            return False

        gw_ip = False
        if platform.system() == "Darwin":
            route_default_result = subprocess.check_output(
                ["route", "get", "default"]
            ).decode()
            try:
                gw_ip = re.search(
                    r"\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}",
                    route_default_result,
                ).group(0)
            except AttributeError:
                pass

        elif platform.system() == "Linux":
            route_default_result = re.findall(
                r"([\w.][\w.]*'?\w?)",
                subprocess.check_output(["ip", "route"]).decode(),
            )
            gw_ip = route_default_result[2]
        return gw_ip

    def get_gateway_mac(self, gw_ip: str) -> Optional[str]:
        """
        Given the gw_ip, this function tries to get the MAC
         from arp.log or from arp tables
        """
        # we keep a cache of the macs and their IPs
        # In case of a zeek dir or a pcap,
        # check if we have the mac of this ip already saved in the db.
        if gw_mac := self.db.get_mac_addr_from_profile(f"profile_{gw_ip}"):
            gw_mac: Union[str, None]
            self.db.set_default_gateway("MAC", gw_mac)
            return gw_mac

        if not self.is_running_non_stop:
            # running on pcap or a given zeek file/dir
            # no MAC in arp.log (in the db) and can't use arp tables,
            # so it's up to the db.is_gw_mac() function to determine the gw mac
            # if it's seen associated with a public IP
            return

        # Obtain the MAC address by using the hosts ARP table
        # First, try the ip command
        try:
            ip_output = subprocess.run(
                ["ip", "neigh", "show", gw_ip],
                capture_output=True,
                check=True,
                text=True,
            ).stdout
            gw_mac = ip_output.split()[-2]
            self.db.set_default_gateway("MAC", gw_mac)
            return gw_mac
        except (subprocess.CalledProcessError, FileNotFoundError):
            # If the ip command doesn't exist or has failed, try using the
            # arp command
            try:
                arp_output = subprocess.run(
                    ["arp", "-an"], capture_output=True, check=True, text=True
                ).stdout
                for line in arp_output.split("\n"):
                    fields = line.split()
                    gw_ip_from_arp_cmd = fields[1].strip("()")
                    # Match the gw_ip in the output with the one given to
                    # this function
                    if len(fields) >= 2 and gw_ip_from_arp_cmd == gw_ip:
                        gw_mac = fields[-4]
                        self.db.set_default_gateway("MAC", gw_mac)
                        return gw_mac
            except (subprocess.CalledProcessError, FileNotFoundError):
                # Could not find the MAC address of gw_ip
                return

        return gw_mac

    def check_if_we_have_pending_offline_mac_queries(self):
        """
        Checks if we have pending MAC queries to get the vendor of.
        These pending queries are MACs that should bee looked up in the
        local downloaded mac db, but aren't because update manager hasn't
        downloaded it yet for whatever reason.
        queries are taken from the pending_mac_queries queue.
        """
        if not hasattr(self, "mac_db"):
            return

        if self.pending_mac_queries.empty():
            return

        while True:
            try:
                mac, profileid = self.pending_mac_queries.get(timeout=0.5)
                if vendor := self.get_vendor_offline(mac, profileid):
                    self.db.set_mac_vendor_to_profile(profileid, mac, vendor)
            except Exception:
                # queue is empty
                return

    def wait_for_dbs(self):
        """
        wait for update manager to finish updating the mac db and open the
        rest of dbs before starting this module
        """
        # this is the loop that controls tasks running on open_dbs
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        # run open_dbs in the background so we don't have
        # to wait for update manager to finish updating the mac db to start this module
        loop.run_until_complete(self.open_dbs())

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

    def pre_main(self):
        utils.drop_root_privs()
        self.wait_for_dbs()
        # the following method only works when running on an interface
        if ip := self.get_gateway_ip_if_interface():
            self.db.set_default_gateway("IP", ip)

            # whether we found the gw ip using dhcp in profiler
            # or using ip route using self.get_gateway_ip()
            # now that it's found, get and store the mac addr of it
            self.get_gateway_mac(ip)

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
        cached_ip_info = self.db.get_ip_info(ip)
        if not cached_ip_info:
            cached_ip_info = {}

        # Get the geocountry
        if cached_ip_info == {} or "geocountry" not in cached_ip_info:
            self.get_geocountry(ip)

        # only update the ASN for this IP if more than 1 month
        # passed since last ASN update on this IP
        if self.asn.should_update_asn(cached_ip_info):
            self.asn.get_asn(ip, cached_ip_info)

        self.get_rdns(ip)

    async def main(self):
        if msg := self.get_msg("new_MAC"):
            data = json.loads(msg["data"])
            mac_addr: str = data["MAC"]
            profileid: str = data["profileid"]

            self.get_vendor(mac_addr, profileid)
            self.check_if_we_have_pending_offline_mac_queries()

        if msg := self.get_msg("new_dns"):
            msg = json.loads(msg["data"])
            flow = self.classifier.convert_to_flow_obj(msg["flow"])
            if domain := flow.query:
                self.get_domain_info(domain)

        if msg := self.get_msg("new_ip"):
            ip = msg["data"]
            self.handle_new_ip(ip)

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
