# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from typing import (
    Union,
    Optional,
    Dict,
    List,
)
from uuid import uuid4, getnode
import datetime
import maxminddb
import ipaddress
import whois
import socket
import requests
import json
from contextlib import redirect_stdout, redirect_stderr
import subprocess
import netifaces
import asyncio
import multiprocessing
import time
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache, partial


from modules.ip_info.jarm import JARM
from slips_files.common.flow_classifier import FlowClassifier
from slips_files.core.helpers.whitelist.whitelist import Whitelist
from .asn_info import ASN
from slips_files.common.abstracts.iasync_module import IAsyncModule
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


class IPInfo(IAsyncModule):
    # Name: short name of the module. Do not use spaces
    name = "ip_info"
    description = "Get different info about an IP/MAC address"
    authors = ["Alya Gomaa", "Sebastian Garcia"]

    def init(self):
        """This will be called when initializing this module"""
        # 30MBs max size of this queue to avoid growing forever in mem
        self.pending_mac_queries = multiprocessing.Queue(maxsize=30000000)
        self.lookup_executor = ThreadPoolExecutor(
            max_workers=4, thread_name_prefix="ip-info"
        )
        self.lookup_semaphore = asyncio.Semaphore(4)
        # to avoid repeated failed rdns and whois lookups. we wait 300s
        # before retries.
        self.negative_cache_ttl = 300
        self.failed_rdns_lookups = {}
        self.failed_whois_lookups = {}
        self.failed_mac_vendor_lookups = {}
        self.asn = ASN(self.db)
        self.JARM = JARM()
        self.classifier = FlowClassifier()
        self.whitelist = Whitelist(self.logger, self.db, self.bloom_filters)
        self.is_running_non_stop: bool = self.db.is_running_non_stop()
        self.valid_tlds = frozenset(whois.validTlds())
        self.domain_validity_cache = {}
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
        self.create_task(self.read_mac_db)

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
                self.mac_vendor_index = self._load_mac_vendor_index(
                    "databases/macaddress-db.json"
                )
                return True
            except OSError:
                # update manager hasn't downloaded it yet
                try:
                    await asyncio.sleep(10)
                    trials += 1
                except KeyboardInterrupt:
                    return False

    @staticmethod
    def _load_mac_vendor_index(db_path: str) -> dict[str, str]:
        """
        Load the MAC vendor database into a dictionary keyed by OUI.

        :param db_path: Relative path to the JSON lines MAC vendor database.
        :return: Mapping of OUI prefixes to vendor names.
        """
        vendor_index = {}
        with open(db_path, "r") as mac_db:
            for line in mac_db:
                try:
                    mac_entry = json.loads(line)
                except json.decoder.JSONDecodeError:
                    continue

                assignment = mac_entry.get("macPrefix")
                vendor_name = mac_entry.get("vendorName")
                if assignment and vendor_name:
                    vendor_index[assignment.upper()] = vendor_name

        return vendor_index

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
        return self._get_ip_family_cached(ip)

    @staticmethod
    @lru_cache(maxsize=1024)
    def _get_ip_family_cached(ip: str):
        """
        Return the socket address family for an IP-like string.

        :param ip: IP address or IP-like string.
        :return: AF_INET6 when the value contains ':', otherwise AF_INET.
        """
        return socket.AF_INET6 if ":" in ip else socket.AF_INET

    def get_rdns(self, ip: str) -> dict:
        """
        get reverse DNS of an ip
        returns RDNS of the given ip or False if not found
        :param ip: str
        """
        data = {}
        if self._is_negative_cache_hit(self.failed_rdns_lookups, ip):
            return False
        try:
            # works with both ipv4 and ipv6
            reverse_dns: str = socket.gethostbyaddr(ip)[0]
            # if there's no reverse dns record for this ip, reverse_dns will be an ip.
            try:
                # check if the reverse_dns value is a valid IP address
                socket.inet_pton(self.get_ip_family(reverse_dns), reverse_dns)
                # reverse_dns is an ip. there's no reverse dns. don't store
                self._store_negative_cache(self.failed_rdns_lookups, ip)
                return False
            except socket.error:
                # reverse_dns is a valid hostname, store it
                data["reverse_dns"] = reverse_dns
                self.failed_rdns_lookups.pop(ip, None)
                self.db.set_ip_info(ip, data)
        except (socket.gaierror, socket.herror, OSError):
            # not an ip or multicast, can't get the reverse dns record of it
            self._store_negative_cache(self.failed_rdns_lookups, ip)
            return False
        return data

    async def get_rdns_async(self, ip: str) -> dict:
        """
        Resolve reverse DNS without blocking the event loop.

        :param ip: IP address to resolve.
        :return: Reverse DNS mapping or False if not found.
        """
        return await self.run_lookup(self.get_rdns, ip)

    # MAC functions
    def get_vendor_online(self, mac_addr):
        # couldn't find vendor using offline db, search online

        # If there is no match in the online database,
        # you will receive an empty response with a status code
        # of HTTP/1.1 204 No Content
        url = "https://api.macvendors.com"
        if self._is_negative_cache_hit(
            self.failed_mac_vendor_lookups, mac_addr
        ):
            return False
        try:
            response = requests.get(f"{url}/{mac_addr}", timeout=2)
            if response.status_code == 200:
                # this online db returns results in an array like str [{results}],
                # make it json
                if vendor := response.text:
                    self.failed_mac_vendor_lookups.pop(mac_addr, None)
                    return vendor
            self._store_negative_cache(
                self.failed_mac_vendor_lookups, mac_addr
            )
            return False
        except (
            requests.exceptions.ReadTimeout,
            requests.exceptions.ConnectionError,
            json.decoder.JSONDecodeError,
        ):
            self._store_negative_cache(
                self.failed_mac_vendor_lookups, mac_addr
            )
            return False

    def get_vendor_offline(self, mac_addr, profileid):
        """
        Gets vendor from Slips' offline database at databases/macaddr-db.json.
        """
        if (
            not hasattr(self, "mac_vendor_index")
            or self.mac_vendor_index is None
        ):
            # when update manager is done updating the mac db, we should ask
            # the db for all these pending queries
            self.pending_mac_queries.put((mac_addr, profileid))
            return False

        oui = mac_addr[:8].upper()
        return self.mac_vendor_index.get(oui, False)

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

    async def get_vendor_async(self, mac_addr: str, profileid: str) -> dict:
        """
        Resolve MAC vendor information without blocking the event loop.

        :param mac_addr: MAC address to enrich.
        :param profileid: Profile identifier associated with the MAC.
        :return: Vendor information dict or False.
        """
        if not utils.is_ignored_ip(profileid.split("_")[-1]):
            return False

        if (
            "ff:ff:ff:ff:ff:ff" in mac_addr.lower()
            or "00:00:00:00:00:00" in mac_addr.lower()
        ):
            return False

        if self.db.get_mac_vendor_from_profile(profileid):
            return True

        mac_info: dict = {"MAC": mac_addr}

        if vendor := self.get_vendor_offline(mac_addr, profileid):
            mac_info["Vendor"] = vendor
            self.db.set_mac_vendor_to_profile(profileid, mac_addr, vendor)
        elif vendor := await self.run_lookup(self.get_vendor_online, mac_addr):
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
        cached_result = self.domain_validity_cache.get(domain)
        if cached_result is not None:
            return cached_result

        if domain.endswith(".arpa") or domain.endswith(".local"):
            self.domain_validity_cache[domain] = False
            return False

        domain_tld: str = self.whitelist.domain_analyzer.get_tld(domain)
        if domain_tld not in self.valid_tlds:
            self.domain_validity_cache[domain] = False
            return False
        self.domain_validity_cache[domain] = True
        return True

    def query_whois(self, domain: str):
        if self._is_negative_cache_hit(self.failed_whois_lookups, domain):
            return None
        try:
            with (
                open("/dev/null", "w") as f,
                redirect_stdout(f),
                redirect_stderr(f),
            ):
                result = whois.query(domain, timeout=2.0)
                if result:
                    self.failed_whois_lookups.pop(domain, None)
                    return result
                self._store_negative_cache(self.failed_whois_lookups, domain)
                return None
        except Exception:
            self._store_negative_cache(self.failed_whois_lookups, domain)
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

    async def get_domain_info_async(self, domain: str):
        """
        Get domain age and organization without blocking the event loop.

        :param domain: Domain to enrich.
        :return: None.
        """
        if not self.is_valid_domain(domain) or self.has_cached_info(domain):
            return

        res = await self.run_lookup(self.query_whois, domain)
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

        sld = utils.extract_hostname(domain)
        sld_res = await self.run_lookup(self.query_whois, sld)
        if sld_res and hasattr(res, "registrant") and sld_res.registrant:
            self.db.set_info_for_domains(domain, {"Org": sld_res.registrant})

    async def shutdown_gracefully(self):
        if hasattr(self, "asn_db"):
            self.asn_db.close()
        if hasattr(self, "country_db"):
            self.country_db.close()
        if hasattr(self, "pending_mac_queries"):
            self.pending_mac_queries.close()
            self.pending_mac_queries.join_thread()
        if hasattr(self, "lookup_executor"):
            self.lookup_executor.shutdown(wait=True, cancel_futures=True)
        if hasattr(self, "domain_validity_cache"):
            self.domain_validity_cache.clear()
        self._get_ip_family_cached.cache_clear()

    # GW
    @staticmethod
    def get_default_gateway(self) -> str:
        gws = netifaces.gateways()
        default = gws.get("default", {})
        return default.get(netifaces.AF_INET, (None,))[0]

    def get_gateway_ip_if_interface(self) -> Dict[str, str] | None:
        """
        returns the gateway ip of the given interface if running on an
        interface.
        and returns own ip if running as an AP (aka the given interface
        is NATing/bridging traffic to another interface).
        """
        if not self.is_running_non_stop:
            # only works if running on an interface
            return

        interfaces: List[str] = utils.get_all_interfaces(self.args)

        gw_ips = {}
        for interface in interfaces:
            try:
                gw_ip = utils.get_gateway_for_iface(interface)
                gw_ips.update({interface: gw_ip})
            except KeyError:
                pass
        return gw_ips

    @staticmethod
    def get_own_mac() -> str:
        # get the MAC address as a hex string
        mac_num = getnode()
        # format it as usual MAC address format xx:xx:xx:xx:xx:xx
        mac = ":".join(
            f"{(mac_num >> ele) & 0xff:02x}" for ele in range(40, -1, -8)
        )
        return mac

    def _get_wifi_interface_if_ap(self) -> str | None:
        ap_interfaces: str = self.db.get_wifi_interface()
        try:
            # we're now sure that we're running in AP mode
            wifi_interface = ap_interfaces["wifi_interface"]
        except KeyError:
            wifi_interface = None
        return wifi_interface

    def _get_mac_using_ip_neigh(self, gw_ip) -> str | None:
        try:
            if not ipaddress.ip_address(gw_ip):
                return

            ip_output = subprocess.run(
                ["ip", "neigh", "show", gw_ip],
                capture_output=True,
                check=True,
                text=True,
            ).stdout
            mac = ip_output.split()[-2]
            return mac
        except (subprocess.CalledProcessError, IndexError, FileNotFoundError):
            return

    def _get_mac_using_arp_cache(self, gw_ip) -> str | None:
        try:
            gw_mac = utils.get_mac_for_ip_using_cache(gw_ip)
            return gw_mac
        except (subprocess.CalledProcessError, IndexError):
            # Could not find the MAC address of gw_ip
            return

    def get_gateway_mac(self, gw_ips: Dict[str, str]) -> Optional[str]:
        """
        Given the gw_ips, this function tries to get the MAC
         from arp.log, using ip neigh or from arp tables
        """
        wifi_interface: str | None = self._get_wifi_interface_if_ap()

        gw_macs = {}
        for interface, gw_ip in gw_ips.items():
            # we keep a cache of the macs and their IPs
            # In case of a zeek dir or a pcap,
            # check if we have the mac of this ip already saved in the db.
            if gw_mac := self.db.get_mac_addr_from_profile(f"profile_{gw_ip}"):
                gw_mac: Union[str, None]
                gw_macs[interface] = gw_mac
                continue

            if not self.is_running_non_stop:
                # ok now we are running on pcap or a given zeek file/dir
                # and we have no MAC in arp.log (in the db) and can't use arp
                # tables, so it's up to the db.is_gw_mac() function to
                # determine the gw mac if it's seen associated with a
                # public IP
                continue

            if interface == wifi_interface:
                # this interface is the wifi interface of the AP
                if own_mac := self.get_own_mac():
                    gw_macs[interface] = own_mac
                    continue

            if gw_mac := self._get_mac_using_ip_neigh(gw_ip):
                gw_macs[interface] = gw_mac
                continue

            if gw_mac := self._get_mac_using_arp_cache(gw_ip):
                gw_macs[interface] = gw_mac
                continue

        if gw_macs:
            return gw_macs

    def check_if_we_have_pending_offline_mac_queries(self):
        """
        Checks if we have pending MAC queries to get the vendor of.
        These pending queries are MACs that should bee looked up in the
        local downloaded mac db, but aren't because update manager hasn't
        downloaded it yet for whatever reason.
        queries are taken from the pending_mac_queries queue.
        """
        if not hasattr(self, "mac_vendor_index"):
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

    def _is_negative_cache_hit(self, cache: dict, key: str) -> bool:
        """
        Check whether a negative cache entry is still valid.

        :param cache: Cache mapping keys to monotonic timestamps.
        :param key: Cache key to evaluate.
        :return: True if the negative cache entry is active.
        """
        timestamp = cache.get(key)
        if timestamp is None:
            return False

        if (time.monotonic() - timestamp) > self.negative_cache_ttl:
            cache.pop(key, None)
            return False

        return True

    def _store_negative_cache(self, cache: dict, key: str):
        """
        Store a negative cache entry.

        :param cache: Cache mapping keys to monotonic timestamps.
        :param key: Cache key to store.
        :return: None.
        """
        cache[key] = time.monotonic()

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

        geocountry = self.db.get_ip_info(ip, "geocountry")
        if not geocountry:
            self.get_geocountry(ip)

        asn = self.db.get_asn_info(ip)
        if self.asn.should_update_asn(asn):
            await self.asn.get_asn_async(ip, self.run_lookup)

        if not self.db.get_rdns_info(ip):
            await self.get_rdns_async(ip)

    async def handle_new_mac_async(self, mac_addr: str, profileid: str):
        """
        Enrich a newly seen MAC without blocking the event loop.

        :param mac_addr: MAC address to enrich.
        :param profileid: Profile associated with the MAC.
        :return: None.
        """
        await self.get_vendor_async(mac_addr, profileid)
        self.check_if_we_have_pending_offline_mac_queries()

    async def handle_new_dns_async(self, domain: str):
        """
        Enrich a newly seen domain without blocking the event loop.

        :param domain: Domain to enrich.
        :return: None.
        """
        await self.get_domain_info_async(domain)

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
        utils.drop_root_privs_permanently()
        self.wait_for_dbs()
        # the following method only works when running on an interface
        if gw_ips := self.get_gateway_ip_if_interface():
            for interface, gw_ip in gw_ips.items():
                self.db.set_default_gateway("IP", gw_ip, interface)

            # whether we found the gw ip using dhcp in profiler
            # or using ip route here (self.get_gateway_ip())
            # now that it's found, get and store the mac addr of it
            if gw_macs := self.get_gateway_mac(gw_ips):
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
            self.get_rdns(ip)

    async def main(self):
        if msg := self.get_msg("new_MAC"):
            data = json.loads(msg["data"])
            mac_addr: str = data["MAC"]
            profileid: str = data["profileid"]

            self.create_task(self.handle_new_mac_async, mac_addr, profileid)

        if msg := self.get_msg("new_dns"):
            msg = json.loads(msg["data"])
            flow = self.classifier.convert_to_flow_obj(msg["flow"])
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
