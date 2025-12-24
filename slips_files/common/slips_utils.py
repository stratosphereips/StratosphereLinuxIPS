# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import base64
import binascii
import hashlib
from datetime import datetime, timedelta
from multiprocessing import Process
from re import findall
from threading import Thread
import netifaces
from uuid import UUID
import tldextract
import validators
from git import Repo
import socket
import requests
import json
import platform
import os
import sys
import ipaddress
import aid_hash
from typing import Any, Optional, Union, List
from ipaddress import IPv4Network, IPv6Network, IPv4Address, IPv6Address
from dataclasses import is_dataclass, asdict
from enum import Enum

from modules.network_discovery.icmp_scan_ports import ICMP_SCAN_PORTS
from slips_files.core.supported_logfiles import SUPPORTED_LOGFILES
from slips_files.core.structures.flow_attributes import (
    State,
    Role,
    Protocol,
)


IS_IN_A_DOCKER_CONTAINER = os.environ.get("IS_IN_A_DOCKER_CONTAINER", False)
BROADCAST_ADDR = "255.255.255.255"


class Utils(object):
    name = "utils"
    description = "Common functions used by different modules of slips."
    authors = ["Alya Gomaa"]

    def __init__(self):
        self.home_network_ranges_str = (
            "192.168.0.0/16",
            "172.16.0.0/12",
            "10.0.0.0/8",
        )
        # IPv4Network objs
        self.home_network_ranges = list(
            map(ipaddress.ip_network, self.home_network_ranges_str)
        )
        self.supported_orgs = (
            "google",
            "microsoft",
            "apple",
            "facebook",
            "twitter",
        )
        self.home_networks = ("192.168.0.0", "172.16.0.0", "10.0.0.0")
        self.threat_levels = {
            "info": 0,
            "low": 0.2,
            "medium": 0.5,
            "high": 0.8,
            "critical": 1,
        }
        # why are we not using /var/lock? bc we need it to be r/w/x by
        # everyone
        self.slips_locks_dir = "/tmp/slips"
        self.time_formats = (
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f%z",
            "%Y/%m/%d %H:%M:%S.%f%z",
            "%Y/%m/%d %H:%M:%S.%f",
            "%Y/%m/%d %H:%M:%S",
            "%Y-%m-%d %H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y/%m/%d-%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
        )
        self.time_format_cache = {}
        # this format will be used across all modules and logfiles of slips
        # its timezone aware
        self.alerts_format = "%Y/%m/%d %H:%M:%S.%f%z"
        self.local_tz = self.get_local_timezone()
        self.aid = aid_hash.AID()
        self.used_inetrface = None

    def generate_uid(self):
        """Generates a UID similar to what Zeek uses."""
        return base64.b64encode(binascii.b2a_hex(os.urandom(9))).decode(
            "utf-8"
        )

    def is_iso_format(self, date_time: str) -> bool:
        try:
            datetime.fromisoformat(date_time)
            return True
        except (ValueError, TypeError):
            return False

    def extract_hostname(self, url: str) -> str:
        """
        extracts the parent domain from the given domain/url
        """
        parsed_url = tldextract.extract(url)
        return f"{parsed_url.domain}.{parsed_url.suffix}"

    def is_localhost(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_loopback
        except ValueError:
            # Invalid IP address
            return False

    def get_cidr_of_private_ip(self, ip):
        """
        returns the cidr/range of the given private ip
        :param ip: should be a private ipv4
        """
        if validators.ipv4(ip):
            first_octet = ip.split(".")[0]
            # see if the first octet of the given ip matches any of the
            # home network ranges
            for network_range in self.home_network_ranges_str:
                if first_octet in network_range:
                    return network_range

    def threat_level_to_string(self, threat_level: float) -> str:
        for str_lvl, int_value in self.threat_levels.items():
            if threat_level <= int_value:
                return str_lvl

    def is_valid_threat_level(self, threat_level):
        return threat_level in self.threat_levels

    @staticmethod
    def get_original_conn_flow(altflow, db) -> Optional[dict]:
        """Returns the original conn.log of the given altflow"""
        original_conn_flow = db.get_flow(altflow.uid)
        original_flow_uid = next(iter(original_conn_flow))
        if original_conn_flow[original_flow_uid]:
            return json.loads(original_conn_flow[original_flow_uid])

    @staticmethod
    def is_ip_in_client_ips(ip_to_check: str, client_ips: List) -> bool:
        ip = ipaddress.ip_address(ip_to_check)
        for entry in client_ips:
            if isinstance(entry, ipaddress.IPv4Network) or isinstance(
                entry, ipaddress.IPv6Network
            ):
                if ip in entry:
                    return True

            elif isinstance(entry, ipaddress.IPv4Address) or isinstance(
                entry, ipaddress.IPv6Address
            ):
                if ip == entry:
                    return True
        return False

    @staticmethod
    def sanitize(input_string):
        """
        Sanitize strings taken from the user
        """
        characters_to_remove = set(";`&|$\n()")
        input_string = input_string.strip()
        remove_characters = str.maketrans(
            "", "", "".join(characters_to_remove)
        )
        sanitized_string = input_string.translate(remove_characters)

        return sanitized_string

    def to_dict(self, obj):
        """
        Converts an Evidence object to a dictionary (aka json serializable)
        :param obj: object of any type.
        """
        if is_dataclass(obj):
            # run this function on each value of the given dataclass
            return {k: self.to_dict(v) for k, v in asdict(obj).items()}

        if isinstance(obj, Enum):
            return obj.name

        if isinstance(obj, list):
            return [self.to_dict(item) for item in obj]

        if isinstance(obj, dict):
            return {k: self.to_dict(v) for k, v in obj.items()}

        return obj

    def get_interface_of_ip(self, ip, db, args) -> str:
        """
        Gets the interface this IP is attacking on
        return s None if slips isnt running on an interface
        """
        if args.interface:
            return args.interface

        if args.access_point:
            # we have 2 interfaces, in which interface is the ip_to_block?
            for _type, interface in db.get_ap_info().items():
                # _type can be 'wifi_interface' or "ethernet_interface"
                local_net: str = db.get_local_network(interface)
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj in ipaddress.IPv4Network(local_net):
                    return interface

    def get_gateway_for_iface(self, iface: str) -> Optional[str]:
        """returns the default gateway for the given interface"""
        gws = netifaces.gateways()
        for family in (netifaces.AF_INET, netifaces.AF_INET6):
            if "default" in gws and gws["default"][family]:
                gw, gw_iface = gws["default"][family]
                if gw_iface == iface:
                    return gw
        return None

    def is_valid_uuid4(self, uuid_string: str) -> bool:
        """Validate that the given str in UUID4"""
        try:
            UUID(uuid_string, version=4)
            return True
        except ValueError:
            return False

    def is_valid_domain(self, domain: str) -> bool:
        extracted = tldextract.extract(domain)
        return bool(extracted.domain) and bool(extracted.suffix)

    def detect_ioc_type(self, data) -> str:
        """
        Detects the type of incoming data:
        ipv4, ipv6, domain, ip range, asn, md5, etc
        """

        objs_map = {
            IPv4Network: "ip",
            IPv6Network: "ip",
            IPv4Address: "ip_range",
            IPv6Address: "ip_range",
        }

        for obj, obj_type in objs_map.items():
            if isinstance(data, obj):
                return obj_type

        data = data.strip()
        try:
            ipaddress.ip_address(data)
            return "ip"
        except (ipaddress.AddressValueError, ValueError):
            pass

        try:
            ipaddress.ip_network(data)
            return "ip_range"
        except ValueError:
            pass

        if validators.md5(data):
            return "md5"

        if validators.url(data):
            return "url"

        if self.is_valid_domain(data):
            return "domain"

        if validators.sha256(data):
            return "sha256"

        if data.startswith("AS"):
            return "asn"

    def get_first_octet(self, ip):
        # the ranges stored are sorted by first octet
        if "." in ip:
            return ip.split(".")[0]
        elif ":" in ip:
            return ip.split(":")[0]
        else:
            # invalid ip
            return

    def are_scan_detection_modules_interested_in_this_ip(self, ip) -> bool:
        """
        Check if any of the scan detection modules (horizontal portscan,
        vertical portscan, icmp scan) are interested in this ip
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
        except (ipaddress.AddressValueError, ValueError):
            return False

        return not (
            ip_obj.is_multicast
            or ip_obj.is_link_local
            or ip_obj.is_loopback
            or ip_obj.is_reserved
        )

    def convert_str_to_state(self, state_as_str: str) -> State:
        if state_as_str == "Established":
            return State.EST
        elif state_as_str == "Not Established":
            return State.NOT_EST
        return State.NOT_EST

    def is_info_needed_by_the_icmp_scan_detector_module(
        self,
        role: Role,
        proto: Protocol,
        state: State,
        source_port: int | str,
    ) -> bool:
        try:
            source_port = int(source_port)
        except ValueError:
            return False

        return (
            role == Role.CLIENT
            and proto in (Protocol.ICMP, Protocol.ICMP6)
            and state == State.EST
            # these are the ports used for common icmp scans that slips
            # currently detects
            and source_port in ICMP_SCAN_PORTS
        )

    def calculate_confidence(self, pkts_sent):
        """
        calculates the evidence confidence based on the pkts sent
        """
        if pkts_sent > 10:
            confidence = 1
        elif pkts_sent == 0:
            return 0.3
        else:
            # Between threshold and 10 pkts compute a kind of linear grow
            confidence = pkts_sent / 10.0
        return confidence

    def drop_root_privs_temporarily(self) -> int:
        """returns the uid of the user that launched sudo"""
        if platform.system() != "Linux":
            return
        try:
            self.sudo_uid = int(os.getenv("SUDO_UID"))
            self.sudo_gid = int(os.getenv("SUDO_GID"))
        except (TypeError, ValueError):
            return  # Not running as root with sudo

        # Drop only effective privileges
        os.setegid(self.sudo_gid)
        os.seteuid(self.sudo_uid)
        return self.sudo_uid

    def regain_root_privs(self):
        os.seteuid(0)
        os.setegid(0)

    def drop_root_privs_permanently(self):
        """
        Drop root privileges if the module doesn't need them
        Shouldn't be called from __init__ because then, it affects the parent process too
        """

        if platform.system() != "Linux":
            return
        try:
            # Get the uid/gid of the user that launched sudo
            sudo_uid = int(os.getenv("SUDO_UID"))
            sudo_gid = int(os.getenv("SUDO_GID"))
        except TypeError:
            # env variables are not set, you're not root
            return
        # Change the current process’s real and effective uids and gids to that user
        # -1 means value is not changed.
        os.setresgid(sudo_gid, sudo_gid, -1)
        os.setresuid(sudo_uid, sudo_uid, -1)
        return

    def is_public_ip(self, ip_str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            return not (
                ip.is_private
                or ip.is_loopback
                or ip.is_reserved
                or ip.is_multicast
                or ip.is_link_local
            )
        except ValueError:
            return False  # invalid IP

    def is_ignored_zeek_log_file(self, filepath: str) -> bool:
        """
        Returns true if the given file ends with .log or .log.labeled and
        is in SUPPORTED_LOGFILES list
        :param filepath: a zeek log file
        """
        if not (
            filepath.endswith(".log") or filepath.endswith(".log.labeled")
        ):
            return True

        filename = os.path.basename(filepath)
        # remove all extensions from filename
        while "." in filename:
            filename = filename.rsplit(".", 1)[0]
        return filename not in SUPPORTED_LOGFILES

    def start_thread(self, thread: Thread, db):
        """
        A wrapper for threading.Thread().start()
        starts the given thread and keeps track of its TID in the db
        :param thread: the thread to start
        :param db: a DBManager obj to store the thread PID
        """
        thread.start()
        db.store_pid(thread.name, int(thread._native_id))

    def start_process(self, process: Process, db):
        """
        A wrapper for  multiprocessing.Process.start()
        starts the given proc and keeps track of its PID in the db
        :param process: the thread to start
        :param db: a DBManager obj to store the thread PID
        """
        process.start()
        db.store_pid(process.name, int(process.pid))

    def convert_ts_format(self, ts, required_format: str):
        """
        Detects and converts the given ts to the given format
        PS: it sets iso format datetime in the local timezone
        :param required_format: can be any format like '%Y/%m/%d %H:%M:%S.%f'
        or 'unixtimestamp', 'iso'
        """
        given_format = self.get_time_format(ts)
        if given_format == required_format:
            return ts

        if given_format == "datetimeobj":
            datetime_obj = ts
        else:
            datetime_obj = self.convert_to_datetime(ts)

        # convert to the req format
        if required_format == "iso":
            return datetime_obj.astimezone(tz=self.local_tz).isoformat()
        elif required_format == "unixtimestamp":
            return datetime_obj.timestamp()

        return datetime_obj.strftime(required_format)

    def get_local_timezone(self):
        """
        Returns the current user local timezone
        """
        now = datetime.now()
        local_now = now.astimezone()
        return local_now.tzinfo

    def convert_to_local_timezone(self, ts):
        """
        puts the given ts in the local timezone of the current user
        :parapm ts: any format
        """
        datetime_obj = self.convert_to_datetime(ts)
        return datetime_obj.astimezone(self.local_tz)

    def is_datetime_obj(self, ts) -> bool:
        """
        checks if the given ts is a datetime obj
        """
        try:
            return isinstance(ts, datetime)
        except Exception:
            return False

    def convert_to_datetime(self, ts):
        if self.is_datetime_obj(ts):
            return ts

        # 1. Unix Timestamp / Float check (Very Fast Path)
        # Most Zeek logs use this.
        try:
            return datetime.fromtimestamp(float(ts))
        except (ValueError, TypeError):
            pass

        # 2. String Parsing (Optimized)
        if isinstance(ts, str):
            return self._convert_str_to_datetime(ts)

        return None

        #
        # given_format = self.get_time_format(ts)
        # return datetime.strptime(ts, given_format)

    def _convert_str_to_datetime(self, ts: str):
        """
        Uses a signature (Length + Separators) to find the cached format
        without looping.
        this is not clean code, but we're having a latency issue and we're
        really need to optimize per flow operations, so don't refactor
        this for a "cleaner" version.
        """
        # Create a lightweight signature to differentiate formats
        # logic: almost all formats have a separator at index 4 and 10.
        # e.g., "2023-01-01 12..." -> 4='-', 10=' '
        # e.g., "2023/01/01-12..." -> 4='/', 10='-'
        try:
            # We use a tuple as dict key: (length, char_at_4, char_at_10)
            # This distinguishes YYYY-MM-DD vs YYYY/MM/DD and ' ' vs 'T'
            if len(ts) >= 11:
                signature = (len(ts), ts[4], ts[10])
            else:
                # Fallback for very short strings
                signature = len(ts)
        except IndexError:
            # String too short to have index 10
            signature = len(ts)

        # HIT: Use cached format
        if signature in self.time_format_cache:
            try:
                return datetime.strptime(ts, self.time_format_cache[signature])
            except ValueError:
                # Edge case: Signature collision (rare) or malformed data
                # Remove bad cache entry and fall through to slow loop
                del self.time_format_cache[signature]

        # MISS: Find format, Cache it, Return it (Very slow)
        found_format = self.get_and_cache_format(ts, signature)
        if found_format:
            return datetime.strptime(ts, found_format)

        return None

    def get_and_cache_format(self, time_str, signature) -> Optional[str]:
        """
        Slow path: Loops through all formats, finds the matching one,
        and saves it to the cache using the signature.
        """
        for time_format in self.time_formats:
            try:
                datetime.strptime(time_str, time_format)
                # Success! Save to cache.
                self.time_format_cache[signature] = time_format
                return time_format
            except ValueError:
                continue

        # Removed the print() statement as it ruins performance
        return None

    def is_unix_ts(self, time) -> bool:
        if isinstance(time, (int, float)):
            return True

        if isinstance(time, str):
            try:
                float(time)
                return True
            except ValueError:
                pass

        return False

    def get_time_format(self, time) -> Optional[str]:
        if self.is_datetime_obj(time):
            return "datetimeobj"

        if self.is_unix_ts(time):
            return "unixtimestamp"

        for time_format in self.time_formats:
            try:
                datetime.strptime(time, time_format)
                return time_format
            except ValueError:
                pass

        return False

    def to_delta(self, time_in_seconds):
        return timedelta(seconds=int(time_in_seconds))

    def get_human_readable_datetime(self, format=None) -> str:
        return utils.convert_ts_format(
            datetime.now(), format or self.alerts_format
        )

    def get_cidr_of_interface(self, interface: str) -> str | None:
        try:
            addrs = netifaces.ifaddresses(interface)
            ipv4_addrs = addrs.get(socket.AF_INET)

            if ipv4_addrs:
                for addr_info in ipv4_addrs:
                    ip = addr_info.get("addr")
                    netmask = addr_info.get("netmask")

                    if ip and netmask:
                        # Create an interface object from the IP and netmask
                        iface = ipaddress.ip_interface(f"{ip}/{netmask}")
                        network_cidr = str(iface.network)
                        return network_cidr
        except Exception:
            return

    def get_all_interfaces(self, args) -> List[str]:
        """
        returns a list of all interfaces slips is now monitoring
        :param args: slips args
        """
        if args.interface:
            return [args.interface]
        if args.access_point:
            return args.access_point.split(",")

        return ["default"]

    def get_mac_for_ip_using_cache(self, ip: str) -> str | None:
        """gets the mac of the given local ip using the local arp cache"""
        try:
            with open("/proc/net/arp") as f:
                next(f)  # skip header
                for line in f:
                    parts = line.split()
                    if parts[0] == ip:
                        return parts[3]
        except FileNotFoundError:
            pass
        return None

    def get_public_ip(self) -> str | None:
        """
        fetch public IP from ipinfo.io
        returns either an IPv4 or IPv6 address as a string, or None if unavailable
        """
        try:
            response = requests.get("http://ipinfo.io/json", timeout=5)
            if response.status_code == 200:
                data = json.loads(response.text)
                if "ip" in data:
                    return data["ip"]
        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.ChunkedEncodingError,
            requests.exceptions.ReadTimeout,
            json.decoder.JSONDecodeError,
        ):
            return None

    def get_own_ips(self, ret="Dict") -> dict[str, list[str]] | list[str]:
        """
        returns a dict of our private IPs from all interfaces and our public
        IPs. return a dict by default
        e.g. { "ipv4": [..], "ipv6": [..] }
        :kwarg ret: "Dict" or "List"
        and returns a list of all the ips combined if ret=List is given
        """
        if "-i" not in sys.argv:
            # this method is only valid when running on an interface
            return []

        ips = {"ipv4": [], "ipv6": []}

        for interface in netifaces.interfaces():
            try:
                addrs = netifaces.ifaddresses(interface)

                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        ips["ipv4"].append(addr["addr"])

                if netifaces.AF_INET6 in addrs:
                    for addr in addrs[netifaces.AF_INET6]:
                        # remove interface suffix
                        ip = addr["addr"].split("%")[0]
                        ips["ipv6"].append(ip)

            except Exception as e:
                print(f"Error processing interface {interface}: {e}")

        public_ip = self.get_public_ip()
        if public_ip:
            if validators.ipv4(public_ip):
                ips["ipv4"].append(public_ip)
            elif validators.ipv6(public_ip):
                ips["ipv6"].append(public_ip)

        if ret == "Dict":
            return ips
        elif ret == "List":
            return [ip for sublist in ips.values() for ip in sublist]

    def convert_to_mb(self, bytes):
        return int(bytes) / (10**6)

    def is_port_in_use(self, port: int) -> bool:
        """
        return True if the given port is used by another app
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if sock.connect_ex(("localhost", port)) != 0:
            # not used
            sock.close()
            return False

        sock.close()
        return True

    def is_private_ip(
        self, ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address, str]
    ) -> bool:
        ip_classes = {IPv4Network, IPv6Network, IPv4Address, IPv6Address}
        for class_ in ip_classes:
            if isinstance(ip, class_):
                return ip and ip.is_private

        if self.detect_ioc_type(ip) != "ip":
            return False
        # convert the given str ip to obj
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private

    def is_ignored_ip(self, ip: str) -> bool:
        """
        This function checks if an IP is a special list of IPs that
        should not be alerted for different reasons
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
        except (ipaddress.AddressValueError, ValueError):
            return True

        # Is the IP multicast, private? (including localhost)
        # The broadcast address 255.255.255.255 is reserved.
        return (
            ip_obj.is_multicast
            or self.is_private_ip(ip_obj)
            or ip_obj.is_link_local
            or ip_obj.is_loopback
            or ip_obj.is_reserved
        )

    def get_md5_hash(self, data: Any) -> str:
        return hashlib.md5(str(data).encode()).hexdigest()

    def get_sha256_hash_of_file_contents(self, filename: str):
        """
        Compute the sha256 hash of a file
        """
        # The size of each read from the file
        block_size = 65536
        # Create the hash object
        file_hash = hashlib.sha256()
        with open(filename, "rb") as f:
            file_bytes = f.read(block_size)
            while len(file_bytes) > 0:
                file_hash.update(file_bytes)
                # Read the next block from the file
                file_bytes = f.read(block_size)

        return file_hash.hexdigest()

    def get_sudo_according_to_env(self) -> str:
        """
        Check if running in host or in docker and sets sudo string accordingly.
        There's no sudo in docker so we need to execute all commands without it
        """
        # This env variable is defined in the Dockerfile
        running_in_docker = os.environ.get("IS_IN_A_DOCKER_CONTAINER", False)
        return "" if running_in_docker else "sudo"

    def is_msg_intended_for(self, message, channel):
        """
        Function to check
            1. If the given message is intended for this channel
            2. The msg has valid data
        """
        return (
            message
            and isinstance(message["data"], str)
            and message["channel"] == channel
        )

    def get_slips_version(self) -> str:
        version_file = "VERSION"
        with open(version_file, "r") as f:
            version = f.read()
        version = version.replace("\n", "")
        return version

    def change_logfiles_ownership(self, file: str, UID, GID):
        """
        if slips is running in docker, the owner of the alerts log files
        is always root
        this function changes it to the user ID and GID in slips.yaml to be
         able to
        rwx the files from outside of docker
        """
        if not (IS_IN_A_DOCKER_CONTAINER and UID and GID):
            # they should be anything other than 0
            return

        os.system(f"chown {UID}:{GID} {file}")

    def get_ip_identification_as_str(self, ip_identification: dict) -> str:
        id = ""
        if "DNS_resolution" in ip_identification:
            resolutions = ip_identification.get("DNS_resolution", [])
            for domain in resolutions:
                id += f"{domain}, "
            ip_identification.pop("DNS_resolution")

        for piece_of_info in ip_identification.values():
            if not piece_of_info:
                continue
            id += f"{piece_of_info}, "
        return id

    def get_branch_info(self):
        """
        Returns a tuple containing (commit,branch)
        """
        try:
            repo = Repo(".")
            # add branch name and commit
            branch = repo.active_branch.name
            commit = repo.active_branch.commit.hexsha
            return commit, branch
        except Exception:
            # when in docker, we copy the repo instead of clone it so there's no .git files
            # we can't add repo metadata
            return False

    def convert_ts_to_tz_aware(self, naive_datetime: datetime) -> datetime:
        """adds the current local tz (self.local_tz) to the given dt obj"""
        naive_datetime = utils.convert_to_datetime(naive_datetime)
        return naive_datetime.replace(tzinfo=self.local_tz)

    def is_aware(self, dt: datetime) -> bool:
        """
        checks if the given datetime object is timemzone aware or not
        """
        return dt.tzinfo is not None and dt.tzinfo.utcoffset(dt) is not None

    def get_time_diff(
        self, start_time: float, end_time: float, return_type="seconds"
    ) -> float:
        """
        Both times can be in any format
        returns difference in seconds
        :param return_type: can be seconds, minutes, hours or days
        """
        if start_time == float("-inf"):
            # a lot of time passed since -inf
            return 100000000000

        start_time = self.convert_to_datetime(start_time)
        end_time = self.convert_to_datetime(end_time)

        diff = str(end_time - start_time)
        # if there are days diff between the flows, diff will be something
        # like 1 day, 17:25:57.458395
        try:
            # calculate the days difference
            diff_in_days = float(diff.split(", ")[0].split(" ")[0])
            diff = diff.split(", ")[1]
        except (IndexError, ValueError):
            # no days different
            diff = diff.split(", ")[0]
            diff_in_days = 0

        diff_in_hrs, diff_in_mins, diff_in_seconds = [
            float(i) for i in diff.split(":")
        ]

        diff_in_seconds = (
            diff_in_seconds
            + (24 * diff_in_days * 60 + diff_in_hrs * 60 + diff_in_mins) * 60
        )
        units = {
            "days": diff_in_seconds / (60 * 60 * 24),
            "hours": diff_in_seconds / (60 * 60),
            "minutes": diff_in_seconds / 60,
            "seconds": diff_in_seconds,
        }

        return units[return_type]

    def remove_milliseconds_decimals(self, ts: str) -> str:
        """
        remove the milliseconds from the given ts
        :param ts: time in unix format
        """
        return str(ts).split(".")[0]

    def assert_microseconds(self, ts: str):
        """
        adds microseconds to the given ts if not present
        :param ts: unix ts
        :return: ts
        """
        ts = self.convert_ts_format(ts, "unixtimestamp")

        ts = str(ts)
        # pattern of unix ts with microseconds
        pattern = r"\b\d+\.\d{6}\b"
        matches = findall(pattern, ts)

        if not matches:
            # fill the missing microseconds and milliseconds with 0
            # 6 is the decimals we need after the . in the unix ts
            ts = ts + "0" * (6 - len(ts.split(".")[-1]))
        return ts

    def get_aid(self, flow):
        """
        calculates the  AID hash of the flow aka All-ID of the flow
        """
        # TODO document this
        proto = flow.proto.lower()

        # aid_hash lib only accepts unix ts
        ts = utils.convert_ts_format(flow.starttime, "unixtimestamp")
        ts: str = self.assert_microseconds(ts)

        cases = {
            "tcp": aid_hash.FlowTuple.make_tcp,
            "udp": aid_hash.FlowTuple.make_udp,
            "icmp": aid_hash.FlowTuple.make_icmp,
        }
        try:
            tpl = cases[proto](
                ts, flow.saddr, flow.daddr, flow.sport, flow.dport
            )
            return self.aid.calc(tpl)
        except KeyError:
            # proto doesn't have an aid.FlowTuple  method
            return ""

    def to_json_serializable(self, obj: Any) -> Any:
        if is_dataclass(obj):
            return {
                k: self.to_json_serializable(v) for k, v in asdict(obj).items()
            }
        elif isinstance(obj, Enum):
            return obj.value
        elif isinstance(obj, list):
            return [self.to_json_serializable(item) for item in obj]
        elif isinstance(obj, dict):
            return {k: self.to_json_serializable(v) for k, v in obj.items()}
        else:
            return obj


utils = Utils()
