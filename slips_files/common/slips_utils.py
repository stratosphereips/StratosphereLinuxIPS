# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import base64
import binascii
import hashlib
from datetime import datetime, timedelta
from re import findall
from threading import Thread

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
from typing import (
    Any,
    Optional,
    Union,
    List,
)
from ipaddress import IPv4Network, IPv6Network, IPv4Address, IPv6Address
from dataclasses import is_dataclass, asdict
from enum import Enum

from slips_files.core.supported_logfiles import SUPPORTED_LOGFILES

IS_IN_A_DOCKER_CONTAINER = os.environ.get("IS_IN_A_DOCKER_CONTAINER", False)


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
        # this format will be used across all modules and logfiles of slips
        # its timezone aware
        self.alerts_format = "%Y/%m/%d %H:%M:%S.%f%z"
        self.local_tz = self.get_local_timezone()
        self.aid = aid_hash.AID()

    def generate_uid(self):
        """Generates a UID similar to what Zeek uses."""
        return base64.b64encode(binascii.b2a_hex(os.urandom(9))).decode(
            "utf-8"
        )

    def is_iso_format(self, date_time: str) -> bool:
        try:
            datetime.fromisoformat(date_time)
            return True
        except ValueError:
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

    def drop_root_privs(self):
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
        starts the given thread and keeps track of its TID/PID in the db
        :param thread: the thread to start
        :param db: a DBManager obj to store the thread PID
        """
        thread.start()
        db.store_pid(thread.name, int(thread._native_id))

    def convert_format(self, ts, required_format: str):
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

        given_format = self.get_time_format(ts)
        return (
            datetime.fromtimestamp(float(ts))
            if given_format == "unixtimestamp"
            else datetime.strptime(ts, given_format)
        )

    def get_time_format(self, time) -> Optional[str]:
        if self.is_datetime_obj(time):
            return "datetimeobj"

        try:
            # Try unix timestamp in seconds.
            datetime.fromtimestamp(float(time))
            return "unixtimestamp"
        except ValueError:
            pass

        for time_format in self.time_formats:
            try:
                datetime.strptime(time, time_format)
                return time_format
            except ValueError:
                pass

        return False

    def to_delta(self, time_in_seconds):
        return timedelta(seconds=int(time_in_seconds))

    def get_human_readable_datetime(self) -> str:
        return utils.convert_format(datetime.now(), self.alerts_format)

    def get_own_ips(self) -> list:
        """
        Returns a list of our local and public IPs
        """
        if "-i" not in sys.argv:
            # this method is only valid when running on an interface
            return []

        IPs = []
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("10.255.255.255", 1))
            IPs.append(s.getsockname()[0])
        except Exception:
            IPs.append("127.0.0.1")
        finally:
            s.close()

        # get public ip

        try:
            response = requests.get(
                "http://ipinfo.io/json",
                timeout=5,
            )
        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.ChunkedEncodingError,
            requests.exceptions.ReadTimeout,
        ):
            return IPs

        if response.status_code != 200:
            return IPs
        if "Connection timed out" in response.text:
            return IPs
        try:
            response = json.loads(response.text)
        except json.decoder.JSONDecodeError:
            return IPs
        public_ip = response["ip"]
        IPs.append(public_ip)
        return IPs

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
        ts = self.convert_format(ts, "unixtimestamp")

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
        ts = utils.convert_format(flow.starttime, "unixtimestamp")
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
