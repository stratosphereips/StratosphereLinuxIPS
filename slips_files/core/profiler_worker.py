import csv
import json
import os
import pprint
import time
import ipaddress
import multiprocessing
from dataclasses import asdict
from typing import (
    List,
    Union,
    Optional,
    Callable,
)

from ipaddress import IPv4Network, IPv6Network, IPv4Address, IPv6Address
import gc

from slips_files.common.abstracts.imodule import IModule
from slips_files.common.slips_utils import utils
from slips_files.common.performance_paths import get_performance_csv_path
from slips_files.common.style import green
from slips_files.core.aid_manager import AIDManager
from slips_files.core.helpers.flow_handler import FlowHandler
from slips_files.core.helpers.localnet_handler import LocalnetHandler
from slips_files.core.helpers.symbols_handler import SymbolHandler
from slips_files.core.helpers.whitelist.whitelist import Whitelist
from slips_files.core.input_profilers.argus import Argus
from slips_files.core.input_profilers.nfdump import Nfdump
from slips_files.core.input_profilers.suricata import Suricata
from slips_files.core.input_profilers.zeek import ZeekJSON, ZeekTabs
from slips_files.core.structures.flow_attributes import Role


class ProfilerWorker(IModule):
    name = "profiler_worker"

    def init(
        self,
        name,
        profiler_queue: multiprocessing.Queue,
        input_handler: (
            ZeekTabs | ZeekJSON | Argus | Suricata | ZeekTabs | Nfdump
        ),
        aid_queue: multiprocessing.Queue,
        aid_manager: AIDManager,
        is_input_done_event: multiprocessing.Event = None,
    ):
        self.name = name
        self.profiler_queue = profiler_queue
        # used to pass aid tasks from workers to the the AIDManager()
        self.aid_queue = aid_queue
        self.aid_manager: AIDManager = aid_manager
        # lets workers stop when input is done even if the stop sentinel
        # never reaches them
        self.is_input_done_event = is_input_done_event
        # this is an instance of
        # ZeekTabs | ZeekJSON | Argus | Suricata | ZeekTabs | Nfdump
        self.input_handler = input_handler
        self.read_configuration()
        self.received_lines = 0
        self.localnet_handler = LocalnetHandler(self)
        self.whitelist = Whitelist(self.logger, self.db, self.bloom_filters)
        self.symbol = SymbolHandler(self.logger, self.db)
        # stores the MAC addresses of the gateway of each interface
        # will have interfaces as keys, and MACs as values
        self.gw_macs = {}
        self.gw_ips = {}
        # flag to know which flow is the start of the pcap/file
        self.first_flow = True
        self.is_running_non_stop: bool = self.db.is_running_non_stop()
        self.slips_start_time = self._get_slips_start_time()
        self.latency_logfile = None
        if self.generate_performance_plots:
            self.latency_logfile = get_performance_csv_path(
                self.output_dir,
                f"{self._get_latency_filename_prefix()}_latency.csv",
            )
            self._initialize_latency_logfile()
        self._modified_tws = {}
        self._time_to_update_modified_tws = time.time()
        self._modified_timewindows_update_period = 3  # in seconds

    def subscribe_to_channels(self):
        self.c1 = self.db.subscribe("new_zeek_fields_line")
        self.channels = {
            "new_zeek_fields_line": self.c1,
        }

    def read_configuration(self):
        self.client_ips: List[
            Union[IPv4Network, IPv6Network, IPv4Address, IPv6Address]
        ]
        self.client_ips = self.conf.client_ips()
        self.local_whitelist_path = self.conf.local_whitelist_path()
        self.timeformat = self.conf.ts_format()
        self.analysis_direction = self.conf.analysis_direction()
        self.label = self.conf.label()
        self.width = self.conf.get_tw_width_in_seconds()
        self.generate_performance_plots = (
            self.conf.generate_performance_plots() is True
        )

    def get_msg_from_queue(self, q: multiprocessing.Queue):
        """
        retrieves a msg from the given queue
        """
        try:
            return q.get(timeout=1, block=False)
        except multiprocessing.queues.Empty:
            return None
        except Exception:
            self.print_traceback()
            return None

    def convert_starttime_to_unix_ts(self, starttime) -> str:
        if utils.is_unix_ts(starttime):
            return starttime

        try:
            return utils.convert_ts_format(starttime, "unixtimestamp")
        except ValueError:
            self.print(
                f"Slips can not recognize time format of "
                f"flow.starttime: {starttime}",
                0,
                1,
            )
            return starttime

    def store_first_seen_ts(self, ts):
        # set the pcap/file start time in the analysis key
        if self.first_flow:
            self.first_flow = False

            if self.db.get_first_flow_time():
                # already set by another worker
                return

            self.db.set_input_metadata({"file_start": ts})

    def _get_slips_start_time(self) -> float:
        slips_start_time = self.db.get_slips_start_time()
        try:
            return float(slips_start_time)
        except (TypeError, ValueError):
            return time.time()

    def _get_latency_filename_prefix(self) -> str:
        if self.name.startswith("profiler_worker_process_"):
            worker_id = self.name.split("_")[-1]
            return f"profiler_worker_{worker_id}"
        return self.name.lower()

    def _initialize_latency_logfile(self):
        if not self.latency_logfile:
            return

        os.makedirs(os.path.dirname(self.latency_logfile), exist_ok=True)
        if os.path.exists(self.latency_logfile):
            return

        with open(
            self.latency_logfile, "w", newline="", encoding="utf-8"
        ) as f:
            writer = csv.writer(f)
            writer.writerow(
                ["timestamp_now", "flow_uid", "latency_in_seconds"]
            )

    def _log_flow_latency(self, flow, flow_starttime) -> None:
        if not self.generate_performance_plots or not self.latency_logfile:
            return

        try:
            flow_start_ts = float(flow_starttime)
        except (TypeError, ValueError):
            return

        now = time.time()
        timestamp_now = now - self.slips_start_time
        latency = now - flow_start_ts
        flow_uid = getattr(flow, "uid", "")

        with open(
            self.latency_logfile, "a", newline="", encoding="utf-8"
        ) as f:
            writer = csv.writer(f)
            writer.writerow([timestamp_now, flow_uid, int(latency)])

    def _update_modified_tws_in_the_db(self, profileid: str, twid: str, flow):
        """
        to avoid updating the modified tws in the db for every single flow,
        we batch the updates and do them every 3 seconds
        """
        self._modified_tws.update({f"{profileid}_{twid}": flow.starttime})
        now = time.time()
        if now > self._time_to_update_modified_tws:
            self._time_to_update_modified_tws = (
                now + self._modified_timewindows_update_period
            )
            # now that slips successfully parsed the flow,
            # mark this profile as modified
            self.db.mark_profile_tw_as_modified(self._modified_tws)
            self._modified_tws = {}

    def store_features_going_in(self, profileid: str, twid: str, flow):
        """
        If we have the all direction set , slips creates profiles
        for each IP, the src and dst
        store features going our adds the conn in the profileA from
        IP A -> IP B in the db
        this function stores the reverse of this connection. adds
        the conn in the profileB from IP B <- IP A
        """
        # self.print(f'Storing features going in for profile
        # {profileid} and tw {twid}')
        supported_types = {"flow", "conn", "argus", "nfdump"}
        for type_ in supported_types:
            if type_ in flow.type_:
                break
        else:
            return

        symbol = self.symbol.compute(flow, twid, "InTuples")

        if not utils.is_valid_ip(flow.saddr):
            return

        role = Role.SERVER
        self.db.add_tuple(profileid, twid, symbol, role, flow)
        self.db.add_ips(profileid, twid, flow, role)
        # Add the flow with all the fields interpreted to the sqlite db
        self.aid_manager.submit_aid_task(flow, profileid, twid, self.label)
        self._update_modified_tws_in_the_db(profileid, twid, flow)

    def get_aid_and_store_flow_in_the_db(
        self,
        handler_func: Callable,
        handle_conn: Callable,
        flow,
        profileid,
        twid,
    ):
        """
        Checks if the given flow is handled with the
        flow_handler.handle_conn func, and submits a task to calc aid and
        store the conn flow in the sqlite db based on this
        i know this is complicated, but it speeds up slips flow reading a
        lot, it makes hash calculation non blocking of the profiler worker
        """
        # why are we not calling this inside handle_conn? because
        # handle_conn is in FlowHandler class, which gets initialized once
        # per flow, and we dont wanna have 1 executor per flow, we want
        # one executor per profiler worker
        if handler_func == handle_conn:
            # Add the flow with all the fields interpreted to the sqlite db
            self.aid_manager.submit_aid_task(flow, profileid, twid, "benign")

    def store_features_going_out(self, flow, profileid, twid):
        """
        function for adding the features going out of the profile
        aka outgoing connections
        """
        self.store_first_seen_ts(flow.starttime)
        flow_handler = FlowHandler(
            self.db,
            self.symbol,
            flow,
            profileid,
            twid,
            self.is_running_non_stop,
        )
        cases = {
            "flow": flow_handler.handle_conn,
            "conn": flow_handler.handle_conn,
            "nfdump": flow_handler.handle_conn,
            "argus": flow_handler.handle_conn,
            "dns": flow_handler.handle_dns,
            "http": flow_handler.handle_http,
            "ssl": flow_handler.handle_ssl,
            "ssh": flow_handler.handle_ssh,
            "notice": flow_handler.handle_notice,
            "ftp": flow_handler.handle_ftp,
            "smtp": flow_handler.handle_smtp,
            "files": flow_handler.handle_files,
            "arp": flow_handler.handle_arp,
            "dhcp": flow_handler.handle_dhcp,
            "software": flow_handler.handle_software,
            "weird": flow_handler.handle_weird,
            "tunnel": flow_handler.handle_tunnel,
            "login": flow_handler.handle_login,
        }
        try:
            # call the function that handles this flow
            handler_func = cases[flow.type_]
            handler_func()
        except KeyError:
            # see if one of the above dict keys is a substr of the flow.type_
            for supported_type, handler_func in cases.items():
                if supported_type in flow.type_:
                    handler_func()
                    break
            else:
                return False

        self.get_aid_and_store_flow_in_the_db(
            handler_func, flow_handler.handle_conn, flow, profileid, twid
        )
        # now that slips successfully parsed the flow,
        # mark this profile as modified
        self._update_modified_tws_in_the_db(profileid, twid, flow)
        return True

    def get_rev_profile(self, flow):
        """
        get the profileid and twid of the daddr at the current starttime,
         not the source address
        """
        if not flow.daddr:
            # some flows don't have a daddr like software.log flows
            return False, False

        # add it to the db id its not there
        rev_profileid = f"profile_{flow.daddr}"
        self.db.add_profile(rev_profileid, flow.starttime)

        # in the database, Find and register the id of the tw where the flow
        # belongs.
        rev_twid: str = self.db.get_timewindow(flow.starttime, rev_profileid)
        return rev_profileid, rev_twid

    def is_gw_info_detected(self, info_type: str, interface: str) -> bool:
        """
        checks own attributes and the db for the gw mac/ip
        :param info_type: can be 'mac' or 'ip'
        """
        info_mapping = {
            "mac": ("gw_macs", self.db.get_gateway_mac),
            "ip": ("gw_ips", self.db.get_gateway_ip),
        }

        if info_type not in info_mapping:
            raise ValueError(f"Unsupported info_type: {info_type}")

        attr, check_db_method = info_mapping[info_type]

        # did we get this interface's GW IP/MAC yet?
        if interface in getattr(self, attr, {}):
            # the reason we don't just check the db is we don't want a db
            # call per each flow
            return True

        # did some other module manage to get it?
        if info := check_db_method(interface):
            getattr(self, attr, {}).update({interface: info})
            return True

        return False

    def handle_in_flow(self, flow):
        """
        Adds a flow for the daddr <- saddr connection
        """
        # they are not actual flows to add in slips,
        # they are info about some ips derived by zeek from the flows
        execluded_flows = "software"
        if flow.type_ in execluded_flows:
            return
        rev_profileid, rev_twid = self.get_rev_profile(flow)
        self.store_features_going_in(rev_profileid, rev_twid, flow)

    def get_gw_ip_using_gw_mac(self, gw_mac) -> Optional[str]:
        """
        gets the ip of the given mac from the db
        prioritizes returning the ipv4. if not found, the function returns
        the ipv6. or none if both are not found.
        """
        # the db returns a serialized list of IPs belonging to this mac
        gw_ips: str = self.db.get_ip_of_mac(gw_mac)

        if not gw_ips:
            return

        gw_ips: List[str] = json.loads(gw_ips)
        # try to get the ipv4 if found in that list
        for ip in gw_ips:
            try:
                ipaddress.IPv4Address(ip)
                return ip
            except ipaddress.AddressValueError:
                continue

        # all of them are ipv6, return the first
        return gw_ips[0]

    def gw_ip_belongs_to_localnet(self, gw_ip: str) -> bool:
        """checks if the given detected gw_ip belongs to the detected local
        network"""
        try:
            gw_ip_obj = ipaddress.ip_address(gw_ip)
        except ValueError:
            return False

        for interface in utils.get_all_interfaces(self.args):
            local_net = self.db.get_local_network(interface)
            if not local_net:
                continue
            try:
                local_net_obj = ipaddress.ip_network(local_net, strict=False)
            except ValueError:
                continue

            if gw_ip_obj in local_net_obj:
                return True
        return False

    def get_gateway_info(self, flow):
        """
        Gets the IP and MAC of the gateway and stores them in the db
        doesn't get the gateway ip if it's already in the db (for example
        detected by ip_info) module
        usually the mac of the flow going from a private ip -> a
        public ip is the mac of the GW
        """

        if not hasattr(flow, "dmac"):
            # some suricata flows dont have that, like SuricataFile objs
            return

        gw_mac_found: bool = self.is_gw_info_detected("mac", flow.interface)

        if not gw_mac_found:
            # we didnt get the MAC of the GW of this flow's interface
            # ok consider the GW MAC = any dst MAC of a flow
            # going from a private srcip -> a public dstip
            if (
                utils.is_private_ip(flow.saddr)
                and not utils.is_ignored_ip(flow.daddr)
                and flow.dmac
            ):
                self.gw_macs.update({flow.interface: flow.dmac})
                self.db.set_default_gateway("MAC", flow.dmac, flow.interface)
                # self.print(
                #     f"MAC address of the gateway detected: "
                #     f"{green(self.gw_mac)}"
                # )
                gw_mac_found = True

        # we need the mac to be set to be able to find the ip using it
        if not self.is_gw_info_detected("ip", flow.interface) and gw_mac_found:
            gw_mac: Optional[str] = self.gw_macs.get(flow.interface)
            if not gw_mac:
                return

            gw_ip: Optional[str] = self.get_gw_ip_using_gw_mac(gw_mac)
            if gw_ip and self.gw_ip_belongs_to_localnet(gw_ip):
                self.gw_ips[flow.interface] = gw_ip
                self.db.set_default_gateway("IP", gw_ip, flow.interface)
                self.print(
                    f"IP address of the gateway detected: " f"{green(gw_ip)}"
                )

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
            or ip_obj.is_link_local
            or ip_obj.is_loopback
            or ip_obj.is_reserved
        )

    def _is_supported_flow_type(self, flow) -> bool:
        supported_types = (
            "ssh",
            "ssl",
            "http",
            "dns",
            "conn",
            "flow",
            "argus",
            "nfdump",
            "notice",
            "dhcp",
            "files",
            "arp",
            "ftp",
            "smtp",
            "software",
            "weird",
            "tunnel",
            "login",
        )
        return bool(
            flow.starttime is not None and flow.type_ in supported_types
        )

    def add_flow_to_profile(self, flow):
        """
        This is the main function that takes the columns of a flow
        and does all the magic to convert it into a working data in slips.
        It includes checking if the profile exists and how to put
        the flow correctly.
        """
        if not self._is_supported_flow_type(flow):
            return False

        try:
            ipaddress.ip_address(flow.saddr)
            ipaddress.ip_address(flow.daddr)
        except (ipaddress.AddressValueError, ValueError, AttributeError):
            # Its a mac
            if flow.type_ not in ("software", "weird"):
                # software and weird.log flows are allowed to not have a daddr
                return False

        flow_starttime = self.convert_starttime_to_unix_ts(flow.starttime)
        self._log_flow_latency(flow, flow_starttime)

        self.get_gateway_info(flow)
        # Check if the flow is whitelisted and we should not process it
        if self.whitelist.is_whitelisted_flow(flow):
            self.print(f"{self.whitelist.get_bloom_filters_stats()}", 2, 0)
            return True

        # 5th. Store the data according to the paremeters
        # Now that we have the profileid and twid, add the data from the flow
        # in this tw for this profile
        profileid = f"profile_{flow.saddr}"
        self.print(f"Storing data in the profile: {profileid}", 3, 0)
        flow.starttime = flow_starttime

        # Create profiles for all ips we see
        self.db.add_profile(profileid, flow.starttime)

        # For this 'forward' profile, find the id in the
        # database of the tw where the flow belongs.
        twid = self.db.get_timewindow(flow.starttime, profileid)

        self.store_features_going_out(flow, profileid, twid)

        if self.analysis_direction == "all":
            self.handle_in_flow(flow)

        if self.db.is_cyst_enabled():
            # print the added flow as a form of debugging feedback for
            # the user to know that slips is working
            self.print(pprint.pp(asdict(flow)))
        return True

    def update_the_files_input_handler_knows_about(self, msg: dict):
        """
        updates the input handler with the new zeek fields
        recvd in the msg
        """
        msg: dict = json.loads(msg["data"])
        self.input_handler.line_processor_cache.update(msg)

    def is_stop_msg(self, msg: str) -> bool:
        """
        this 'stop' msg is the last msg ever sent by the input process
        to indicate that no more flows are coming
        the number of stop msgs sent is = the number of started workers
        """
        return msg == "stop"

    def pre_main(self):
        """
        if this profiler worker was started late after slips detected
        latency, it won't know about the processors published in the
        new_zeek_fields_line channel. this pre_main takes care of that
        """
        worker_number = self.name.split("_")[-1]
        self.print(
            f"Started {green('Profiler Worker')} {green(worker_number)} [PID"
            f" {green(os.getpid())}]"
        )

        if line_processors := self.db.get_line_processors():
            for file_type, indices in line_processors.items():
                self.input_handler.line_processor_cache.update(
                    {file_type: json.loads(indices)}
                )

    def should_stop(self):
        """
        Overrides the default IModule should_stop().
        This module will only stop when it recvs the sentinel stop msg
        """
        return False

    def main(self):
        # Disable automatic GC, we'll trigger it manually
        gc.disable()
        try:
            for _ in range(3):
                if msg := self.get_msg("new_zeek_fields_line"):
                    self.update_the_files_input_handler_knows_about(msg)

            msg = self.get_msg_from_queue(self.profiler_queue)
            if not msg:
                return

            if self.is_stop_msg(msg):
                gc.collect()
                # no need to wait for the should_stop(), this worker will
                # never recv any new flows after the stop msg
                return 1

            line: dict = msg["line"]

            self.received_lines += 1
            flow, err = self.input_handler.process_line(line)

            if not flow:
                # put back the msg in queue until this profiler gets a
                # msg in new_zeek_fields_line about the unknown line_processor
                # or another worker that knows how to process this line does it
                if err == "unknown line_processor":
                    if (
                        self.is_input_done_event is not None
                        and self.is_input_done_event.is_set()
                    ):
                        return
                    self.profiler_queue.put(msg)
                return

            self.add_flow_to_profile(flow)
            self.localnet_handler.handle_setting_local_net(flow)
            self.db.increment_processed_flows()

            if self.generate_performance_plots:
                self.db.record_flow_per_minute(self.name)

            # manually run garbage collection to avoid the latency
            # introduced by it when slips is given a huge number of flows
            if self.received_lines % 10000 == 0:
                gc.collect()

        except KeyboardInterrupt:
            # on the first ctrl+c profiler AND input process should stop,
            # so the modules receive no more flows.
            # modules should just finish the flows they have and slips will
            # exit gracefully
            gc.enable()
            return 1
        except Exception:
            self.print(
                f"Unable to process flow: {msg if msg else None}: "
                f"{self.print_traceback()}",
                0,
                1,
            )
