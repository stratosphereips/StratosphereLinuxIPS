# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
# Stratosphere Linux IPS. A machine-learning Intrusion Detection System
# Copyright (C) 2021 Sebastian Garcia
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
import json
import threading

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
# Contact: eldraco@gmail.com, sebastian.garcia@agents.fel.cvut.cz,
# stratosphere@aic.fel.cvut.cz
from dataclasses import asdict
import queue
import ipaddress
import pprint
import multiprocessing
from typing import (
    List,
    Union,
    Optional,
)
import validators
from ipaddress import IPv4Network, IPv6Network, IPv4Address, IPv6Address
from slips_files.common.abstracts.observer import IObservable
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from slips_files.common.abstracts.core import ICore
from slips_files.common.style import green
from slips_files.core.helpers.flow_handler import FlowHandler
from slips_files.core.helpers.symbols_handler import SymbolHandler
from slips_files.core.helpers.whitelist.whitelist import Whitelist
from slips_files.core.input_profilers.argus import Argus
from slips_files.core.input_profilers.nfdump import Nfdump
from slips_files.core.input_profilers.suricata import Suricata
from slips_files.core.input_profilers.zeek import ZeekJSON, ZeekTabs

SUPPORTED_INPUT_TYPES = {
    "zeek": ZeekJSON,
    "binetflow": Argus,
    "binetflow-tabs": Argus,
    "suricata": Suricata,
    "zeek-tabs": ZeekTabs,
    "nfdump": Nfdump,
}
SEPARATORS = {
    "zeek": "",
    "suricata": "",
    "nfdump": ",",
    "binetflow": ",",
    "zeek-tabs": "\t",
    "binetflow-tabs": "\t",
}


class Profiler(ICore, IObservable):
    """A class to create the profiles for IPs"""

    name = "Profiler"

    def init(
        self,
        is_profiler_done: multiprocessing.Semaphore = None,
        profiler_queue=None,
        is_profiler_done_event: multiprocessing.Event = None,
    ):
        IObservable.__init__(self)
        self.add_observer(self.logger)
        # when profiler is done processing, it releases this semaphore,
        # that's how the process_manager knows it's done
        # when both the input and the profiler are done,
        # the input process signals the rest of the modules to stop
        self.done_processing: multiprocessing.Semaphore = is_profiler_done
        # every line put in this queue should be profiled
        self.profiler_queue: multiprocessing.Queue = profiler_queue
        self.timeformat = None
        self.input_type = False
        self.rec_lines = 0
        self.is_localnet_set = False
        self.whitelist = Whitelist(self.logger, self.db)
        self.read_configuration()
        self.symbol = SymbolHandler(self.logger, self.db)
        # there has to be a timeout or it will wait forever and never
        # receive a new line
        self.timeout = 0.0000001
        self.c1 = self.db.subscribe("reload_whitelist")
        self.channels = {
            "reload_whitelist": self.c1,
        }
        # is set by this proc to tell input proc that we are done
        # processing and it can exit no issue
        self.is_profiler_done_event = is_profiler_done_event
        self.gw_mac = None
        self.gw_ip = None
        self.profiler_threads = []
        self.stop_profiler_threads = multiprocessing.Event()
        # each msg received from inputprocess will be put here, and each one
        # profiler_threads will retrieve from this queue.
        # the goal of this is to have main() handle the stop msg.
        # so without this, only 1 of the 3 threads received the stop msg
        # and exits, and the rest of the 2 threads AND the main() keep
        # waiting for new msgs
        self.flows_to_process_q = multiprocessing.Queue()
        # that queue will be used in 4 different threads. the 3 profilers
        # and main().
        self.pending_flows_queue_lock = threading.Lock()

    def read_configuration(self):
        conf = ConfigParser()
        self.local_whitelist_path = conf.local_whitelist_path()
        self.timeformat = conf.ts_format()
        self.analysis_direction = conf.analysis_direction()
        self.label = conf.label()
        self.width = conf.get_tw_width_as_float()
        self.client_ips: List[
            Union[IPv4Network, IPv6Network, IPv4Address, IPv6Address]
        ]
        self.client_ips = conf.client_ips()

    def convert_starttime_to_epoch(self, starttime) -> str:
        try:
            return utils.convert_format(starttime, "unixtimestamp")
        except ValueError:
            self.print(
                f"We can not recognize time format of "
                f"flow.starttime: {starttime}",
                0,
                1,
            )
            return starttime

    def get_rev_profile(self, flow):
        """
        get the profileid and twid of the daddr at the current starttime,
         not the source address
        """
        if not flow.daddr:
            # some flows don't have a daddr like software.log flows
            return False, False

        rev_profileid: str = self.db.get_profileid_from_ip(flow.daddr)
        if not rev_profileid:
            # the profileid is not present in the db, create it
            rev_profileid = f"profile_{flow.daddr}"
            self.db.add_profile(rev_profileid, flow.starttime)

        # in the database, Find and register the id of the tw where the flow
        # belongs.
        rev_twid: str = self.db.get_timewindow(flow.starttime, rev_profileid)
        return rev_profileid, rev_twid

    def get_gw_ip_using_gw_mac(self) -> Optional[str]:
        """
        gets the ip of the given mac from the db
        prioritizes returning the ipv4. if not found, the function returns
        the ipv6. or none if both are not found.
        """
        # the db returns a serialized list of IPs belonging to this mac
        gw_ips: str = self.db.get_ip_of_mac(self.gw_mac)

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

    def is_gw_info_detected(self, info_type: str) -> bool:
        """
        checks own attributes and the db for the gw mac/ip
        :param info_type: can be 'mac' or 'ip'
        """
        info_mapping = {
            "mac": ("gw_mac", self.db.get_gateway_mac),
            "ip": ("gw_ip", self.db.get_gateway_ip),
        }

        if info_type not in info_mapping:
            raise ValueError(f"Unsupported info_type: {info_type}")

        attr, check_db_method = info_mapping[info_type]

        if getattr(self, attr):
            # the reason we don't just check the db is we don't want a db
            # call per each flow
            return True

        # did some other module manage to get it?
        if info := check_db_method():
            setattr(self, attr, info)
            return True

        return False

    def get_gateway_info(self, flow):
        """
        Gets the IP and MAC of the gateway and stores them in the db

        usually the mac of the flow going from a private ip -> a
        public ip is the mac of the GW
        """

        if not hasattr(flow, "dmac"):
            # some suricata flows dont have that, like SuricataFile objs
            return

        gw_mac_found: bool = self.is_gw_info_detected("mac")
        if not gw_mac_found:
            if (
                utils.is_private_ip(flow.saddr)
                and not utils.is_ignored_ip(flow.daddr)
                and flow.dmac
            ):
                self.gw_mac: str = flow.dmac
                self.db.set_default_gateway("MAC", self.gw_mac)
                # self.print(
                #     f"MAC address of the gateway detected: "
                #     f"{green(self.gw_mac)}"
                # )
                gw_mac_found = True

        # we need the mac to be set to be able to find the ip using it
        if not self.is_gw_info_detected("ip") and gw_mac_found:
            self.gw_ip: Optional[str] = self.get_gw_ip_using_gw_mac()
            if self.gw_ip:
                self.db.set_default_gateway("IP", self.gw_ip)
                self.print(
                    f"IP address of the gateway detected: "
                    f"{green(self.gw_ip)}"
                )

    def add_flow_to_profile(self, flow):
        """
        This is the main function that takes the columns of a flow
        and does all the magic to convert it into a working data in slips.
        It includes checking if the profile exists and how to put
        the flow correctly.
        """
        flow_parser = FlowHandler(self.db, self.symbol, flow)

        if not flow_parser.is_supported_flow_type():
            return False

        profileid = f"profile_{flow.saddr}"
        flow_parser.profileid = profileid

        try:
            ipaddress.ip_address(flow.saddr)
            ipaddress.ip_address(flow.daddr)
        except (ipaddress.AddressValueError, ValueError, AttributeError):
            # Its a mac
            if flow.type_ not in ("software", "weird"):
                # software and weird.log flows are allowed to not have a daddr
                return False

        self.get_gateway_info(flow)

        # Check if the flow is whitelisted and we should not process it
        if self.whitelist.is_whitelisted_flow(flow):
            return True

        # 5th. Store the data according to the paremeters
        # Now that we have the profileid and twid, add the data from the flow
        # in this tw for this profile
        self.print(f"Storing data in the profile: {profileid}", 3, 0)
        flow.starttime = self.convert_starttime_to_epoch(flow.starttime)
        # For this 'forward' profile, find the id in the
        # database of the tw where the flow belongs.
        twid = self.db.get_timewindow(flow.starttime, profileid)
        flow_parser.twid = twid

        # Create profiles for all ips we see
        self.db.add_profile(profileid, flow.starttime)
        self.store_features_going_out(flow, flow_parser)
        if self.analysis_direction == "all":
            self.handle_in_flow(flow)

        if self.db.is_cyst_enabled():
            # print the added flow as a form of debugging feedback for
            # the user to know that slips is working
            self.print(pprint.pp(asdict(flow)))
        return True

    def store_features_going_out(self, flow, flow_parser: FlowHandler):
        """
        function for adding the features going out of the profile
        """
        cases = {
            "flow": flow_parser.handle_conn,
            "conn": flow_parser.handle_conn,
            "nfdump": flow_parser.handle_conn,
            "argus": flow_parser.handle_conn,
            "dns": flow_parser.handle_dns,
            "http": flow_parser.handle_http,
            "ssl": flow_parser.handle_ssl,
            "ssh": flow_parser.handle_ssh,
            "notice": flow_parser.handle_notice,
            "ftp": flow_parser.handle_ftp,
            "smtp": flow_parser.handle_smtp,
            "files": flow_parser.handle_files,
            "arp": flow_parser.handle_arp,
            "dhcp": flow_parser.handle_dhcp,
            "software": flow_parser.handle_software,
            "weird": flow_parser.handle_weird,
            "tunnel": flow_parser.handle_tunnel,
        }
        try:
            # call the function that handles this flow
            cases[flow.type_]()
        except KeyError:
            for supported_type in cases:
                if supported_type in flow.type_:
                    cases[supported_type]()
            return False

        # if the flow type matched any of the ifs above,
        # mark this profile as modified
        self.db.mark_profile_tw_as_modified(
            flow_parser.profileid, flow_parser.twid, ""
        )

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

        saddr_as_obj = ipaddress.ip_address(flow.saddr)
        # Add the src tuple using the src ip, and dst port
        tupleid = f"{saddr_as_obj}-{flow.dport}-{flow.proto}"
        role = "Server"
        # create the intuple
        self.db.add_tuple(profileid, twid, tupleid, symbol, role, flow)

        # Add the srcip and srcport
        self.db.add_ips(profileid, twid, flow, role)
        port_type = "Src"
        self.db.add_port(profileid, twid, flow, role, port_type)

        # Add the dstport
        port_type = "Dst"
        self.db.add_port(profileid, twid, flow, role, port_type)

        # Add the flow with all the fields interpreted
        self.db.add_flow(
            flow,
            profileid=profileid,
            twid=twid,
            label=self.label,
        )
        self.db.mark_profile_tw_as_modified(profileid, twid, "")

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

    def should_set_localnet(self, flow) -> bool:
        """
        returns true only if the saddr of the current flow is ipv4, private
        and we don't have the local_net set already
        """
        if self.is_localnet_set:
            return False

        if flow.saddr == "0.0.0.0":
            return False

        if self.get_private_client_ips():
            # if we have private client ips, we're ready to set the
            # localnetwork
            return True

        if not validators.ipv4(flow.saddr):
            return False

        if self.is_ignored_ip(flow.saddr):
            return False

        saddr_obj: ipaddress = ipaddress.ip_address(flow.saddr)
        if not utils.is_private_ip(saddr_obj):
            return False

        return True

    def get_input_type(self, line: dict, input_type: str):
        """
        for example if the input_type is zeek_folder
        this function determines if it's tab or json
        etc
        :param line: dict with the line as read from the input file/dir
        given to slips using -f and the name of the logfile this line was read from
        :the input_type: as determined by slips.py
        """
        if input_type in ("zeek_folder", "zeek_log_file", "pcap", "interface"):
            # is it tab separated or comma separated?
            actual_line = line["data"]
            if isinstance(actual_line, dict):
                return "zeek"
            return "zeek-tabs"
        elif input_type == "stdin":
            # ok we're reading flows from stdin, but what type of flows?
            return line["line_type"]
        else:
            # if it's none of the above cases
            # it's probably one of a kind
            # pcap, binetflow, binetflow tabs, nfdump, etc
            return input_type

    def join_profiler_threads(self):
        # wait for the profiler threads to complete
        for thread in self.profiler_threads:
            thread.join()

    def mark_process_as_done_processing(self):
        """
        is called to mark this process as done processing so
        slips.py would know when to terminate
        """
        # signal slips.py that this process is done
        self.print(
            "Marking Profiler as done processing.", log_to_logfiles_only=True
        )
        self.done_processing.release()
        self.print("Profiler is done processing.", log_to_logfiles_only=True)
        self.is_profiler_done_event.set()
        self.print(
            "Profiler is done telling input.py " "that it's done processing.",
            log_to_logfiles_only=True,
        )

    def is_stop_msg(self, msg: str) -> bool:
        """
        this 'stop' msg is the last msg ever sent by the input process
        to indicate that no more flows are coming
        """
        return msg == "stop"

    def get_private_client_ips(
        self,
    ) -> List[Union[IPv4Network, IPv6Network, IPv4Address, IPv6Address]]:
        """
        returns the private ips found in the client_ips param
        in the config file
        """
        private_clients = []
        for ip in self.client_ips:
            if utils.is_private_ip(ip):
                private_clients.append(ip)
        return private_clients

    def get_local_net(self, flow) -> Optional[str]:
        """
        gets the local network from client_ip param in the config file,
        or by using the localnetwork of the first private
        srcip seen in the traffic
        """
        # For now the local network is only ipv4, but it
        # could be ipv6 in the future. Todo.
        private_client_ips: List[
            Union[IPv4Network, IPv6Network, IPv4Address, IPv6Address]
        ]
        private_client_ips = self.get_private_client_ips()

        if private_client_ips:
            # does the client ip from the config already have the localnet?
            for range_ in private_client_ips:
                if isinstance(range_, IPv4Network) or isinstance(
                    range_, IPv6Network
                ):
                    self.is_localnet_set = True
                    return str(range_)

            # all client ips should belong to the same local network,
            # it doesn't make sense to have ips belonging to different
            # networks in the config file!
            ip: str = str(private_client_ips[0])
        else:
            ip: str = flow.saddr

        self.is_localnet_set = True
        return utils.get_cidr_of_private_ip(ip)

    def handle_setting_local_net(self, flow):
        """
        stores the local network if possible
        """
        if not self.should_set_localnet(flow):
            return

        local_net: str = self.get_local_net(flow)
        self.print(f"Used local network: {green(local_net)}")
        self.db.set_local_network(local_net)

    def get_msg_from_input_proc(
        self, q: multiprocessing.Queue, thread_safe=False
    ):
        """
        retrieves a msg from the given queue
        :kwarg thread_safe: set it to true if the queue passed is used by
        the profiler threads (e.g pending_flows_queue).
         when set to true, this function uses the pending flows queue lock.
        """
        try:
            if thread_safe:
                with self.pending_flows_queue_lock:
                    return q.get(timeout=1, block=False)
            else:
                return q.get(timeout=1, block=False)
        except queue.Empty:
            return None
        except Exception:
            return None

    def start_profiler_threads(self):
        """starts 3 profiler threads for faster processing of the flows"""
        num_of_profiler_threads = 3
        for _ in range(num_of_profiler_threads):
            t = threading.Thread(target=self.process_flow)
            t.daemon = True
            t.start()
            self.profiler_threads.append(t)

    def init_input_handlers(self, line, input_type):
        # self.input_type is set only once by define_separator
        # once we know the type, no need to check each line for it
        if not self.input_type:
            # Find the type of input received
            self.input_type = self.get_input_type(line, input_type)

        # What type of input do we have?
        if not self.input_type:
            # the above define_type can't define the type of input
            self.print("Can't determine input type.")
            return False

        # only create the input_handler_obj once,
        # the rest of the flows will use the same input handler
        if not hasattr(self, "input_handler_obj"):
            self.input_handler_obj = SUPPORTED_INPUT_TYPES[self.input_type]()

    def stop_profiler_thread(self) -> bool:
        # cant use while self.flows_to_process_q.qsize() != 0 only here
        # because when the thread starts, this qsize is 0, so we need
        # another indicator that we are at the end of the flows. aka the
        # stop_profiler_threads event
        return (
            self.stop_profiler_threads.is_set()
            and not self.flows_to_process_q.qsize()
        )

    def process_flow(self):
        """
        This function runs in 3 parallel threads for faster processing of
        the flows
        """

        while not self.stop_profiler_thread():
            msg = self.get_msg_from_input_proc(
                self.flows_to_process_q, thread_safe=True
            )
            if not msg:
                # wait for msgs
                continue

            line: dict = msg["line"]
            input_type: str = msg["input_type"]

            # TODO who is putting this True here?
            if line is True:
                continue

            # Received new input data
            self.print(f"< Received Line: {line}", 2, 0)
            self.rec_lines += 1

            # get the correct input type class and process the line based on it
            try:
                self.init_input_handlers(line, input_type)

                flow = self.input_handler_obj.process_line(line)
                if not flow:
                    continue

                self.add_flow_to_profile(flow)
                self.handle_setting_local_net(flow)
                self.db.increment_processed_flows()
            except Exception as e:
                self.print_traceback()
                self.print(
                    f"Problem processing line {line}. "
                    f"Line discarded. Error: {e}",
                    0,
                    1,
                )

    def should_stop(self):
        """
        overrides Imodule's should_stop()
        the common Imodule's should_stop() stop when there's no msg in
        each channel and the termination event is set
        since this module is the one responsible for signaling the
        termination event (via process_manager) then it doesnt make sense
        to check for it. it will never be set before this module stops.
        """
        return False

    def shutdown_gracefully(self):
        self.stop_profiler_threads.set()
        # wait for all flows to be processed by the profiler threads.
        self.join_profiler_threads()
        # close the queues to avoid deadlocks.
        # this step SHOULD NEVER be done before closing the threads
        self.flows_to_process_q.close()
        self.profiler_queue.close()

        self.db.set_new_incoming_flows(False)
        self.print(
            f"Stopping. Total lines read: {self.rec_lines}",
            log_to_logfiles_only=True,
        )
        self.mark_process_as_done_processing()

    def pre_main(self):
        utils.drop_root_privs()
        client_ips = [str(ip) for ip in self.client_ips]
        if client_ips:
            self.print(f"Used client IPs: {green(', '.join(client_ips))}")
        self.start_profiler_threads()

    def main(self):
        # the only thing that stops this loop is the 'stop' msg
        # we're using self.should_stop() here instead of while True to be
        # able to unit test this function:D
        while not self.should_stop():
            # listen on this channel in case whitelist.conf is changed,
            # we need to process the new changes
            if self.get_msg("reload_whitelist"):
                # if whitelist.conf is edited using pycharm
                # a msg will be sent to this channel on every keypress,
                # because pycharm saves file automatically
                # otherwise this channel will get a msg only when
                # whitelist.conf is modified and saved to disk
                self.whitelist.update()

            msg = self.get_msg_from_input_proc(self.profiler_queue)
            if not msg:
                # wait for msgs
                continue

            # ALYA, DO NOT REMOVE THIS CHECK
            # without it, there's no way this module will know it's
            # time to stop and no new flows are coming
            if self.is_stop_msg(msg):
                # shutdown gracefully will be called by ICore() once this
                # function returns
                return 1

            self.pending_flows_queue_lock.acquire()
            self.flows_to_process_q.put(msg)
            self.pending_flows_queue_lock.release()
