# Stratosphere Linux IPS. A machine-learning Intrusion Detection System
# Copyright (C) 2021 Sebastian Garcia
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

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
)

import validators

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
        self.profiler_queue = profiler_queue
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

    def read_configuration(self):
        conf = ConfigParser()
        self.whitelist_path = conf.whitelist_path()
        self.timeformat = conf.ts_format()
        self.analysis_direction = conf.analysis_direction()
        self.label = conf.label()
        self.width = conf.get_tw_width_as_float()
        self.client_ips: List[str] = conf.client_ips()

    def convert_starttime_to_epoch(self):
        try:
            self.flow.starttime = utils.convert_format(
                self.flow.starttime, "unixtimestamp"
            )
        except ValueError:
            self.print(
                f"We can not recognize time format of "
                f"self.flow.starttime: {self.flow.starttime}",
                0,
                1,
            )

    def get_rev_profile(self):
        """
        get the profileid and twid of the daddr at the current starttime,
         not the source address
        """
        if not self.flow.daddr:
            # some flows don't have a daddr like software.log flows
            return False, False

        rev_profileid: str = self.db.get_profileid_from_ip(self.flow.daddr)
        if not rev_profileid:
            # the profileid is not present in the db, create it
            rev_profileid = f"profile_{self.flow.daddr}"
            self.db.add_profile(rev_profileid, self.flow.starttime)

        # in the database, Find and register the id of the tw where the flow
        # belongs.
        rev_twid: str = self.db.get_timewindow(
            self.flow.starttime, rev_profileid
        )
        return rev_profileid, rev_twid

    def add_flow_to_profile(self):
        """
        This is the main function that takes the columns of a flow
        and does all the magic to convert it into a working data in our
        system.
        It includes checking if the profile exists and how to put
        the flow correctly.
        """
        # try:
        if not hasattr(self, "flow"):
            # TODO this is a quick fix
            return False

        self.flow_parser = FlowHandler(self.db, self.symbol, self.flow)

        if not self.flow_parser.is_supported_flow_type():
            return False

        self.profileid = f"profile_{self.flow.saddr}"
        self.flow_parser.profileid = self.profileid

        try:
            self.saddr_as_obj = ipaddress.ip_address(self.flow.saddr)
            self.daddr_as_obj = ipaddress.ip_address(self.flow.daddr)
        except (ipaddress.AddressValueError, ValueError):
            # Its a mac
            if self.flow.type_ not in ("software", "weird"):
                # software and weird.log flows are allowed to not have a daddr
                return False

        # Check if the flow is whitelisted and we should not process it
        if self.whitelist.is_whitelisted_flow(self.flow):
            return True

        # 5th. Store the data according to the paremeters
        # Now that we have the profileid and twid, add the data from the flow
        # in this tw for this profile
        self.print(f"Storing data in the profile: {self.profileid}", 3, 0)
        self.convert_starttime_to_epoch()
        # For this 'forward' profile, find the id in the
        # database of the tw where the flow belongs.
        self.twid = self.db.get_timewindow(self.flow.starttime, self.profileid)
        self.flow_parser.twid = self.twid

        # Create profiles for all ips we see
        self.db.add_profile(self.profileid, self.flow.starttime)
        self.store_features_going_out()
        if self.analysis_direction == "all":
            self.handle_in_flows()

        if self.db.is_cyst_enabled():
            # print the added flow as a form of debugging feedback for
            # the user to know that slips is working
            self.print(pprint.pp(asdict(self.flow)))

        return True

    def store_features_going_out(self):
        """
        function for adding the features going out of the profile
        """
        cases = {
            "flow": self.flow_parser.handle_conn,
            "conn": self.flow_parser.handle_conn,
            "nfdump": self.flow_parser.handle_conn,
            "argus": self.flow_parser.handle_conn,
            "dns": self.flow_parser.handle_dns,
            "http": self.flow_parser.handle_http,
            "ssl": self.flow_parser.handle_ssl,
            "ssh": self.flow_parser.handle_ssh,
            "notice": self.flow_parser.handle_notice,
            "ftp": self.flow_parser.handle_ftp,
            "smtp": self.flow_parser.handle_smtp,
            "files": self.flow_parser.handle_files,
            "arp": self.flow_parser.handle_arp,
            "dhcp": self.flow_parser.handle_dhcp,
            "software": self.flow_parser.handle_software,
            "weird": self.flow_parser.handle_weird,
            "tunnel": self.flow_parser.handle_tunnel,
        }
        try:
            # call the function that handles this flow
            cases[self.flow.type_]()
        except KeyError:
            for supported_type in cases:
                if supported_type in self.flow.type_:
                    cases[supported_type]()
            return False

        # if the flow type matched any of the ifs above,
        # mark this profile as modified
        self.db.mark_profile_tw_as_modified(self.profileid, self.twid, "")

    def store_features_going_in(self, profileid: str, twid: str):
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
        if (
            "flow" not in self.flow.type_
            and "conn" not in self.flow.type_
            and "argus" not in self.flow.type_
            and "nfdump" not in self.flow.type_
        ):
            return
        symbol = self.symbol.compute(self.flow, self.twid, "InTuples")

        # Add the src tuple using the src ip, and dst port
        tupleid = f"{self.saddr_as_obj}-{self.flow.dport}-{self.flow.proto}"
        role = "Server"
        # create the intuple
        self.db.add_tuple(profileid, twid, tupleid, symbol, role, self.flow)

        # Add the srcip and srcport
        self.db.add_ips(profileid, twid, self.flow, role)
        port_type = "Src"
        self.db.add_port(profileid, twid, self.flow, role, port_type)

        # Add the dstport
        port_type = "Dst"
        self.db.add_port(profileid, twid, self.flow, role, port_type)

        # Add the flow with all the fields interpreted
        self.db.add_flow(
            self.flow,
            profileid=profileid,
            twid=twid,
            label=self.label,
        )
        self.db.mark_profile_tw_as_modified(profileid, twid, "")

    def handle_in_flows(self):
        """
        Adds a flow for the daddr <- saddr connection
        """
        # they are not actual flows to add in slips,
        # they are info about some ips derived by zeek from the flows
        execluded_flows = "software"
        if self.flow.type_ in execluded_flows:
            return
        rev_profileid, rev_twid = self.get_rev_profile()
        self.store_features_going_in(rev_profileid, rev_twid)

    def should_set_localnet(self) -> bool:
        """
        returns true only if the saddr of the current flow is ipv4, private
        and we don't have the local_net set already
        """
        if self.is_localnet_set:
            return False

        if self.get_private_client_ips():
            # if we have private client ips, we're ready to set the
            # localnetwork
            return True

        if not validators.ipv4(self.flow.saddr):
            return False

        saddr_obj: ipaddress = ipaddress.ip_address(self.flow.saddr)
        is_private_ip = utils.is_private_ip(saddr_obj)
        if not is_private_ip:
            return False

        return True

    def define_separator(self, line: dict, input_type: str):
        """
        :param line: dict with the line as read from the input file/dir
        given to slips using -f and the name of the logfile this line was read from
        :the input_type: as determined by slips.py
        this function determines the line separator
        for example if the input_type is zeek_folder
        this function determines if it's tab or json
        etc
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

    def shutdown_gracefully(self):
        self.print(
            f"Stopping. Total lines read: {self.rec_lines}",
            log_to_logfiles_only=True,
        )
        self.mark_process_as_done_processing()

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

    def get_private_client_ips(self) -> List[str]:
        """
        returns the private ips found in the client_ips param
        in the config file
        """
        private_clients = []
        for ip in self.client_ips:
            if utils.is_private_ip(ipaddress.ip_address(ip)):
                private_clients.append(ip)
        return private_clients

    def get_local_net(self) -> str:
        """
        gets the local network from client_ip param in the config file,
        or by using the localnetwork of the first private
        srcip seen in the traffic
        """
        # For now the local network is only ipv4, but it
        # could be ipv6 in the future. Todo.
        private_client_ips: List[str] = self.get_private_client_ips()
        if private_client_ips:
            # all client ips should belong to the same local network,
            # it doesn't make sense to have ips belonging to different
            # networks in the config file!
            ip = private_client_ips[0]
        else:
            ip = self.flow.saddr

        self.is_localnet_set = True
        return utils.get_cidr_of_private_ip(ip)

    def handle_setting_local_net(self):
        """
        stores the local network if possible
        """
        if not self.should_set_localnet():
            return

        local_net: str = self.get_local_net()
        self.print(f"Used local network: {green(local_net)}")
        self.db.set_local_network(local_net)

    def should_stop(self):
        """
        overrides Imodule's should_stop()
        the common Imodule's should_stop() stop when there's no msg in
        each channel and the termination event is set
        since this module has no channels, that common should_stop()
        returns true here as soon as the termination event is set!
        the purpose of this is to not shutdown profiler as soon as the
        termination event is set by the process_manager.py
        """
        return False

    def get_msg_from_input_proc(self):
        # ALYA, DO NOT REMOVE THIS CHECK
        # without it, there's no way this module will know it's
        # time to stop and no new flows are coming
        try:
            # this msg can be a str only when it's a 'stop' msg indicating
            # that this module should stop
            return self.profiler_queue.get(timeout=1, block=False)
        except queue.Empty:
            return
        except Exception:
            # ValueError is raised when the queue is closed
            return

    def pre_main(self):
        utils.drop_root_privs()
        self.print(f"Used client IPs: {green(str(self.client_ips))}")

    def main(self):
        while True:
            msg = self.get_msg_from_input_proc()
            if self.is_stop_msg(msg):
                # 1 indicates an error then shutdown gracefully is called
                return 1
            if not msg:
                # wait for msgs
                continue

            line: dict = msg["line"]
            input_type: str = msg["input_type"]
            # total_flows: int = msg.get("total_flows", 0)

            # TODO who is putting this True here?
            if line is True:
                continue

            # Received new input data
            self.print(f"< Received Line: {line}", 2, 0)
            self.rec_lines += 1

            # self.input_type is set only once by define_separator
            # once we know the type, no need to check each line for it
            if not self.input_type:
                # Find the type of input received
                self.input_type = self.define_separator(line, input_type)

            # What type of input do we have?
            if not self.input_type:
                # the above define_type can't define the type of input
                self.print("Can't determine input type.")
                return False

            # only create the input obj once,
            # the rest of the flows will use the same input handler
            if not hasattr(self, "input"):
                self.input = SUPPORTED_INPUT_TYPES[self.input_type]()

            # get the correct input type class and process the line based on it
            try:
                self.flow = self.input.process_line(line)
                if self.flow:
                    self.add_flow_to_profile()
                    self.handle_setting_local_net()
                    self.db.increment_processed_flows()
            except Exception as e:
                self.print(
                    f"Problem processing line {line}. " f"Line discarded. {e}",
                    0,
                    1,
                )
                self.flow = False

            # listen on this channel in case whitelist.conf is changed,
            # we need to process the new changes
            if self.get_msg("reload_whitelist"):
                # if whitelist.conf is edited using pycharm
                # a msg will be sent to this channel on every keypress,
                # because pycharm saves file automatically
                # otherwise this channel will get a msg only when
                # whitelist.conf is modified and saved to disk
                self.whitelist.update()

        return 1
