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
# Contact: eldraco@gmail.com, sebastian.garcia@agents.fel.cvut.cz, stratosphere@aic.fel.cvut.cz
from slips_files.common.imports import *

from slips_files.core.helpers.flow_parser import FlowParser
from slips_files.core.helpers.symbols_handler import SymbolHandler

from datetime import datetime
from slips_files.core.helpers.whitelist import Whitelist
from dataclasses import asdict
import json
import sys
import ipaddress
import traceback
from slips_files.common.abstracts.core import ICore
from pprint import pp

from slips_files.core.input_profilers.argus import Argus
from slips_files.core.input_profilers.nfdump import Nfdump
from slips_files.core.input_profilers.suricata import Suricata
from slips_files.core.input_profilers.zeek import ZeekJSON, ZeekTabs

SUPPORTED_INPUT_TYPES = {
    'zeek': ZeekJSON,
    'argus': Argus,
    'argus-tabs': Argus,
    'suricata': Suricata,
    'zeek-tabs': ZeekTabs,
    'nfdump': Nfdump,
}
SEPARATORS = {
    'zeek': '',
    'suricata': '',
    'nfdump': ',',
    'argus': ',',
    'zeek-tabs': '\t',
    'argus-tabs': '\t'
}

class Profiler(ICore):
    """A class to create the profiles for IPs"""
    name = 'Profiler'

    def init(self, profiler_queue=None):
        # every line put in this queue should be profiled
        self.profiler_queue = profiler_queue
        self.timeformat = None
        self.input_type = False
        self.whitelisted_flows_ctr = 0
        self.rec_lines = 0
        self.whitelist = Whitelist(self.db)
        # Read the configuration
        self.read_configuration()
        self.symbol = SymbolHandler(self.output_dir,
                                    self.redis_port,
                                    self.db)
        # there has to be a timeout or it will wait forever and never receive a new line
        self.timeout = 0.0000001
        self.c1 = self.db.subscribe('reload_whitelist')
        self.channels = {
            'reload_whitelist': self.c1,
        }



    def read_configuration(self):
        conf = ConfigParser()
        self.whitelist_path = conf.whitelist_path()
        self.timeformat = conf.ts_format()
        self.analysis_direction = conf.analysis_direction()
        self.label = conf.label()
        self.home_net = conf.get_home_network()
        self.width = conf.get_tw_width_as_float()

    def define_type(self, line):
        """
        Try to define the type of input
        Heuristic detection: dict (zeek from pcap of int), json (suricata),
        or csv (argus), or TAB separated (conn.log only from zeek)?
        Bro actually gives us json, but it was already coverted into a dict
        in inputProcess
        Outputs can be: zeek, suricata, argus, zeek-tabs
        """
        try:

            # All lines come as a dict, specifying the name of file and data.
            # Take the data
            try:
                # is data in json format?
                data = line['data']
                file_type = line['type']
            except KeyError:
                self.print('\tData did is not in json format ', 0, 1)
                self.print('\tProblem in define_type()', 0, 1)
                return False

            if file_type in ('stdin', 'external_module'):
                # don't determine the type of line given using define_type(),
                # the type of line is taken directly from the user or from an external module like CYST
                # because define_type expects zeek lines in a certain format and the user won't reformat the zeek line
                # before giving it to slips
                # input type should be defined in the external module
                self.input_type = line['line_type']
                self.separator = SEPARATORS[self.input_type]
                return self.input_type

            # In the case of Zeek from an interface or pcap,
            # the structure is a JSON
            # So try to convert into a dict
            if type(data) == dict:
                try:
                    _ = data['data']
                    # self.separator = '	'
                    self.input_type = 'zeek-tabs'
                except KeyError:
                    self.input_type = 'zeek'

            else:
                # data is a str
                try:
                    # data is a serialized json dict
                    # suricata lines have 'event_type' key, either flow, dns, etc..
                    data = json.loads(data)
                    if data['event_type']:
                        # found the key, is suricata
                        self.input_type = 'suricata'
                except (ValueError, KeyError):
                    data = str(data)
                    # not suricata, data is a tab or comma separated str
                    nr_commas = data.count(',')
                    if nr_commas > 3:
                        # we have 2 files where Commas is the separator
                        # argus comma-separated files, or nfdump lines
                        # in argus, the ts format has a space
                        # in nfdump lines, the ts format doesn't
                        self.input_type = 'nfdump' if ' ' in data.split(',')[0] else 'argus'
                    elif '->' in data or 'StartTime' in data:
                        self.input_type = 'argus-tabs'
                    else:
                        self.input_type = 'zeek-tabs'

            self.separator = SEPARATORS[self.input_type]
            return self.input_type

        except Exception:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(
                f'\tProblem in define_type() line {exception_line}', 0, 1
            )
            self.print(traceback.print_exc(),0,1)
            sys.exit(1)

    def convert_starttime_to_epoch(self):
        try:
            self.flow.starttime = utils.convert_format(self.flow.starttime, 'unixtimestamp')
        except ValueError:
            self.print(f'We can not recognize time format of '
                       f'self.flow.starttime: {self.flow.starttime}', 0, 1)

    def get_rev_profile(self):
        """
        get the profileid and twid of the daddr at the current starttime,
         not the source address
        """
        if not self.flow.daddr:
            # some flows don't have a daddr like software.log flows
            return False, False
        rev_profileid = self.db.getProfileIdFromIP(self.daddr_as_obj)
        if not rev_profileid:
            self.print(
                'The dstip profile was not here... create', 3, 0
            )
            # Create a reverse profileid for managing the data going to the dstip.
            rev_profileid = f'profile_{self.flow.daddr}'
            self.db.addProfile(
                rev_profileid, self.flow.starttime, self.width
            )
            # Try again
            rev_profileid = self.db.getProfileIdFromIP(
                self.daddr_as_obj
            )

        # in the database, Find the id of the tw where the flow belongs.
        rev_twid = self.db.get_timewindow(self.flow.starttime, rev_profileid)
        return rev_profileid, rev_twid

    def add_flow_to_profile(self):
        """
        This is the main function that takes the columns of a flow and does all the magic to
        convert it into a working data in our system.
        It includes checking if the profile exists and how to put the flow correctly.
        It interprets each column
        """
        # try:
        if not hasattr(self, 'flow'):
            #TODO this is a quick fix
            return False

        self.flow_parser = FlowParser(self.db, self.symbol, self.flow)

        if not self.flow_parser.is_supported_flow():
            return False

        self.flow_parser.make_sure_theres_a_uid()
        self.profileid = f'profile_{self.flow.saddr}'
        self.flow_parser.profileid = self.profileid

        try:
            self.saddr_as_obj = ipaddress.ip_address(self.flow.saddr)
            self.daddr_as_obj = ipaddress.ip_address(self.flow.daddr)
        except (ipaddress.AddressValueError, ValueError):
            # Its a mac
            if self.flow.type_ not in ('software', 'weird'):
                # software and weird.log flows are allowed to not have a daddr
                return False

        # Check if the flow is whitelisted and we should not process
        if self.whitelist.is_whitelisted_flow(self.flow):
            if 'conn' in self.flow.type_:
                self.whitelisted_flows_ctr +=1
            return True

        # 5th. Store the data according to the paremeters
        # Now that we have the profileid and twid, add the data from the flow in this tw for this profile
        self.print(f'Storing data in the profile: {self.profileid}', 3, 0)
        self.convert_starttime_to_epoch()
        # For this 'forward' profile, find the id in the database of the tw where the flow belongs.
        self.twid = self.db.get_timewindow(self.flow.starttime, self.profileid)
        self.flow_parser.twid = self.twid

        if self.home_net:
            # Home network is defined in slips.conf. Create profiles for home IPs only
            for network in self.home_net:
                if self.saddr_as_obj in network:
                    # if a new profile is added for this saddr
                    self.db.addProfile(
                        self.profileid, self.flow.starttime, self.width
                    )
                    self.store_features_going_out()

                if (
                    self.analysis_direction == 'all'
                    and self.daddr_as_obj in network
                ):
                    self.handle_in_flows()

        else:
            # home_network param wasn't set in slips.conf
            # Create profiles for all ips we see
            self.db.addProfile(self.profileid, self.flow.starttime, self.width)
            self.store_features_going_out()
            if self.analysis_direction == 'all':
                # No home. Store all
                self.handle_in_flows()

        if self.db.is_cyst_enabled():
            # print the added flow as a form of debugging feedback for
            # the user to know that slips is working
            self.print(pp(asdict(self.flow)))

        return True
        # except Exception:
        #     # For some reason we can not use the output queue here.. check
        #     self.print(
        #         f'Error in Profiler Process add_flow_to_profile (). {traceback.format_exc()}'
        #     ,0,1)
        #     self.print(traceback.print_exc(),0,1)
        #     return False

    def store_features_going_out(self):
        """
        function for adding the features going out of the profile
        """
        cases = {
            'flow': self.flow_parser.handle_conn,
            'conn': self.flow_parser.handle_conn,
            'nfdump': self.flow_parser.handle_conn,
            'argus': self.flow_parser.handle_conn,
            'dns': self.flow_parser.handle_dns,
            'http': self.flow_parser.handle_http,
            'ssl': self.flow_parser.handle_ssl,
            'ssh': self.flow_parser.handle_ssh,
            'notice': self.flow_parser.handle_notice,
            'ftp': self.flow_parser.handle_ftp,
            'smtp': self.flow_parser.handle_smtp,
            'files': self.flow_parser.handle_files,
            'arp': self.flow_parser.handle_arp,
            'dhcp': self.flow_parser.handle_dhcp,
            'software': self.flow_parser.handle_software,
            'weird': self.flow_parser.handle_weird,
            'tunnel': self.flow_parser.handle_tunnel,
        }
        try:
            # call the function that handles this flow
            cases[self.flow.type_]()
        except KeyError:
            for flow in cases:
                if flow in self.flow.type_:
                    cases[flow]()
            return False

        # if the flow type matched any of the ifs above,
        # mark this profile as modified
        self.db.markProfileTWAsModified(self.profileid, self.twid, '')

    def store_features_going_in(self, profileid, twid):
        """
        If we have the all direction set , slips creates profiles for each IP, the src and dst
        store features going our adds the conn in the profileA from IP A -> IP B in the db
        this function stores the reverse of this connection. adds the conn in the profileB from IP B <- IP A
        """
        # self.print(f'Storing features going in for profile {profileid} and tw {twid}')
        if (
            'flow' not in self.flow.type_
            and 'conn' not in self.flow.type_
            and 'argus' not in self.flow.type_
            and 'nfdump' not in self.flow.type_
        ):
            return
        symbol = self.symbol.compute(self.flow, self.twid, 'InTuples')

        # Add the src tuple using the src ip, and dst port
        tupleid = f'{self.saddr_as_obj}-{self.flow.dport}-{self.flow.proto}'
        role = 'Server'
        # create the intuple
        self.db.add_tuple(
            profileid, twid, tupleid, symbol, role, self.flow
        )

        # Add the srcip and srcport
        self.db.add_ips(profileid, twid, self.flow, role)
        port_type = 'Src'
        self.db.add_port(profileid, twid, self.flow, role, port_type)

        # Add the dstport
        port_type = 'Dst'
        self.db.add_port(profileid, twid, self.flow, role, port_type)

        # Add the flow with all the fields interpreted
        self.db.add_flow(
            self.flow,
            profileid=profileid,
            twid=twid,
            label=self.label,
        )
        self.db.markProfileTWAsModified(profileid, twid, '')

    def handle_in_flows(self):
        """
        Adds a flow for the daddr <- saddr connection
        """
        # they are not actual flows to add in slips,
        # they are info about some ips derived by zeek from the flows
        execluded_flows = ('software')
        if self.flow.type_ in execluded_flows:
            return
        rev_profileid, rev_twid = self.get_rev_profile()
        self.store_features_going_in(rev_profileid, rev_twid)

    def shutdown_gracefully(self):
        self.print(f"Stopping. Total lines read: {self.rec_lines}", 0, 1)
        # By default if a process(profiler) is not the creator of the queue(profiler_queue) then on
        # exit it will attempt to join the queue’s background thread.
        # this causes a deadlock
        # to avoid this behaviour we should call cancel_join_thread
        self.profiler_queue.cancel_join_thread()

    def pre_main(self):
        utils.drop_root_privs()

    def main(self):
        while not self.should_stop():
            try:
                msg: dict = self.profiler_queue.get(timeout=3)
                line: str = msg['line']
                total_flows: int = msg.get('total_flows', 0)
            except Exception as e:
                # the queue is empty, which means input proc
                # is done reading flows
                continue

            # TODO who is putting this True here?
            if line == True:
                continue

            if 'stop' in line:
                self.print(f"Stopping profiler process. Number of whitelisted conn flows: "
                           f"{self.whitelisted_flows_ctr}", 2, 0)

                self.shutdown_gracefully()
                self.print(
                    f'Stopping Profiler Process. Received {self.rec_lines} lines '
                    f'({utils.convert_format(datetime.now(), utils.alerts_format)})', 2, 0,
                )
                return 1

            # Received new input data
            self.print(f'< Received Line: {line}', 2, 0)
            self.rec_lines += 1

            if not self.input_type:
                # Find the type of input received
                self.define_type(line)
                # don't init the pbar when given the following input types because
                # we don't know the total flows beforehand
                if self.db.get_input_type() not in ('pcap', 'interface', 'stdin'):
                    # Find the number of flows we're going to receive of input received
                    self.notify_observers({
                        'bar': 'init',
                        'bar_info': {
                            'input_type': self.input_type,
                            'total_flows': total_flows
                        }
                    })

            # What type of input do we have?
            if not self.input_type:
                # the above define_type can't define the type of input
                self.print("Can't determine input type.")
                return False


            # only create the input obj once
            if not hasattr(self, 'input'):
                self.input = SUPPORTED_INPUT_TYPES[self.input_type]()

            # get the correct input type class and process the line based on it
            self.flow = self.input.process_line(line)
            if self.flow:
                self.add_flow_to_profile()

            self.notify_observers({'bar': 'update'})

            # listen on this channel in case whitelist.conf is changed,
            # we need to process the new changes
            if self.get_msg('reload_whitelist'):
                # if whitelist.conf is edited using pycharm
                # a msg will be sent to this channel on every keypress, because pycharm saves file automatically
                # otherwise this channel will get a msg only when whitelist.conf is modified and saved to disk
                self.whitelist.read_whitelist()

        return 1
