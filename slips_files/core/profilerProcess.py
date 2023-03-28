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
from slips_files.core.database.database import __database__
from slips_files.common.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from datetime import datetime, timedelta
from .whitelist import Whitelist
import multiprocessing
import json
import sys
import ipaddress
import traceback
import os
import binascii
import base64
from re import split
from tqdm import tqdm

# Profiler Process
class ProfilerProcess(multiprocessing.Process):
    """A class to create the profiles for IPs and the rest of data"""

    def __init__(
        self, inputqueue, outputqueue, verbose, debug, redis_port
    ):
        self.name = 'Profiler'
        multiprocessing.Process.__init__(self)
        self.inputqueue = inputqueue
        self.outputqueue = outputqueue
        self.timeformat = None
        self.input_type = False
        self.ctr = 0
        self.whitelist = Whitelist(outputqueue, redis_port)
        # Read the configuration
        self.read_configuration()
        __database__.start(redis_port)
        # Set the database output queue
        __database__.setOutputQueue(self.outputqueue)
        self.verbose = verbose
        self.debug = debug
        # there has to be a timeout or it will wait forever and never receive a new line
        self.timeout = 0.0000001
        self.c1 = __database__.subscribe('reload_whitelist')
        self.separators = {
            'zeek': '',
            'suricata': '',
            'nfdump': ',',
            'argus': ',',
            'zeek-tabs': '\t',
            'argus-tabs': '\t'
        }

    def print(self, text, verbose=1, debug=0):
        """
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by taking all the processes into account
        :param verbose:
            0 - don't print
            1 - basic operation/proof of work
            2 - log I/O operations and filenames
            3 - log database/profile/timewindow changes
        :param debug:
            0 - don't print
            1 - print exceptions
            2 - unsupported and unhandled types (cases that may cause errors)
            3 - red warnings that needs examination - developer warnings
        :param text: text to print. Can include format like 'Test {}'.format('here')
        """

        levels = f'{verbose}{debug}'
        self.outputqueue.put(f'{levels}|{self.name}|{text}')

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
        Try to define very fast the type of input
        Heuristic detection: dict (zeek from pcap of int), json (suricata), or csv (argus), or TAB separated (conn.log only from zeek)?
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

            if file_type == 'stdin':
                # don't determine the type of line given using define_type(),
                # the type of line is taken directly from the user
                # because define_type expects zeek lines in a certain format and the user won't reformat the zeek line
                # before giving it to slips
                self.input_type = line['line_type']
                self.separator = self.separators[self.input_type]
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
                        # comma separated str
                        # we have 2 files where Commas is the separator
                        # argus comma-separated files, or nfdump lines
                        # in argus, the ts format has a space
                        # in nfdump lines, the ts format doesn't
                        ts = data.split(',')[0]
                        if ' ' in ts:
                            self.input_type = 'nfdump'
                        else:
                            self.input_type = 'argus'
                    else:
                        # tab separated str
                        # a zeek tab file or a binetflow tab file
                        if '->' in data or 'StartTime' in data:
                            self.input_type = 'argus-tabs'
                        else:
                            self.input_type = 'zeek-tabs'

            self.separator = self.separators[self.input_type]
            return self.input_type

        except Exception as ex:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(
                f'\tProblem in define_type() line {exception_line}', 0, 1
            )
            self.print(traceback.print_exc(),0,1)
            sys.exit(1)

    def define_columns(self, new_line):
        """
        Define the columns for Argus and Zeek-tabs from the line received
        :param new_line: should be the header line of the argus/zeek-tabs file
        """
        # These are the indexes for later fast processing
        line = new_line['data']
        # use null instead of false because 0==False and starttime index
        # won't be adde to the temp_dict at the end of this function
        self.column_idx = {
            'starttime': 'null',
            'endtime': 'null',
            'dur': 'null',
            'proto': 'null',
            'appproto': 'null',
            'saddr': 'null',
            'sport': 'null',
            'dir': 'null',
            'daddr': 'null',
            'dport': 'null',
            'state': 'null',
            'pkts': 'null',
            'spkts': 'null',
            'dpkts': 'null',
            'bytes': 'null',
            'sbytes': 'null',
            'dbytes': 'null',
        }

        try:
            nline = line.strip().split(self.separator)
            for field in nline:
                if 'time' in field.lower():
                    self.column_idx['starttime'] = nline.index(field)
                elif 'dur' in field.lower():
                    self.column_idx['dur'] = nline.index(field)
                elif 'proto' in field.lower():
                    self.column_idx['proto'] = nline.index(field)
                elif 'srca' in field.lower():
                    self.column_idx['saddr'] = nline.index(field)
                elif 'sport' in field.lower():
                    self.column_idx['sport'] = nline.index(field)
                elif 'dir' in field.lower():
                    self.column_idx['dir'] = nline.index(field)
                elif 'dsta' in field.lower():
                    self.column_idx['daddr'] = nline.index(field)
                elif 'dport' in field.lower():
                    self.column_idx['dport'] = nline.index(field)
                elif 'state' in field.lower():
                    self.column_idx['state'] = nline.index(field)
                elif 'totpkts' in field.lower():
                    self.column_idx['pkts'] = nline.index(field)
                elif 'totbytes' in field.lower():
                    self.column_idx['bytes'] = nline.index(field)
                elif 'srcbytes' in field.lower():
                    self.column_idx['sbytes'] = nline.index(field)
                elif 'srcpkts' in field.lower():
                    self.column_idx['spkts'] = nline.index(field)
                elif 'dstpkts' in field.lower():
                    self.column_idx['dpkts'] = nline.index(field)
            # Some of the fields were not found probably,
            # so just delete them from the index if their value is False.
            # If not we will believe that we have data on them
            # We need a temp dict because we can not change the size of dict while analyzing it
            temp_dict = {}
            for k, e in self.column_idx.items():
                if e == 'null':
                    continue
                temp_dict[k] = e
            self.column_idx = temp_dict
            return self.column_idx
        except Exception as ex:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(
                f'\tProblem in define_columns() line {exception_line}', 0, 1
            )
            self.print(traceback.print_exc(),0,1)
            sys.exit(1)

    def process_zeek_tabs_input(self, new_line: str) -> None:
        """
        Process the tab line from zeek.
        """
        line = new_line['data']
        line = line.rstrip('\n')
        # the data is either \t separated or space separated
        if '\t' in line:
            line = line.split('\t')
        else:
            # zeek files that are space separated are either separated by 2 or 3 spaces so we can't use python's split()
            # using regex split, split line when you encounter more than 2 spaces in a row
            line = split(r'\s{2,}', line)


        # Generic fields in Zeek
        self.column_values: dict = {}
        # We need to set it to empty at the beginning so any new flow has
        # the key 'type'
        self.column_values['type'] = ''
        try:
            self.column_values['starttime'] = utils.convert_to_datetime(line[0])
        except IndexError:
            self.column_values['starttime'] = ''

        try:
            self.column_values['uid'] = line[1]
        except IndexError:
            self.column_values['uid'] = False
        try:
            self.column_values['saddr'] = line[2]
        except IndexError:
            self.column_values['saddr'] = ''
        try:
            self.column_values['daddr'] = line[4]
        except IndexError:
            self.column_values['daddr'] = ''

        if 'conn.log' in new_line['type']:
            self.column_values['type'] = 'conn'
            try:
                self.column_values['dur'] = float(line[8])
            except (IndexError, ValueError):
                self.column_values['dur'] = 0
            self.column_values['endtime'] = str(
                self.column_values['starttime']
            ) + str(timedelta(seconds=self.column_values['dur']))
            self.column_values['proto'] = line[6]
            try:
                self.column_values['appproto'] = line[7]
            except IndexError:
                # no service recognized
                self.column_values['appproto'] = ''
            try:
                self.column_values['sport'] = line[3]
            except IndexError:
                self.column_values['sport'] = ''
            self.column_values['dir'] = '->'
            try:
                self.column_values['dport'] = line[5]
            except IndexError:
                self.column_values['dport'] = ''
            try:
                self.column_values['state'] = line[11]
            except IndexError:
                self.column_values['state'] = ''
            try:
                self.column_values['spkts'] = float(line[16])
            except (IndexError, ValueError):
                self.column_values['spkts'] = 0
            try:
                self.column_values['dpkts'] = float(line[18])
            except (IndexError, ValueError):
                self.column_values['dpkts'] = 0
            self.column_values['pkts'] = (
                self.column_values['spkts'] + self.column_values['dpkts']
            )
            try:
                self.column_values['sbytes'] = float(line[9])
            except (IndexError, ValueError):
                self.column_values['sbytes'] = 0
            try:
                self.column_values['dbytes'] = float(line[10])
            except (IndexError, ValueError):
                self.column_values['dbytes'] = 0
            self.column_values['bytes'] = (
                self.column_values['sbytes'] + self.column_values['dbytes']
            )
            try:
                self.column_values['state_hist'] = line[15]
            except IndexError:
                self.column_values['state_hist'] = self.column_values['state']

            try:
                self.column_values['smac'] = line[21]
            except IndexError:
                self.column_values['smac'] = ''

            try:
                self.column_values['dmac'] = line[22]
            except IndexError:
                self.column_values['dmac'] = ''

        elif 'dns.log' in new_line['type']:
            self.column_values['type'] = 'dns'
            try:
                self.column_values['query'] = line[9]
            except IndexError:
                self.column_values['query'] = ''
            try:
                self.column_values['qclass_name'] = line[11]
            except IndexError:
                self.column_values['qclass_name'] = ''
            try:
                self.column_values['qtype_name'] = line[13]
            except IndexError:
                self.column_values['qtype_name'] = ''
            try:
                self.column_values['rcode_name'] = line[15]
            except IndexError:
                self.column_values['rcode_name'] = ''
            try:
                answers = line[21]
                if type(answers) == str:
                    # If the answer is only 1, Zeek gives a string
                    # so convert to a list
                    answers = answers.split(',')
                # ignore dns TXT records
                answers = [answer for answer in answers if 'TXT ' not in answer]
                self.column_values['answers'] = answers
            except IndexError:
                self.column_values['answers'] = ''
            try:
                self.column_values['TTLs'] = line[22]
            except IndexError:
                self.column_values['TTLs'] = ''
        elif 'http.log' in new_line['type']:
            self.column_values['type'] = 'http'
            try:
                self.column_values['method'] = line[7]
            except IndexError:
                self.column_values['method'] = ''
            try:
                self.column_values['host'] = line[8]
            except IndexError:
                self.column_values['host'] = ''
            try:
                self.column_values['uri'] = line[9]
            except IndexError:
                self.column_values['uri'] = ''
            try:
                self.column_values['httpversion'] = line[11]
            except IndexError:
                self.column_values['httpversion'] = ''
            try:
                self.column_values['user_agent'] = line[12]
            except IndexError:
                self.column_values['user_agent'] = ''
            try:
                self.column_values['request_body_len'] = line[13]
            except IndexError:
                self.column_values['request_body_len'] = 0
            try:
                self.column_values['response_body_len'] = line[14]
            except IndexError:
                self.column_values['response_body_len'] = 0
            try:
                self.column_values['status_code'] = line[15]
            except IndexError:
                self.column_values['status_code'] = ''
            try:
                self.column_values['status_msg'] = line[16]
            except IndexError:
                self.column_values['status_msg'] = ''
            try:
                self.column_values['resp_mime_types'] = line[28]
            except IndexError:
                self.column_values['resp_mime_types'] = ''
            try:
                self.column_values['resp_fuids'] = line[26]
            except IndexError:
                self.column_values['resp_fuids'] = ''

        elif 'ssl.log' in new_line['type']:
            self.column_values['type'] = 'ssl'
            try:
                self.column_values['sport'] = line[3]
            except IndexError:
                self.column_values['sport'] = ''
            try:
                self.column_values['dport'] = line[5]
            except IndexError:
                self.column_values['dport'] = ''
            try:
                self.column_values['sslversion'] = line[6]
            except IndexError:
                self.column_values['sslversion'] = ''
            try:
                self.column_values['cipher'] = line[7]
            except IndexError:
                self.column_values['cipher'] = ''
            try:
                self.column_values['curve'] = line[8]
            except IndexError:
                self.column_values['curve'] = ''
            try:
                self.column_values['server_name'] = line[9]
            except IndexError:
                self.column_values['server_name'] = ''
            try:
                self.column_values['resumed'] = line[10]
            except IndexError:
                self.column_values['resumed'] = ''
            try:
                self.column_values['established'] = line[13]
            except IndexError:
                self.column_values['established'] = ''
            try:
                self.column_values['cert_chain_fuids'] = line[14]
            except IndexError:
                self.column_values['cert_chain_fuids'] = ''
            try:
                self.column_values['client_cert_chain_fuids'] = line[15]
            except IndexError:
                self.column_values['client_cert_chain_fuids'] = ''
            try:
                self.column_values['subject'] = line[16]
            except IndexError:
                self.column_values['subject'] = ''
            try:
                self.column_values['issuer'] = line[17]
            except IndexError:
                self.column_values['issuer'] = ''
            try:
                self.column_values['validation_status'] = line[20]
            except IndexError:
                self.column_values['validation_status'] = ''

            try:
                self.column_values['ja3'] = line[21]
            except IndexError:
                self.column_values['ja3'] = ''
            try:
                self.column_values['ja3s'] = line[22]
            except IndexError:
                self.column_values['ja3s'] = ''

            try:
                self.column_values['is_DoH'] = line[23]
            except IndexError:
                self.column_values['is_DoH'] = ''

        elif 'ssh.log' in new_line['type']:
            self.column_values['type'] = 'ssh'
            try:
                self.column_values['version'] = line[6]
            except IndexError:
                self.column_values['version'] = ''
            # Zeek can put in column 7 the auth success if it has one
            # or the auth attempts only. However if the auth
            # success is there, the auth attempts are too.
            if 'T' in line[7]:
                try:
                    self.column_values['auth_success'] = line[7]
                except IndexError:
                    self.column_values['auth_success'] = ''
                try:
                    self.column_values['auth_attempts'] = line[8]
                except IndexError:
                    self.column_values['auth_attempts'] = ''
                try:
                    self.column_values['client'] = line[10]
                except IndexError:
                    self.column_values['client'] = ''
                try:
                    self.column_values['server'] = line[11]
                except IndexError:
                    self.column_values['server'] = ''
                try:
                    self.column_values['cipher_alg'] = line[12]
                except IndexError:
                    self.column_values['cipher_alg'] = ''
                try:
                    self.column_values['mac_alg'] = line[13]
                except IndexError:
                    self.column_values['mac_alg'] = ''
                try:
                    self.column_values['compression_alg'] = line[14]
                except IndexError:
                    self.column_values['compression_alg'] = ''
                try:
                    self.column_values['kex_alg'] = line[15]
                except IndexError:
                    self.column_values['kex_alg'] = ''
                try:
                    self.column_values['host_key_alg'] = line[16]
                except IndexError:
                    self.column_values['host_key_alg'] = ''
                try:
                    self.column_values['host_key'] = line[17]
                except IndexError:
                    self.column_values['host_key'] = ''
            elif 'T' not in line[7]:
                self.column_values['auth_success'] = ''
                try:
                    self.column_values['auth_attempts'] = line[7]
                except IndexError:
                    self.column_values['auth_attempts'] = ''
                try:
                    self.column_values['client'] = line[9]
                except IndexError:
                    self.column_values['client'] = ''
                try:
                    self.column_values['server'] = line[10]
                except IndexError:
                    self.column_values['server'] = ''
                try:
                    self.column_values['cipher_alg'] = line[11]
                except IndexError:
                    self.column_values['cipher_alg'] = ''
                try:
                    self.column_values['mac_alg'] = line[12]
                except IndexError:
                    self.column_values['mac_alg'] = ''
                try:
                    self.column_values['compression_alg'] = line[13]
                except IndexError:
                    self.column_values['compression_alg'] = ''
                try:
                    self.column_values['kex_alg'] = line[14]
                except IndexError:
                    self.column_values['kex_alg'] = ''
                try:
                    self.column_values['host_key_alg'] = line[15]
                except IndexError:
                    self.column_values['host_key_alg'] = ''
                try:
                    self.column_values['host_key'] = line[16]
                except IndexError:
                    self.column_values['host_key'] = ''
        elif 'irc' in new_line['type']:
            self.column_values['type'] = 'irc'
        elif 'long' in new_line['type']:
            self.column_values['type'] = 'long'
        elif 'dhcp.log' in new_line['type']:
            self.column_values['type'] = 'dhcp'
            #  daddr in dhcp.log is the server_addr at index 3, not 4 like most log files
            self.column_values['daddr'] = line[3]
            self.column_values['client_addr'] = line[2]   # the same as saddr
            self.column_values['server_addr'] = line[3]
            self.column_values['mac'] = line[4]   # this is the client mac
            self.column_values['host_name'] = line[5]
            self.column_values['requested_addr'] = line[8]
            self.column_values['saddr'] = self.column_values['client_addr']
            self.column_values['daddr'] = self.column_values['server_addr']
        elif 'dce_rpc' in new_line['type']:
            self.column_values['type'] = 'dce_rpc'
        elif 'dnp3' in new_line['type']:
            self.column_values['type'] = 'dnp3'
        elif 'ftp' in new_line['type']:
            self.column_values['type'] = 'ftp'
            self.column_values['used_port'] = line[17]
        elif 'kerberos' in new_line['type']:
            self.column_values['type'] = 'kerberos'
        elif 'mysql' in new_line['type']:
            self.column_values['type'] = 'mysql'
        elif 'modbus' in new_line['type']:
            self.column_values['type'] = 'modbus'
        elif 'ntlm' in new_line['type']:
            self.column_values['type'] = 'ntlm'
        elif 'rdp' in new_line['type']:
            self.column_values['type'] = 'rdp'
        elif 'sip' in new_line['type']:
            self.column_values['type'] = 'sip'
        elif 'smb_cmd' in new_line['type']:
            self.column_values['type'] = 'smb_cmd'
        elif 'smb_files' in new_line['type']:
            self.column_values['type'] = 'smb_files'
        elif 'smb_mapping' in new_line['type']:
            self.column_values['type'] = 'smb_mapping'
        elif 'smtp.log' in new_line['type']:
            # "ts uid id.orig_h id.orig_p id.resp_h id.resp_p trans_depth helo mailfrom
            # rcptto date from to reply_to msg_id in_reply_to subject x_originating_ip
            # first_received second_received last_reply path user_agent tls fuids is_webmail"
            self.column_values['type'] = 'smtp'
            self.column_values['last_reply'] = line[20]
        elif 'socks.log' in new_line['type']:
            self.column_values['type'] = 'socks'
        elif 'syslog.log' in new_line['type']:
            self.column_values['type'] = 'syslog'
        elif 'tunnel.log' in new_line['type']:
            self.column_values['type'] = 'tunnel'
        elif 'notice.log' in new_line['type']:
            # fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	fuid	file_mime_type	file_desc
            # proto	note	msg	sub	src	dst	p	n	peer_descr	actions	suppress_for
            self.column_values['type'] = 'notice'
            # portscan notices don't have id.orig_h or id.resp_h fields, instead they have src and dst
            if self.column_values['saddr'] == '-':
                try:
                    self.column_values['saddr'] = line[13]   #  src field
                except IndexError:
                    # line doesn't have a p field
                    # keep it - as it is
                    pass

            if self.column_values['daddr'] == '-':
                self.column_values['daddr'] = line[14]  #  dst field
                if self.column_values['daddr'] == '-':
                    self.column_values['daddr'] = self.column_values['saddr']

            self.column_values['dport'] = line[5]   # id.orig_p
            if self.column_values['dport'] == '-':
                try:
                    self.column_values['dport'] = line[15]   # p field
                except IndexError:
                    # line doesn't have a p field
                    # keep it - as it is
                    pass
            self.column_values['sport'] = line[3]
            self.column_values['note'] = line[10]
            self.column_values['scanning_ip'] = self.column_values['saddr']
            self.column_values['scanned_port'] = self.column_values['dport']
            self.column_values['msg'] = line[
                11
            ]   # we're looking for self signed certs in this field
        elif 'files.log' in new_line['type']:
            """Parse the fields we're interested in in the files.log file"""
            # the slash before files to distinguish between 'files' in the dir name and file.log
            self.column_values.update(
                {
                    'type': 'files',
                    'uid': line[4],
                    'saddr': line[2],
                    'daddr': line[3],  # rx_hosts
                    'size': line[13],  # downloaded file size
                    'md5': line[19],
                    # used for detecting ssl certs
                    'source': line[5],
                    'analyzers': line[7],
                    'sha1': line[19],
                }
            )

        elif 'arp.log' in new_line['type']:
            self.column_values['type'] = 'arp'
            self.column_values['operation'] = line[1]
            self.column_values['src_mac'] = line[2]
            self.column_values['dst_mac'] = line[3]
            self.column_values['saddr'] = line[4]
            self.column_values['daddr'] = line[5]
            self.column_values['src_hw'] = line[6]
            self.column_values['dst_hw'] = line[7]

        elif 'weird' in new_line['type']:
            self.column_values['type'] = 'weird'
            self.column_values['name'] = line[6]
            self.column_values['addl'] = line[7]


    def process_zeek_input(self, new_line: dict):
        """
        Process one zeek line(new_line) and extract columns
        (parse them into column_values dict) to send to the database
        """
        line = new_line['data']
        file_type = new_line['type']
        # all zeek lines recieved from stdin should be of type conn
        if file_type == 'stdin' and new_line.get('line_type', False) == 'zeek':
            file_type = 'conn'
        else:
            # if the zeek dir given to slips has 'conn' in it's name,
            # slips thinks it's reading a conn file
            # because we use the file path as the file 'type'
            # to fix this, only use the file name as file 'type'
            file_type = file_type.split('/')[-1]

        # Generic fields in Zeek
        self.column_values = {}
        # We need to set it to empty at the beginning so any new flow has the key 'type'
        self.column_values['type'] = ''
        # to set the default value to '' if ts isn't found
        ts = line.get('ts', False)
        if ts:
            self.column_values['starttime'] = utils.convert_to_datetime(ts)
        else:
            self.column_values['starttime'] = ''

        self.column_values['uid'] = line.get('uid', False)
        self.column_values['saddr'] = line.get('id.orig_h', '')
        self.column_values['daddr'] = line.get('id.resp_h', '')

        # Handle each zeek file type separately
        if 'conn' in file_type:
            self.column_values.update(
                {
                    'type': 'conn',
                    'dur': float(line.get('duration', 0)),
                    'endtime': str(self.column_values['starttime'])
                    + str(timedelta(seconds=float(line.get('duration', 0)))),
                    'proto': line['proto'],
                    'appproto': line.get('service', ''),
                    'sport': line.get('id.orig_p', ''),
                    'dport': line.get('id.resp_p', ''),
                    'state': line.get('conn_state', ''),
                    'dir': '->',
                    'spkts': line.get('orig_pkts', 0),
                    'dpkts': line.get('resp_pkts', 0),
                    'sbytes': line.get('orig_bytes', 0),
                    'dbytes': line.get('resp_bytes', 0),
                    'pkts': line.get('orig_pkts', 0)
                    + line.get('resp_pkts', 0),
                    'bytes': line.get('orig_bytes', 0)
                    + line.get('resp_bytes', 0),
                    'state_hist': line.get(
                        'history', line.get('conn_state', '')
                    ),
                    'smac': line.get('orig_l2_addr', ''),
                    'dmac': line.get('resp_l2_addr', ''),
                }
            )
            # orig_bytes: The number of payload bytes the src sent.
            # orig_ip_bytes: the length of the header + the payload

        elif 'dns' in file_type:
            self.column_values.update(
                {
                    'type': 'dns',
                    'query': line.get('query', ''),
                    'qclass_name': line.get('qclass_name', ''),
                    'qtype_name': line.get('qtype_name', ''),
                    'rcode_name': line.get('rcode_name', ''),
                    'answers': line.get('answers', ''),
                    'TTLs': line.get('TTLs', ''),
                }
            )

            if type(self.column_values['answers']) == str:
                # If the answer is only 1, Zeek gives a string
                # so convert to a list
                self.column_values.update(
                    {'answers': [self.column_values['answers']]}
                )

        elif 'http' in file_type:
            self.column_values.update(
                {
                    'type': 'http',
                    'method': line.get('method', ''),
                    'host': line.get('host', ''),
                    'uri': line.get('uri', ''),
                    'httpversion': line.get('version', 0),
                    'user_agent': line.get('user_agent', ''),
                    'request_body_len': line.get('request_body_len', 0),
                    'response_body_len': line.get('response_body_len', 0),
                    'status_code': line.get('status_code', ''),
                    'status_msg': line.get('status_msg', ''),
                    'resp_mime_types': line.get('resp_mime_types', ''),
                    'resp_fuids': line.get('resp_fuids', ''),
                }
            )

        elif 'ssl' in file_type:
            self.column_values.update(
                {
                    'type': 'ssl',
                    'sslversion': line.get('version', ''),
                    'sport': line.get('id.orig_p', ','),
                    'dport': line.get('id.resp_p', ','),
                    'cipher': line.get('cipher', ''),
                    'resumed': line.get('resumed', ''),
                    'established': line.get('established', ''),
                    'cert_chain_fuids': line.get('cert_chain_fuids', ''),
                    'client_cert_chain_fuids': line.get(
                        'client_cert_chain_fuids', ''
                    ),
                    'subject': line.get('subject', ''),
                    'issuer': line.get('issuer', ''),
                    'validation_status': line.get('validation_status', ''),
                    'curve': line.get('curve', ''),
                    'server_name': line.get('server_name', ''),
                    'ja3': line.get('ja3', ''),
                    'is_DoH': line.get('is_DoH', 'false'),
                    'ja3s': line.get('ja3s', ''),
                }
            )

        elif 'ssh' in file_type:
            self.column_values.update(
                {
                    'type': 'ssh',
                    'version': line.get('version', ''),
                    'auth_success': line.get('auth_success', ''),
                    'auth_attempts': line.get('auth_attempts', ''),
                    'client': line.get('client', ''),
                    'server': line.get('server', ''),
                    'cipher_alg': line.get('cipher_alg', ''),
                    'mac_alg': line.get('mac_alg', ''),
                    'compression_alg': line.get('compression_alg', ''),
                    'kex_alg': line.get('kex_alg', ''),
                    'host_key_alg': line.get('host_key_alg', ''),
                    'host_key': line.get('host_key', ''),
                }
            )

        elif 'irc' in file_type:
            self.column_values.update({'type': 'irc'})
        elif 'long' in file_type:
            self.column_values.update({'type': 'long'})
        elif 'dhcp' in file_type:
            self.column_values.update(
                {
                    'type': 'dhcp',
                    'client_addr': line.get('client_addr', ''),
                    'server_addr': line.get('server_addr', ''),
                    'host_name': line.get('host_name', ''),
                    'mac': line.get('mac', ''),  # this is the client mac
                    'saddr': line.get('client_addr', ''),
                    'daddr': line.get('server_addr', ''),
                    'requested_addr': line.get('requested_addr', ''),
                }
            )
            # self.column_values['domain'] = line.get('domain','')
            # self.column_values['assigned_addr'] = line.get('assigned_addr','')

            # Some zeek flow don't have saddr or daddr, seen in dhcp.log and notice.log use the mac address instead
            if (
                self.column_values['saddr'] == ''
                and self.column_values['daddr'] == ''
                and line.get('mac', False)
            ):
                self.column_values.update({'saddr': line.get('mac', '')})

        elif 'dce_rpc' in file_type:
            self.column_values.update({'type': 'dce_rpc'})
        elif 'dnp3' in file_type:
            self.column_values.update({'type': 'dnp3'})
        elif 'ftp' in file_type:
            self.column_values.update(
                {
                    'type': 'ftp',
                    'used_port': line.get('data_channel.resp_p', False),
                }
            )

        elif 'kerberos' in file_type:
            self.column_values.update({'type': 'kerberos'})
        elif 'mysql' in file_type:
            self.column_values.update({'type': 'mysql'})
        elif 'modbus' in file_type:
            self.column_values.update({'type': 'modbus'})
        elif 'ntlm' in file_type:
            self.column_values.update({'type': 'ntlm'})
        elif 'rdp' in file_type:
            self.column_values.update({'type': 'rdp'})
        elif 'sip' in file_type:
            self.column_values.update({'type': 'sip'})
        elif 'smb_cmd' in file_type:
            self.column_values.update({'type': 'smb_cmd'})
        elif 'smb_files' in file_type:
            self.column_values.update({'type': 'smb_files'})
        elif 'smb_mapping' in file_type:
            self.column_values.update({'type': 'smb_mapping'})
        elif 'smtp' in file_type:
            self.column_values.update(
                {'type': 'smtp', 'last_reply': line.get('last_reply', '')}
            )
        elif 'socks' in file_type:
            self.column_values.update({'type': 'socks'})
        elif 'syslog' in file_type:
            self.column_values.update({'type': 'syslog'})
        elif 'tunnel' in file_type:
            self.column_values.update({'type': 'tunnel'})
        elif 'notice' in file_type:
            """Parse the fields we're interested in in the notice.log file"""
            # notice fields: ts - uid id.orig_h(saddr) - id.orig_p(sport) - id.resp_h(daddr) - id.resp_p(dport) - note - msg
            self.column_values.update(
                {
                    'type': 'notice',
                    'sport': line.get('id.orig_p', ''),
                    'dport': line.get('id.resp_p', ''),
                    # self.column_values['scanned_ip'] = line.get('dst', '')
                    'note': line.get('note', ''),
                    'msg': line.get(
                        'msg', ''
                    ),  # we,'re looking for self signed certs in this field
                    'scanned_port': line.get('p', ''),
                    'scanning_ip': line.get('src', ''),
                }
            )

            # portscan notices don't have id.orig_h or id.resp_h fields, instead they have src and dst
            if self.column_values['saddr'] == '':
                self.column_values.update({'saddr': line.get('src', '')})
            if self.column_values['daddr'] == '':
                # set daddr to src for now because the notice that contains portscan doesn't have a dst field and slips needs it to work
                self.column_values.update(
                    {'daddr': line.get('dst', self.column_values['saddr'])}
                )

        elif 'files.log' in file_type:
            """Parse the fields we're interested in in the files.log file"""
            # the slash before files to distinguish between 'files' in the dir name and file.log
            saddr =  line.get('tx_hosts', [''])[0]
            if saddr:
                self.column_values['saddr'] = saddr

            daddr = line.get('rx_hosts', [''])[0]
            if daddr:
                self.column_values['daddr'] = daddr

            self.column_values.update(
                {
                    'type': 'files',
                    'uid': line.get('conn_uids', [''])[0],
                    'size': line.get('seen_bytes', ''),  # downloaded file size
                    'md5': line.get('md5', ''),
                    # used for detecting ssl certs
                    'source': line.get('source', ''),
                    'analyzers': line.get('analyzers', ''),
                    'sha1': line.get('sha1', ''),
                }
            )
        elif 'arp' in file_type:
            self.column_values.update(
                {
                    'type': 'arp',
                    'src_mac': line.get('src_mac', ''),
                    'dst_mac': line.get('dst_mac', ''),
                    'saddr': line.get('orig_h', ''),
                    'daddr': line.get('resp_h', ''),
                    'dst_hw': line.get('resp_hw', ''),
                    'src_hw': line.get('orig_hw', ''),
                    'operation': line.get('operation', ''),
                }
            )
        elif 'software' in file_type:
            software_type = line.get('software_type', '')
            # store info about everything except http:broswer
            # we're already reading browser UA from http.log
            if software_type == 'HTTP::BROWSER':
                return True
            self.column_values.update(
                {
                    'type': 'software',
                    'saddr': line.get('host', ''),
                    'software_type': software_type,
                    'unparsed_version': line.get('unparsed_version', ''),
                    'version.major': line.get('version.major', ''),
                    'version.minor': line.get('version.minor', ''),
                }
            )

        elif 'weird' in file_type:
            self.column_values.update(
                {
                    'type': 'weird',
                    'name': line.get('name', ''),
                    'addl': line.get('addl', ''),
                }
            )
        else:
            return False
        return True

    def process_argus_input(self, new_line):
        """
        Process the line and extract columns for argus
        """
        line = new_line['data']
        self.column_values = {
            'starttime': False,
            'endtime': False,
            'dur': False,
            'proto': False,
            'appproto': False,
            'saddr': False,
            'sport': False,
            'dir': False,
            'daddr': False,
            'dport': False,
            'state': False,
            'pkts': False,
            'spkts': False,
            'dpkts': False,
            'bytes': False,
            'sbytes': False,
            'dbytes': False,
            'type': 'argus',
        }

        nline = line.strip().split(self.separator)
        try:
            self.column_values['starttime'] = utils.convert_to_datetime(
                nline[self.column_idx['starttime']]
            )
        except KeyError:
            pass
        try:
            self.column_values['endtime'] = nline[self.column_idx['endtime']]
        except KeyError:
            pass
        try:
            self.column_values['dur'] = nline[self.column_idx['dur']]
        except KeyError:
            pass
        try:
            self.column_values['proto'] = nline[self.column_idx['proto']]
        except KeyError:
            pass
        try:
            self.column_values['appproto'] = nline[self.column_idx['appproto']]
        except KeyError:
            pass
        try:
            self.column_values['saddr'] = nline[self.column_idx['saddr']]
        except KeyError:
            pass
        try:
            self.column_values['sport'] = nline[self.column_idx['sport']]
        except KeyError:
            pass
        try:
            self.column_values['dir'] = nline[self.column_idx['dir']]
        except KeyError:
            pass
        try:
            self.column_values['daddr'] = nline[self.column_idx['daddr']]
        except KeyError:
            pass
        try:
            self.column_values['dport'] = nline[self.column_idx['dport']]
        except KeyError:
            pass
        try:
            self.column_values['state'] = nline[self.column_idx['state']]
        except KeyError:
            pass
        try:
            self.column_values['pkts'] = int(nline[self.column_idx['pkts']])
        except KeyError:
            pass
        try:
            self.column_values['spkts'] = int(nline[self.column_idx['spkts']])
        except KeyError:
            pass
        try:
            self.column_values['dpkts'] = int(nline[self.column_idx['dpkts']])
        except KeyError:
            pass
        try:
            self.column_values['bytes'] = int(nline[self.column_idx['bytes']])
        except KeyError:
            pass
        try:
            self.column_values['sbytes'] = int(
                nline[self.column_idx['sbytes']]
            )
        except KeyError:
            pass
        try:
            self.column_values['dbytes'] = int(
                nline[self.column_idx['dbytes']]
            )
        except KeyError:
            pass

    def process_nfdump_input(self, new_line):
        """
        Process the line and extract columns for nfdump
        """
        self.separator = ','
        self.column_values = {
            'starttime': False,
            'endtime': False,
            'dur': False,
            'proto': False,
            'appproto': False,
            'saddr': False,
            'sport': False,
            'dir': False,
            'daddr': False,
            'dport': False,
            'state': False,
            'pkts': False,
            'spkts': False,
            'dpkts': False,
            'bytes': False,
            'sbytes': False,
            'dbytes': False,
            'type': 'nfdump',
        }
        # Read the lines fast
        line = new_line['data']
        nline = line.strip().split(self.separator)
        try:
            self.column_values['starttime'] = utils.convert_to_datetime(nline[0])
        except IndexError:
            pass
        try:
            self.column_values['endtime'] = utils.convert_to_datetime(nline[1])
        except IndexError:
            pass
        try:
            self.column_values['dur'] = nline[2]
        except IndexError:
            pass
        try:
            self.column_values['proto'] = nline[7]
        except IndexError:
            pass
        try:
            self.column_values['saddr'] = nline[3]
        except IndexError:
            pass
        try:
            self.column_values['sport'] = nline[5]
        except IndexError:
            pass
        try:
            # Direction: ingress=0, egress=1
            self.column_values['dir'] = nline[22]
        except IndexError:
            pass
        try:
            self.column_values['daddr'] = nline[4]
        except IndexError:
            pass
        try:
            self.column_values['dport'] = nline[6]
        except IndexError:
            pass
        try:
            self.column_values['state'] = nline[8]
        except IndexError:
            pass
        try:
            self.column_values['spkts'] = nline[11]
        except IndexError:
            pass
        try:
            self.column_values['dpkts'] = nline[13]
        except IndexError:
            pass
        try:
            self.column_values['pkts'] = (
                self.column_values['spkts'] + self.column_values['dpkts']
            )
        except IndexError:
            pass
        try:
            self.column_values['sbytes'] = nline[12]
        except IndexError:
            pass
        try:
            self.column_values['dbytes'] = nline[14]
        except IndexError:
            pass
        try:
            self.column_values['bytes'] = (
                self.column_values['sbytes'] + self.column_values['dbytes']
            )
        except IndexError:
            pass

    def process_suricata_input(self, line) -> None:
        """Read suricata json input and store it in column_values"""

        # convert to dict if it's not a dict already
        if type(line) == str:
            # lien is the actual data
            line = json.loads(line)
        else:
            # line is a dict with data and type as keys
            try:
                line = json.loads(line['data'])
            except KeyError:
                # can't find the line!
                return

        self.column_values: dict = {}
        try:
            self.column_values['starttime'] = utils.convert_to_datetime(line['timestamp'])
        # except (KeyError, ValueError):
        except ValueError:
            # Reason for catching ValueError:
            # "ValueError: time data '1900-01-00T00:00:08.511802+0000' does not match format '%Y-%m-%dT%H:%M:%S.%f%z'"
            # It means some flow do not have valid timestamp. It seems to me if suricata does not know the timestamp, it put
            # there this not valid time.
            self.column_values['starttime'] = False
        self.column_values['endtime'] = False
        self.column_values['dur'] = 0
        self.column_values['flow_id'] = line.get('flow_id', False)
        self.column_values['saddr'] = line.get('src_ip', False)
        self.column_values['sport'] = line.get('src_port', False)
        self.column_values['daddr'] = line.get('dest_ip', False)
        self.column_values['dport'] = line.get('dest_port', False)
        self.column_values['proto'] = line.get('proto', False)
        self.column_values['type'] = line.get('event_type', False)
        self.column_values['dir'] = '->'
        self.column_values['appproto'] = line.get('app_proto', False)

        if self.column_values['type']:
            """
            suricata available event_type values:
            -flow
            -tls
            -http
            -dns
            -alert
            -fileinfo
            -stats (only one line - it is conclusion of entire capture)
            """
            if self.column_values['type'] == 'flow':
                # A suricata line of flow type usually has 2 components.
                # 1. flow information
                # 2. tcp information
                if line.get('flow', None):
                    try:
                        # Define time again, because this is line of flow type and
                        # we do not want timestamp but start time.
                        self.column_values['starttime'] = utils.convert_to_datetime(
                            line['flow']['start']
                        )
                    except KeyError:
                        self.column_values['starttime'] = False
                    try:
                        self.column_values['endtime'] = utils.convert_to_datetime(
                            line['flow']['end']
                        )
                    except KeyError:
                        self.column_values['endtime'] = False

                    try:
                        self.column_values['dur'] = (
                            self.column_values['endtime']
                            - self.column_values['starttime']
                        ).total_seconds()
                    except (KeyError, TypeError):
                        self.column_values['dur'] = 0
                    try:
                        self.column_values['spkts'] = line['flow'][
                            'pkts_toserver'
                        ]
                    except KeyError:
                        self.column_values['spkts'] = 0
                    try:
                        self.column_values['dpkts'] = line['flow'][
                            'pkts_toclient'
                        ]
                    except KeyError:
                        self.column_values['dpkts'] = 0

                    self.column_values['pkts'] = (
                        self.column_values['dpkts']
                        + self.column_values['spkts']
                    )

                    try:
                        self.column_values['sbytes'] = line['flow'][
                            'bytes_toserver'
                        ]
                    except KeyError:
                        self.column_values['sbytes'] = 0

                    try:
                        self.column_values['dbytes'] = line['flow'][
                            'bytes_toclient'
                        ]
                    except KeyError:
                        self.column_values['dbytes'] = 0

                    self.column_values['bytes'] = (
                        self.column_values['dbytes']
                        + self.column_values['sbytes']
                    )

                    try:
                        """
                        There are different states in which a flow can be.
                        Suricata distinguishes three flow-states for TCP and two for UDP. For TCP,
                        these are: New, Established and Closed,for UDP only new and established.
                        For each of these states Suricata can employ different timeouts.
                        """
                        self.column_values['state'] = line['flow']['state']
                    except KeyError:
                        self.column_values['state'] = ''
            elif self.column_values['type'] == 'http':
                if line.get('http', None):
                    try:
                        self.column_values['method'] = line['http'][
                            'http_method'
                        ]
                    except KeyError:
                        self.column_values['method'] = ''
                    try:
                        self.column_values['host'] = line['http']['hostname']
                    except KeyError:
                        self.column_values['host'] = ''
                    try:
                        self.column_values['uri'] = line['http']['url']
                    except KeyError:
                        self.column_values['uri'] = ''
                    try:
                        self.column_values['user_agent'] = line['http'][
                            'http_user_agent'
                        ]
                    except KeyError:
                        self.column_values['user_agent'] = ''
                    try:
                        self.column_values['status_code'] = line['http'][
                            'status'
                        ]
                    except KeyError:
                        self.column_values['status_code'] = ''
                    try:
                        self.column_values['httpversion'] = line['http'][
                            'protocol'
                        ]
                    except KeyError:
                        self.column_values['httpversion'] = ''
                    try:
                        self.column_values['response_body_len'] = line['http'][
                            'length'
                        ]
                    except KeyError:
                        self.column_values['response_body_len'] = 0
                    try:
                        self.column_values['request_body_len'] = line['http'][
                            'request_body_len'
                        ]
                    except KeyError:
                        self.column_values['request_body_len'] = 0
                    self.column_values['status_msg'] = ''
                    self.column_values['resp_mime_types'] = ''
                    self.column_values['resp_fuids'] = ''

            elif self.column_values['type'] == 'dns':
                if line.get('dns', None):
                    try:
                        self.column_values['query'] = line['dns']['rdata']
                    except KeyError:
                        self.column_values['query'] = ''
                    try:
                        self.column_values['TTLs'] = line['dns']['ttl']
                    except KeyError:
                        self.column_values['TTLs'] = ''

                    try:
                        self.column_values['qtype_name'] = line['dns'][
                            'rrtype'
                        ]
                    except KeyError:
                        self.column_values['qtype_name'] = ''
                    # can not find in eve.json:
                    self.column_values['qclass_name'] = ''
                    self.column_values['rcode_name'] = ''
                    self.column_values['answers'] = ''
                    if type(self.column_values['answers']) == str:
                        # If the answer is only 1, Zeek gives a string
                        # so convert to a list
                        self.column_values['answers'] = [
                            self.column_values['answers']
                        ]
            elif self.column_values['type'] == 'tls':
                if line.get('tls', None):
                    try:
                        self.column_values['sslversion'] = line['tls'][
                            'version'
                        ]
                    except KeyError:
                        self.column_values['sslversion'] = ''
                    try:
                        self.column_values['subject'] = line['tls']['subject']
                    except KeyError:
                        self.column_values['subject'] = ''
                    try:
                        self.column_values['issuer'] = line['tls']['issuerdn']
                    except KeyError:
                        self.column_values['issuer'] = ''
                    try:
                        self.column_values['server_name'] = line['tls']['sni']
                    except KeyError:
                        self.column_values['server_name'] = ''

                    try:
                        self.column_values['notbefore'] = utils.convert_to_datetime(
                            line['tls']['notbefore']
                        )
                    except KeyError:
                        self.column_values['notbefore'] = ''

                    try:
                        self.column_values['notafter'] = utils.convert_to_datetime(
                            line['tls']['notafter']
                        )
                    except KeyError:
                        self.column_values['notafter'] = ''

            elif self.column_values['type'] == 'alert':
                if line.get('alert', None):
                    try:
                        self.column_values['signature'] = line['alert'][
                            'signature'
                        ]
                    except KeyError:
                        self.column_values['signature'] = ''
                    try:
                        self.column_values['category'] = line['alert'][
                            'category'
                        ]
                    except KeyError:
                        self.column_values['category'] = ''
                    try:
                        self.column_values['severity'] = line['alert'][
                            'severity'
                        ]
                    except KeyError:
                        self.column_values['severity'] = ''
            elif self.column_values['type'] == 'fileinfo':
                try:
                    self.column_values['filesize'] = line['fileinfo']['size']
                except KeyError:
                    self.column_values['filesize'] = ''
            elif self.column_values['type'] == 'ssh':
                try:
                    self.column_values['client'] = line['ssh']['client']['software_version']
                except KeyError:
                    self.column_values['client'] = ''

                try:
                    self.column_values['version'] = line['ssh']['client']['proto_version']
                except KeyError:
                    self.column_values['version'] = ''

                try:
                    self.column_values['server'] = line['ssh']['server']['software_version']
                except KeyError:
                    self.column_values['server'] = ''
                # these fields aren't available in suricata, they're available in zeek only
                self.column_values['auth_success'] = ''
                self.column_values['auth_attempts'] = ''
                self.column_values['cipher_alg'] = ''
                self.column_values['mac_alg'] = ''
                self.column_values['kex_alg'] = ''
                self.column_values['compression_alg'] = ''
                self.column_values['host_key_alg'] = ''
                self.column_values['host_key'] = ''


    def publish_to_new_MAC(self, mac, ip, host_name=False):
        """
        check if mac and ip aren't multicast or link-local
        and publish to new_MAC channel to get more info about the mac
        :param mac: src/dst mac
        :param ip: src/dst ip
        src macs should be passed with srcips, dstmac with dstips
        """
        if not mac or mac in ('00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff'):
            return
        # get the src and dst addresses as objects
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_multicast:
                return
        except ValueError:
            return

        # send the src and dst MAC to IP_Info module to get vendor info about this MAC
        to_send = {
            'MAC': mac,
            'profileid': f'profile_{ip}'
        }
        if host_name:
            to_send.update({
                'host_name': host_name
            })
        __database__.publish('new_MAC', json.dumps(to_send))

    def is_supported_flow(self):

        supported_types = (
            'ssh',
            'ssl',
            'http',
            'dns',
            'conn',
            'flow',
            'argus',
            'nfdump',
            'notice',
            'dhcp',
            'files',
            'arp',
            'ftp',
            'smtp',
            'software',
            'weird'
        )

        if (
            not self.column_values
            or self.column_values['starttime'] is None
            or self.column_values['type'] not in supported_types
        ):
            return False
        return True

    def get_starttime(self):
        ts = self.column_values['starttime']
        try:
            # seconds.
            # make sure starttime is a datetime obj (not a str) so we can get the timestamp
            starttime = utils.convert_format(ts, 'unixtimestamp')
        except ValueError:
            self.print(f'We can not recognize time format: {ts}', 0, 1)
            starttime = ts
        return starttime

    def get_uid(self):
        """
        Generates a uid if none is found
        """
        # This uid check is for when we read things that are not zeek

        uid = self.column_values.get('uid', False)
        if not uid:
            # In the case of other tools that are not Zeek, there is no UID. So we generate a new one here
            # Zeeks uses human-readable strings in Base62 format, from 112 bits usually.
            # We do base64 with some bits just because we need a fast unique way
            uid = base64.b64encode(
                binascii.b2a_hex(os.urandom(9))
            ).decode('utf-8')
        self.column_values['uid'] = uid
        return uid

    def get_rev_profile(self):
        """
        get the profileid and twid of the daddr at the current starttime,
         not the source address
        """
        if not self.daddr:
            # some flows don't have a daddr like software.log flows
            return False, False
        rev_profileid = __database__.getProfileIdFromIP(self.daddr_as_obj)
        if not rev_profileid:
            self.print(
                'The dstip profile was not here... create', 3, 0
            )
            # Create a reverse profileid for managing the data going to the dstip.
            rev_profileid = f'profile_{self.daddr}'
            __database__.addProfile(
                rev_profileid, self.starttime, self.width
            )
            # Try again
            rev_profileid = __database__.getProfileIdFromIP(
                self.daddr_as_obj
            )

        # in the database, Find the id of the tw where the flow belongs.
        rev_twid = __database__.get_timewindow(self.starttime, rev_profileid)
        return rev_profileid, rev_twid

    def publish_to_new_dhcp(self):
        """
        Publish the GW addr in the new_dhcp channel
        """
        epoch_time = utils.convert_format(self.starttime, 'unixtimestamp')
        # this channel is used for setting the default gw ip,
        # only 1 flow is enough for that
        # on home networks, the router serves as a simple DHCP server
        to_send = {
            'uid': self.uid,
            'server_addr': self.column_values.get('server_addr', False),
            'client_addr': self.column_values.get('client_addr', False),
            'requested_addr': self.column_values.get('requested_addr', False),
            'profileid': self.profileid,
            'twid': __database__.get_timewindow(epoch_time, self.profileid),
            'ts': epoch_time
        }
        __database__.publish('new_dhcp', json.dumps(to_send))


    def publish_to_new_software(self):
        """
        Send the whole flow to new_software channel
        """
        epoch_time = utils.convert_format(self.starttime, 'unixtimestamp')
        self.column_values.update(
            {
                'starttime': epoch_time,
                'twid': __database__.get_timewindow(epoch_time, self.profileid),
            }
        )
        __database__.publish(
            'new_software', json.dumps(self.column_values)
        )

    def add_flow_to_profile(self):
        """
        This is the main function that takes the columns of a flow and does all the magic to
        convert it into a working data in our system.
        It includes checking if the profile exists and how to put the flow correctly.
        It interprets each column
        """

        try:
            if not self.is_supported_flow():
                return False

            self.uid = self.get_uid()
            self.flow_type = self.column_values['type']
            self.saddr = self.column_values['saddr']
            self.daddr = self.column_values['daddr']
            self.profileid = f'profile_{self.saddr}'

            try:
                self.saddr_as_obj = ipaddress.ip_address(self.saddr)
                self.daddr_as_obj = ipaddress.ip_address(self.daddr)
            except (ipaddress.AddressValueError, ValueError):
                # Its a mac
                if self.flow_type != 'software':
                    # software flows are allowed to not have a daddr
                    return False

            # Check if the flow is whitelisted and we should not process
            if self.whitelist.is_whitelisted_flow(self.column_values, self.flow_type):
                return True

            # 5th. Store the data according to the paremeters
            # Now that we have the profileid and twid, add the data from the flow in this tw for this profile
            self.print(
                'Storing data in the profile: {}'.format(self.profileid), 3, 0
            )
            self.starttime = self.get_starttime()
            # For this 'forward' profile, find the id in the database of the tw where the flow belongs.
            self.twid = __database__.get_timewindow(self.starttime, self.profileid)

            if self.home_net:
                # Home network is defined in slips.conf. Create profiles for home IPs only
                for network in self.home_net:
                    if self.saddr_as_obj in network:
                        # if a new profile is added for this saddr
                        __database__.addProfile(
                            self.profileid, self.starttime, self.width
                        )
                        self.store_features_going_out()

                    if self.analysis_direction == 'all':
                        # in all mode we create profiled for daddrs too
                        if self.daddr_as_obj in network:
                            self.handle_in_flows()
            else:
                # home_network param wasn't set in slips.conf
                # Create profiles for all ips we see
                __database__.addProfile(self.profileid, self.starttime, self.width)
                self.store_features_going_out()
                if self.analysis_direction == 'all':
                    # No home. Store all
                    self.handle_in_flows()
            return True
        except Exception as ex:
            # For some reason we can not use the output queue here.. check
            self.print(
                f'Error in add_flow_to_profile Profiler Process. {traceback.format_exc()}'
            ,0,1)
            self.print(traceback.print_exc(),0,1)
            return False

    def handle_conn(self):
        role = 'Client'

        tupleid = f'{self.daddr_as_obj}-{self.column_values["dport"]}-{self.column_values["proto"]}'
        # Compute the symbol for this flow, for this TW, for this profile.
        # The symbol is based on the 'letters' of the original Startosphere ips tool
        symbol = self.compute_symbol('OutTuples')
        # Change symbol for its internal data. Symbol is a tuple and is confusing if we ever change the API
        # Add the out tuple
        __database__.add_tuple(
            self.profileid, self.twid, tupleid, symbol, role, self.starttime, self.uid
        )
        # Add the dstip
        __database__.add_ips(
            self.profileid, self.twid, self.daddr_as_obj, self.column_values, role
        )
        # Add the dstport
        port_type = 'Dst'
        __database__.add_port(
            self.profileid,
            self.twid,
            self.daddr_as_obj,
            self.column_values,
            role,
            port_type,
        )
        # Add the srcport
        port_type = 'Src'
        __database__.add_port(
            self.profileid,
            self.twid,
            self.daddr_as_obj,
            self.column_values,
            role,
            port_type,
        )
        # Add the flow with all the fields interpreted
        __database__.add_flow(
            profileid=self.profileid,
            twid=self.twid,
            stime=self.starttime,
            dur=self.column_values['dur'],
            saddr=str(self.saddr_as_obj),
            sport=self.column_values['sport'],
            daddr=str(self.daddr_as_obj),
            dport=self.column_values['dport'],
            proto=self.column_values['proto'],
            state=self.column_values['state'],
            pkts=self.column_values['pkts'],
            allbytes=self.column_values['bytes'],
            spkts=self.column_values['spkts'],
            sbytes=self.column_values['sbytes'],
            appproto=self.column_values['appproto'],
            smac=self.column_values.get('smac',''),
            dmac=self.column_values.get('dmac',''),
            uid=self.uid,
            label=self.label,
            flow_type=self.flow_type,
        )
        self.publish_to_new_MAC(self.column_values.get('smac'), self.saddr)
        self.publish_to_new_MAC(self.column_values.get('dmac'), self.daddr)

    def handle_dns(self):
        __database__.add_out_dns(
            self.profileid,
            self.twid,
            self.column_values['daddr'],
            self.starttime,
            self.flow_type,
            self.uid,
            self.column_values['query'],
            self.column_values['qclass_name'],
            self.column_values['qtype_name'],
            self.column_values['rcode_name'],
            self.column_values['answers'],
            self.column_values['TTLs']
        )

    def handle_http(self):
        __database__.add_out_http(
            self.daddr,
            self.profileid,
            self.twid,
            self.starttime,
            self.flow_type,
            self.uid,
            self.column_values['method'],
            self.column_values['host'],
            self.column_values['uri'],
            self.column_values['httpversion'],
            self.column_values['user_agent'],
            self.column_values['request_body_len'],
            self.column_values['response_body_len'],
            self.column_values['status_code'],
            self.column_values['status_msg'],
            self.column_values['resp_mime_types'],
            self.column_values['resp_fuids'],
        )

    def handle_ssl(self):
        __database__.add_out_ssl(
            self.profileid,
            self.twid,
            self.starttime,
            self.daddr_as_obj,
            self.column_values['dport'],
            self.flow_type,
            self.uid,
            self.column_values['sslversion'],
            self.column_values['cipher'],
            self.column_values['resumed'],
            self.column_values['established'],
            self.column_values['cert_chain_fuids'],
            self.column_values['client_cert_chain_fuids'],
            self.column_values['subject'],
            self.column_values['issuer'],
            self.column_values['validation_status'],
            self.column_values['curve'],
            self.column_values['server_name'],
            self.column_values['ja3'],
            self.column_values['ja3s'],
            self.column_values['is_DoH'],
        )

    def handle_ssh(self):
        __database__.add_out_ssh(
            self.profileid,
            self.twid,
            self.starttime,
            self.flow_type,
            self.uid,
            self.column_values['version'],
            self.column_values['auth_attempts'],
            self.column_values['auth_success'],
            self.column_values['client'],
            self.column_values['server'],
            self.column_values['cipher_alg'],
            self.column_values['mac_alg'],
            self.column_values['compression_alg'],
            self.column_values['kex_alg'],
            self.column_values['host_key_alg'],
            self.column_values['host_key'],
            self.daddr
        )

    def handle_notice(self):
        __database__.add_out_notice(
                self.profileid,
                self.twid,
                self.starttime,
                self.daddr,
                self.column_values['sport'],
                self.column_values['dport'],
                self.column_values['note'],
                self.column_values['msg'],
                self.column_values['scanned_port'],
                self.column_values['scanning_ip'],
                self.uid,
        )

        if 'Gateway_addr_identified' in self.column_values['note']:
            # get the gw addr form the msg
            gw_addr = self.column_values['msg'].split(': ')[-1].strip()
            __database__.set_default_gateway("IP", gw_addr)

    def handle_ftp(self):
        used_port = self.column_values['used_port']
        if used_port:
            __database__.set_ftp_port(used_port)

    def handle_smtp(self):
        to_send = {
                'uid': self.uid,
                'daddr': self.daddr,
                'saddr': self.saddr,
                'profileid': self.profileid,
                'twid': self.twid,
                'ts': self.starttime,
                'last_reply': self.column_values['last_reply'],
            }
        to_send = json.dumps(to_send)
        __database__.publish('new_smtp', to_send)

    def handle_in_flows(self):
        """
        Adds a flow for the daddr <- saddr connection
        """
        # they are not actual flows to add in slips,
        # they are info about some ips derived by zeek from the flows
        execluded_flows = ('software')
        if self.flow_type in execluded_flows:
            return
        rev_profileid, rev_twid = self.get_rev_profile()
        self.store_features_going_in(rev_profileid, rev_twid)

    def handle_software(self):
        __database__.add_software_to_profile(
            self.profileid,
            self.column_values['software_type'],
            self.column_values['version.major'],
            self.column_values['version.minor'],
            self.column_values['uid']
        )
        self.publish_to_new_software()

    def handle_dhcp(self):
        if self.column_values.get('mac', False):
            # send this to ip_info module to get vendor info about this MAC
            self.publish_to_new_MAC(
                self.column_values.get('mac', False),
                self.saddr,
                host_name=(self.column_values.get('host_name', False))
            )
        server_addr = self.column_values.get('server_addr', False)

        if server_addr:
            __database__.store_dhcp_server(server_addr)
            __database__.mark_profile_as_dhcp(self.profileid)

        self.publish_to_new_dhcp()

    def handle_files(self):
        """ Send files.log data to new_downloaded_file channel in vt module to see if it's malicious"""
        to_send = {
            'uid': self.uid,
            'daddr': self.daddr,
            'saddr': self.saddr,
            'size': self.column_values['size'],
            'md5': self.column_values['md5'],
            'sha1': self.column_values['sha1'],
            'analyzers': self.column_values['analyzers'],
            'source': self.column_values['source'],
            'profileid': self.profileid,
            'twid': self.twid,
            'ts': self.starttime,
        }
        to_send = json.dumps(to_send)
        __database__.publish('new_downloaded_file', to_send)

    def handle_arp(self):
        to_send = {
            'uid': self.uid,
            'daddr': self.daddr,
            'saddr': self.saddr,
            'dst_mac': self.column_values['dst_mac'],
            'src_mac': self.column_values['src_mac'],
            'dst_hw': self.column_values['dst_hw'],
            'src_hw': self.column_values['src_hw'],
            'operation': self.column_values['operation'],
            'ts': self.starttime,
            'profileid': self.profileid,
            'twid': self.twid,
        }
        # send to arp module
        to_send = json.dumps(to_send)
        __database__.publish('new_arp', to_send)

        self.publish_to_new_MAC(
            self.column_values['dst_mac'], self.daddr
        )
        self.publish_to_new_MAC(
            self.column_values['src_mac'], self.saddr
        )

        # Add the flow with all the fields interpreted
        __database__.add_flow(
            profileid=self.profileid,
            twid=self.twid,
            stime=self.starttime,
            dur='0',
            saddr=str(self.saddr_as_obj),
            daddr=str(self.daddr_as_obj),
            proto='ARP',
            uid=self.uid,
            flow_type='arp'
        )

    def handle_weird(self):
        """
        handles weird.log zeek flows
        """
        to_send = {
            'uid': self.uid,
            'ts': self.starttime,
            'daddr': self.daddr,
            'saddr': self.saddr,
            'profileid': self.profileid,
            'twid': self.twid,
            'name': self.column_values['name'],
            'addl': self.column_values['addl']
        }
        to_send = json.dumps(to_send)
        __database__.publish('new_weird', to_send)

    def store_features_going_out(self):
        """
        function for adding the features going out of the profile
        """
        cases = {
            'flow': self.handle_conn,
            'conn': self.handle_conn,
            'nfdump': self.handle_conn,
            'argus': self.handle_conn,
            'dns': self.handle_dns,
            'http': self.handle_http,
            'ssl': self.handle_ssl,
            'ssh': self.handle_ssh,
            'notice': self.handle_notice,
            'ftp': self.handle_ftp,
            'smtp': self.handle_smtp,
            'files': self.handle_files,
            'arp': self.handle_arp,
            'dhcp': self.handle_dhcp,
            'software': self.handle_software,
            'weird': self.handle_weird,
        }

        try:
            # call the function that handles this flow
            cases[self.flow_type]()
        except KeyError:
            # does flow contain a part of the key?
            for flow in cases:
                if flow in self.flow_type:
                    cases[flow]()
            else:
                return False

        # if the flow type matched any of the ifs above,
        # mark this profile as modified
        __database__.markProfileTWAsModified(self.profileid, self.twid, '')

    def store_features_going_in(self, profileid, twid):
        """
        If we have the all direction set , slips creates profiles for each IP, the src and dst
        store features going our adds the conn in the profileA from IP A -> IP B in the db
        this function stores the reverse of this connection. adds the conn in the profileB from IP B <- IP A
        """
        role = 'Server'

        # self.print(f'Storing features going in for profile {profileid} and tw {twid}')
        if not (
            'flow' in self.flow_type
            or 'conn' in self.flow_type
            or 'argus' in self.flow_type
            or 'nfdump' in self.flow_type
        ):
            return
        symbol = self.compute_symbol('InTuples')

        # Add the src tuple using the src ip, and dst port
        tupleid = f'{self.daddr_as_obj}-{self.column_values["dport"]}-{self.column_values["proto"]}'
        __database__.add_tuple(
            profileid, twid, tupleid, symbol, role, self.starttime, self.uid
        )

        # Add the srcip and srcport
        __database__.add_ips(
            profileid, twid, self.saddr_as_obj, self.column_values, role
        )
        port_type = 'Src'
        __database__.add_port(
            profileid,
            twid,
            self.daddr_as_obj,
            self.column_values,
            role,
            port_type,
        )

        # Add the dstport
        port_type = 'Dst'
        __database__.add_port(
            profileid,
            twid,
            self.daddr_as_obj,
            self.column_values,
            role,
            port_type,
        )

        # Add the flow with all the fields interpreted
        __database__.add_flow(
            profileid=profileid,
            twid=twid,
            stime=self.starttime,
            dur=self.column_values['dur'],
            saddr=str(self.saddr_as_obj),
            sport=self.column_values['sport'],
            daddr=str(self.daddr_as_obj),
            dport=self.column_values['dport'],
            proto=self.column_values['proto'],
            state=self.column_values['state'],
            pkts=self.column_values['pkts'],
            allbytes=self.column_values['bytes'],
            spkts=self.column_values['spkts'],
            sbytes=self.column_values['sbytes'],
            appproto=self.column_values['appproto'],
            uid=self.uid,
            label=self.label,
            flow_type=self.flow_type
        )
        __database__.markProfileTWAsModified(profileid, twid, '')

    def compute_symbol(
        self,
        tuple_key: str,
    ):
        """
        This function computes the new symbol for the tuple according to the
        original stratosphere ips model of letters
        Here we do not apply any detection model, we just create the letters
        as one more feature twid is the starttime of the flow
        """
        tupleid = f'{self.daddr_as_obj}-{self.column_values["dport"]}-{self.column_values["proto"]}'

        # current_time = self.column_values['starttime']
        current_duration = self.column_values['dur']
        current_size = self.column_values['bytes']

        try:
            current_duration = float(current_duration)
            current_size = int(current_size)
            now_ts = float(self.starttime)
            self.print(
                'Starting compute symbol. Profileid: {}, Tupleid {}, time:{} ({}), dur:{}, size:{}'.format(
                    self.profileid,
                    tupleid,
                    self.twid,
                    type(self.twid),
                    current_duration,
                    current_size,
                ),3,0
            )
            # Variables for computing the symbol of each tuple
            T2 = False
            TD = False
            # Thresholds learnt from Stratosphere ips first version
            # Timeout time, after 1hs
            tto = timedelta(seconds=3600)
            tt1 = float(1.05)
            tt2 = float(1.3)
            tt3 = float(5)
            td1 = float(0.1)
            td2 = float(10)
            ts1 = float(250)
            ts2 = float(1100)

            # Get the time of the last flow in this tuple, and the last last
            # Implicitely this is converting what we stored as 'now' into 'last_ts' and what we stored as 'last_ts' as 'last_last_ts'
            (last_last_ts, last_ts) = __database__.getT2ForProfileTW(
                self.profileid, self.twid, tupleid, tuple_key
            )
            # self.print(f'Profileid: {profileid}. Data extracted from DB. last_ts: {last_ts}, last_last_ts: {last_last_ts}', 0, 5)

            def compute_periodicity(
                now_ts: float, last_ts: float, last_last_ts: float
            ):
                """Function to compute the periodicity"""
                zeros = ''
                if last_last_ts is False or last_ts is False:
                    TD = -1
                    T1 = None
                    T2 = None
                else:
                    # Time diff between the past flow and the past-past flow.
                    T1 = last_ts - last_last_ts
                    # Time diff between the current flow and the past flow.
                    # We already computed this before, but we can do it here again just in case
                    T2 = now_ts - last_ts

                    # We have a time out of 1hs. After that, put 1 number 0 for each hs
                    # It should not happen that we also check T1... right?
                    if T2 >= tto.total_seconds():
                        t2_in_hours = T2 / tto.total_seconds()
                        # Shoud round it. Because we need the time to pass to really count it
                        # For example:
                        # 7100 / 3600 =~ 1.972  ->  int(1.972) = 1
                        for i in range(int(t2_in_hours)):
                            # Add the zeros to the symbol object
                            zeros += '0'

                    # Compute TD
                    try:
                        if T2 >= T1:
                            TD = T2 / T1
                        else:
                            TD = T1 / T2
                    except ZeroDivisionError:
                        TD = 1

                    # Decide the periodic based on TD and the thresholds
                    if TD <= tt1:
                        # Strongly periodicity
                        TD = 1
                    elif TD <= tt2:
                        # Weakly periodicity
                        TD = 2
                    elif TD <= tt3:
                        # Weakly not periodicity
                        TD = 3
                    elif TD > tt3:
                        # Strongly not periodicity
                        TD = 4
                self.print(
                    'Compute Periodicity: Profileid: {}, Tuple: {}, T1={}, T2={}, TD={}'.format(
                        self.profileid, tupleid, T1, T2, TD
                    ),
                    3,
                    0,
                )
                return TD, zeros

            def compute_duration():
                """Function to compute letter of the duration"""
                if current_duration <= td1:
                    return 1
                elif current_duration > td1 and current_duration <= td2:
                    return 2
                elif current_duration > td2:
                    return 3

            def compute_size():
                """Function to compute letter of the size"""
                if current_size <= ts1:
                    return 1
                elif current_size > ts1 and current_size <= ts2:
                    return 2
                elif current_size > ts2:
                    return 3

            def compute_letter():
                """Function to compute letter"""
                # format of this map is as follows
                # {periodicity: {'size' : {duration: letter, duration: letter, etc.}}
                periodicity_map = {
                    # every key in this dict represents a periodicity
                    '-1': {
                        # every key in this dict is a size 1,2,3
                        # 'size' : {duration: letter, diration: letter, etc.}
                        '1': {'1': '1', '2': '2', '3': '3'},
                        '2': {'1': '4', '2': '5', '3': '6'},
                        '3': {'1': '7', '2': '8', '3': '9'},
                    },
                    '1': {
                        '1': {'1': 'a', '2': 'b', '3': 'c'},
                        '2': {'1': 'd', '2': 'e', '3': 'f'},
                        '3': {'1': 'g', '2': 'h', '3': 'i'},
                    },
                    '2': {
                        '1': {'1': 'A', '2': 'B', '3': 'C'},
                        '2': {'1': 'D', '2': 'E', '3': 'F'},
                        '3': {'1': 'G', '2': 'H', '3': 'I'},
                    },
                    '3': {
                        '1': {'1': 'r', '2': 's', '3': 't'},
                        '2': {'1': 'u', '2': 'v', '3': 'w'},
                        '3': {'1': 'x', '2': 'y', '3': 'z'},
                    },
                    '4': {
                        '1': {'1': 'R', '2': 'S', '3': 'T'},
                        '2': {'1': 'U', '2': 'V', '3': 'W'},
                        '3': {'1': 'X', '2': 'Y', '3': 'Z'},
                    },
                }
                return periodicity_map[str(periodicity)][str(size)][
                    str(duration)
                ]

            def compute_timechar():
                """Function to compute the timechar"""
                # self.print(f'Compute timechar. Profileid: {profileid} T2: {T2}', 0, 5)
                if not isinstance(T2, bool):
                    if T2 <= timedelta(seconds=5).total_seconds():
                        return '.'
                    elif T2 <= timedelta(seconds=60).total_seconds():
                        return ','
                    elif T2 <= timedelta(seconds=300).total_seconds():
                        return '+'
                    elif T2 <= timedelta(seconds=3600).total_seconds():
                        return '*'
                    else:
                        # Changed from 0 to ''
                        return ''
                else:
                    return ''

            # Here begins the function's code
            try:
                # Update value of T2
                if now_ts and last_ts:
                    T2 = now_ts - last_ts
                else:
                    T2 = False
                # Are flows sorted?
                if T2 < 0:
                    # Flows are not sorted!
                    # What is going on here when the flows are not ordered?? Are we losing flows?
                    # Put a warning
                    self.print(
                        'Warning: Coming flows are not sorted -> Some time diff are less than zero.',
                        0,
                        2,
                    )
                    pass
            except TypeError:
                T2 = False
            # self.print("T2:{}".format(T2), 0, 1)
            # p = __database__.start_profiling()
            # Compute the rest
            periodicity, zeros = compute_periodicity(
                now_ts, last_ts, last_last_ts
            )
            duration = compute_duration()
            # self.print("Duration: {}".format(duration), 0, 1)
            size = compute_size()
            # self.print("Size: {}".format(size), 0, 1)
            letter = compute_letter()
            # self.print("Letter: {}".format(letter), 0, 1)
            timechar = compute_timechar()
            # self.print("TimeChar: {}".format(timechar), 0, 1)
            self.print(
                'Profileid: {}, Tuple: {}, Periodicity: {}, Duration: {}, Size: {}, Letter: {}. TimeChar: {}'.format(
                    self.profileid,
                    tupleid,
                    periodicity,
                    duration,
                    size,
                    letter,
                    timechar,
                ),
                3,
                0,
            )
            # p = __database__.end_profiling(p)
            symbol = zeros + letter + timechar
            # Return the symbol, the current time of the flow and the T1 value
            return symbol, (last_ts, now_ts)
        except Exception as ex:
            # For some reason we can not use the output queue here.. check
            self.print('Error in compute_symbol in Profiler Process.', 0, 1)
            self.print('{}'.format(traceback.format_exc()), 0, 1)



    def shutdown_gracefully(self):
        # can't use self.name because multiprocessing library adds the child number to the name so it's not const
        __database__.publish('finished_modules', 'Profiler')

    def run(self):
        utils.drop_root_privs()
        rec_lines = 0
        # Main loop function
        while True:
            try:
                line = self.inputqueue.get()
                if 'stop' in line:
                    # if timewindows are not updated for a long time (see at logsProcess.py),
                    # we will stop slips automatically.The 'stop_process' line is sent from logsProcess.py.
                    self.shutdown_gracefully()
                    self.print(
                        'Stopping Profiler Process. Received {} lines ({})'.format(
                            rec_lines,
                            utils.convert_format(datetime.now(), utils.alerts_format),
                        ), 2,0
                    )
                    return True

                # Received new input data
                # Extract the columns smartly
                self.print('< Received Line: {}'.format(line), 2, 0)
                rec_lines += 1

                if not self.input_type:
                    # Find the type of input received
                    self.define_type(line)
                    # Find the number of flows we're going to receive of input received
                    self.outputqueue.put(f"initialize progress bar")

                # What type of input do we have?
                if not self.input_type:
                    # the above define_type can't define the type of input
                    self.print("Can't determine input type.", 5, 6)

                elif self.input_type == 'zeek':
                    # self.print('Zeek line')
                    self.process_zeek_input(line)
                    # Add the flow to the profile
                    self.add_flow_to_profile()

                    self.outputqueue.put(f"update progress bar")

                elif (
                    self.input_type == 'argus'
                    or self.input_type == 'argus-tabs'
                ):
                    # self.print('Argus line')
                    # Argus puts the definition of the columns on the first line only
                    # So read the first line and define the columns
                    try:
                        if '-f' in sys.argv and 'argus' in sys.argv:
                            # argus from stdin
                            self.define_columns(
                                {
                                    'data': "StartTime,Dur,Proto,SrcAddr,Sport,"
                                            "Dir,"
                                            "DstAddr,Dport,State,sTos,dTos,TotPkts,"
                                            "TotBytes,SrcBytes,SrcPkts,Label"
                                }
                            )

                        _ = self.column_idx['starttime']
                        self.process_argus_input(line)
                        # Add the flow to the profile
                        self.add_flow_to_profile()
                        self.outputqueue.put(f"update progress bar")
                    except (AttributeError, KeyError):
                        # Define columns. Do not add this line to profile, its only headers
                        self.define_columns(line)
                elif self.input_type == 'suricata':
                    self.process_suricata_input(line)
                    # Add the flow to the profile
                    self.add_flow_to_profile()
                    self.outputqueue.put(f"update progress bar")
                elif self.input_type == 'zeek-tabs':
                    # self.print('Zeek-tabs line')
                    self.process_zeek_tabs_input(line)
                    # Add the flow to the profile
                    self.add_flow_to_profile()
                    self.outputqueue.put(f"update progress bar")
                elif self.input_type == 'nfdump':
                    self.process_nfdump_input(line)
                    self.add_flow_to_profile()
                    self.outputqueue.put(f"update progress bar")
                else:
                    self.print("Can't recognize input file type.")
                    return False



                # listen on this channel in case whitelist.conf is changed, we need to process the new changes
                message = __database__.get_message(self.c1)
                if message and message['data'] == 'stop_process':
                    self.shutdown_gracefully()
                    return True
                if utils.is_msg_intended_for(message, 'reload_whitelist'):
                    # if whitelist.conf is edited using pycharm
                    # a msg will be sent to this channel on every keypress, because pycharm saves file automatically
                    # otherwise this channel will get a msg only when whitelist.conf is modified and saved to disk
                    self.whitelist.read_whitelist()

            except KeyboardInterrupt:
                self.shutdown_gracefully()
                return True
            except Exception as ex:
                exception_line = sys.exc_info()[2].tb_lineno
                self.print(
                    f'Error. Stopped Profiler Process. Received {rec_lines} '
                    f'lines', 0, 1,
                )
                self.print(
                    f'\tProblem with Profiler Process. line '
                    f'{exception_line}', 0, 1,
                )
                self.print(traceback.format_exc())
                return True
