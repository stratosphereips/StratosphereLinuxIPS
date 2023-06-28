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

from slips_files.core.flows.zeek import Conn, DNS, HTTP, SSL, SSH, DHCP, FTP
from slips_files.core.flows.zeek import Files, ARP, Weird, SMTP, Tunnel, Notice, Software
from slips_files.core.flows.argus import ArgusConn
from slips_files.core.flows.nfdump import NfdumpConn
from slips_files.core.flows.suricata import SuricataFlow, SuricataHTTP, SuricataDNS
from slips_files.core.flows.suricata import SuricataFile,  SuricataTLS, SuricataSSH

from datetime import datetime, timedelta
from slips_files.core.helpers.whitelist import Whitelist
from dataclasses import asdict
import json
import sys
import ipaddress
import traceback
import os
import binascii
import base64
from re import split
from slips_files.common.abstracts import Core
from pprint import pp

# Profiler Process
class ProfilerProcess(Core):
    """A class to create the profiles for IPs and the rest of data"""
    name = 'Profiler'

    def init(self, profiler_queue=None):
        # every line put in this queue should be profiled
        self.profiler_queue = profiler_queue
        self.timeformat = None
        self.input_type = False
        self.whitelisted_flows_ctr = 0
        self.rec_lines = 0
        self.whitelist = Whitelist(self.output_queue, self.db)
        # Read the configuration
        self.read_configuration()
        # there has to be a timeout or it will wait forever and never receive a new line
        self.timeout = 0.0000001
        self.c1 = self.db.subscribe('reload_whitelist')
        self.channels = {
            'reload_whitelist': self.c1,
        }

        self.separators = {
            'zeek': '',
            'suricata': '',
            'nfdump': ',',
            'argus': ',',
            'zeek-tabs': '\t',
            'argus-tabs': '\t'
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

            if file_type in ('stdin', 'external_module'):
                # don't determine the type of line given using define_type(),
                # the type of line is taken directly from the user or from an external module like CYST
                # because define_type expects zeek lines in a certain format and the user won't reformat the zeek line
                # before giving it to slips
                # input type should be defined in the external module
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
                        # we have 2 files where Commas is the separator
                        # argus comma-separated files, or nfdump lines
                        # in argus, the ts format has a space
                        # in nfdump lines, the ts format doesn't
                        self.input_type = 'nfdump' if ' ' in data.split(',')[0] else 'argus'
                    elif '->' in data or 'StartTime' in data:
                        self.input_type = 'argus-tabs'
                    else:
                        self.input_type = 'zeek-tabs'

            self.separator = self.separators[self.input_type]
            return self.input_type

        except Exception:
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
        self.column_idx = {}
        # these are the fields as slips understands them {original_field_name, slips_field_name}
        supported_fields = {
                'time': 'starttime',
                'endtime':'endtime',
                'appproto': 'appproto',
                'dur':'dur',
                'proto':'proto',
                'srca':'saddr',
                'sport':'sport',
                'dir':'dir',
                'dsta':'daddr',
                'dport':'dport',
                'state':'state',
                'totpkts':'pkts',
                'totbytes':'bytes',
                'srcbytes':'sbytes',
                'dstbytes':'dbytes',
                'srcpkts':'spkts',
                'dstpkts':'dpkts',
            }
        try:
            nline = line.strip().split(self.separator)
            # parse the given nline, and try to map the fields we find to the fields slips
            # undertsands from the dict above.
            for field in nline:
                for original_field, slips_field in supported_fields.items():
                    if original_field in field.lower():
                        # found 1 original field that slips supports. store its' slips
                        # equivalent name and index in the column_index
                        self.column_idx[slips_field] = nline.index(field)
                        break

            return self.column_idx
        except Exception:
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
        # zeek files that are space separated are either separated by 2 or 3 spaces so we can't use python's split()
        # using regex split, split line when you encounter more than 2 spaces in a row
        line = line.split('\t') if '\t' in line else split(r'\s{2,}', line)

        if ts := line[0]:
            starttime = utils.convert_to_datetime(ts)
        else:
            starttime = ''

        def get_value_at(index: int, default_=''):
            try:
                val = line[index]
                return default_ if val == '-' else val
            except IndexError:
                return default_

        uid = get_value_at(1)
        saddr = get_value_at(2, '')
        saddr = get_value_at(3, '')

        if 'conn.log' in new_line['type']:
            self.flow: Conn = Conn(
                starttime,
                get_value_at(1, False),
                get_value_at(2),
                get_value_at(4),

                float(get_value_at(8, 0)),

                get_value_at(6, False),
                get_value_at(7),

                int(get_value_at(3)),
                int(get_value_at(5)),

                int(get_value_at(16, 0)),
                int(get_value_at(18, 0)),

                int(get_value_at(9, 0)),
                int(get_value_at(10, 0)),

                get_value_at(21),
                get_value_at(22),

                get_value_at(11),
                get_value_at(15),
            )


        elif 'dns.log' in new_line['type']:
            self.flow: DNS = DNS(
                starttime,
                get_value_at(1, False),
                get_value_at(2),
                get_value_at(4),

                get_value_at(9),

                get_value_at(11),
                get_value_at(13),
                get_value_at(15),

                get_value_at(21),
                get_value_at(22),
            )

        elif 'http.log' in new_line['type']:
            self.flow: HTTP = HTTP(
                starttime,
                get_value_at(1, False),
                get_value_at(2),
                get_value_at(4),

                get_value_at(7),
                get_value_at(8),
                get_value_at(9),

                get_value_at(11),
                get_value_at(12),

                int(get_value_at(13, 0)),
                int(get_value_at(14, 0)),

                get_value_at(15),
                get_value_at(16),

                get_value_at(28),
                get_value_at(26),

            )

        elif 'ssl.log' in new_line['type']:
            self.flow: SSL = SSL(
                starttime,
                get_value_at(1, False),
                get_value_at(2),
                get_value_at(4),

                get_value_at(6),
                get_value_at(3),
                get_value_at(5),

                get_value_at(7),
                get_value_at(10),

                get_value_at(13),
                get_value_at(14),
                get_value_at(15),

                get_value_at(16),

                get_value_at(17),
                get_value_at(20),
                get_value_at(8),
                get_value_at(9),

                get_value_at(21),
                get_value_at(22),
                get_value_at(23),
            )

        elif 'ssh.log' in new_line['type']:
            # Zeek can put in column 7 the auth success if it has one
            # or the auth attempts only. However if the auth
            # success is there, the auth attempts are too.
            auth_success = get_value_at(7)
            if 'T' in auth_success:
                self.flow: SSH = SSH(
                    starttime,
                    get_value_at(1, False),
                    get_value_at(2),
                    get_value_at(4),

                    get_value_at(6),
                    get_value_at(7),
                    get_value_at(8),

                    get_value_at(10),
                    get_value_at(11),
                    get_value_at(12),
                    get_value_at(13),

                    get_value_at(14),
                    get_value_at(15),

                    get_value_at(16),
                    get_value_at(17),
                )
            else:
                self.flow: SSH = SSH(
                    starttime,
                    get_value_at(1, False),
                    get_value_at(2),
                    get_value_at(4),

                    get_value_at(6),
                    '',
                    get_value_at(7),

                    get_value_at(9),
                    get_value_at(10),
                    get_value_at(11),
                    get_value_at(12),

                    get_value_at(13),
                    get_value_at(14),

                    get_value_at(15),
                    get_value_at(16),
                )
        elif 'dhcp.log' in new_line['type']:
            self.flow: DHCP = DHCP(
                starttime,
                get_value_at(1, False),
                get_value_at(2),
                get_value_at(3),   #  daddr in dhcp.log is the server_addr at index 3 not 4 like most log files

                get_value_at(2), # client_addr is the same as saddr
                get_value_at(3),
                get_value_at(5),

                get_value_at(4),
                get_value_at(8),

            )
        elif 'smtp.log' in new_line['type']:
            self.flow: SMTP = SMTP(
                starttime,
                get_value_at(1, False),
                get_value_at(2),
                get_value_at(4),

                get_value_at(20)
            )
        elif 'tunnel.log' in new_line['type']:
            self.flow: Tunnel = Tunnel(
                starttime,
                get_value_at(1, False),
                get_value_at(2),
                get_value_at(4),

                get_value_at(3),
                get_value_at(5),

                get_value_at(6),
                get_value_at(7),

            )
        elif 'notice.log' in new_line['type']:
            # portscan notices don't have id.orig_h or id.resp_h fields,
            # instead they have src and dst
            self.flow: Notice = Notice(
                starttime,
                get_value_at(1, False),
                get_value_at(13, '-'),    #  src field
                get_value_at(4),

                get_value_at(3),
                get_value_at(5, ''),


                get_value_at(10), # note
                get_value_at(11), # msg

                get_value_at(15), # scanned_port
                get_value_at(13, '-'), # scanning_ip

                get_value_at(14), # dst

            )
        elif 'files.log' in new_line['type']:
            self.flow: Files = Files(
                starttime,
                get_value_at(4, False),
                get_value_at(2),
                get_value_at(3),

                get_value_at(13),
                get_value_at(19),

                get_value_at(5),
                get_value_at(7),
                get_value_at(19),

                get_value_at(2),
                get_value_at(3),
            )
        elif 'arp.log' in new_line['type']:
            self.flow: ARP = ARP(
                starttime,
                get_value_at(1, False),
                get_value_at(4),
                get_value_at(5),

                get_value_at(2),
                get_value_at(3),

                get_value_at(6),
                get_value_at(7),

                get_value_at(1),
            )

        elif 'weird' in new_line['type']:
            self.flow: Weird = Weird(
                starttime,
                get_value_at(1, False),
                get_value_at(2),
                get_value_at(4),

                get_value_at(6),
                get_value_at(7),
            )
        else:
            return False
        return True

    def process_zeek_input(self, new_line: dict):
        """
        Process one zeek line(new_line) and extract columns
        (parse them into column_values dict) to send to the database
        """
        line = new_line['data']
        file_type = new_line['type']
        # all zeek lines recieved from stdin should be of type conn
        if file_type in ('stdin', 'external_module') and new_line.get('line_type', False) == 'zeek':
            file_type = 'conn'
        else:
            # if the zeek dir given to slips has 'conn' in it's name,
            # slips thinks it's reading a conn file
            # because we use the file path as the file 'type'
            # to fix this, only use the file name as file 'type'
            file_type = file_type.split('/')[-1]

        if ts := line.get('ts', False):
            starttime = utils.convert_to_datetime(ts)
        else:
            starttime = ''

        if 'conn' in file_type:
            self.flow: Conn = Conn(
                starttime,
                line.get('uid', False),
                line.get('id.orig_h', ''),
                line.get('id.resp_h', ''),
                line.get('duration', 0),
                line.get('proto',''),
                line.get('service', ''),
                line.get('id.orig_p', ''),
                line.get('id.resp_p', ''),
                line.get('orig_pkts', 0),
                line.get('resp_pkts', 0),
                line.get('orig_bytes', 0),
                line.get('resp_bytes', 0),
                line.get('orig_l2_addr', ''),
                line.get('resp_l2_addr', ''),
                line.get('conn_state', ''),
                line.get('history', ''),
            )
            # orig_bytes: The number of payload bytes the src sent.
            # orig_ip_bytes: the length of the header + the payload

        elif 'dns' in file_type:
            self.flow: DNS = DNS(
                starttime,
                line.get('uid', False),
                line.get('id.orig_h', ''),
                line.get('id.resp_h', ''),
                line.get('query', ''),
                line.get('qclass_name', ''),
                line.get('qtype_name', ''),
                line.get('rcode_name', ''),
                line.get('answers', ''),
                line.get('TTLs', ''),
            )

        elif 'http' in file_type:
            self.flow: HTTP = HTTP(
                starttime,
                line.get('uid', False),
                line.get('id.orig_h', ''),
                line.get('id.resp_h', ''),

                line.get('method', ''),
                line.get('host', ''),
                line.get('uri', ''),
                line.get('version', 0),
                line.get('user_agent', ''),
                line.get('request_body_len', 0),
                line.get('response_body_len', 0),
                line.get('status_code', ''),
                line.get('status_msg', ''),
                line.get('resp_mime_types', ''),
                line.get('resp_fuids', ''),
            )

        elif 'ssl' in file_type:
            self.flow: SSL = SSL(
                starttime,
                line.get('uid', False),
                line.get('id.orig_h', ''),
                line.get('id.resp_h', ''),

                line.get('version', ''),
                line.get('id.orig_p', ','),
                line.get('id.resp_p', ','),

                line.get('cipher', ''),
                line.get('resumed', ''),

                line.get('established', ''),
                line.get('cert_chain_fuids', ''),
                line.get('client_cert_chain_fuids', ''),

                line.get('subject', ''),

                line.get('issuer', ''),
                line.get('validation_status', ''),
                line.get('curve', ''),
                line.get('server_name', ''),

                line.get('ja3', ''),
                line.get('ja3s', ''),
                line.get('is_DoH', 'false'),

            )
        elif 'ssh' in file_type:
            self.flow: SSH = SSH(
                starttime,
                line.get('uid', False),
                line.get('id.orig_h', ''),
                line.get('id.resp_h', ''),

                line.get('version', ''),
                line.get('auth_success', ''),
                line.get('auth_attempts', ''),

                line.get('client', ''),
                line.get('server', ''),
                line.get('cipher_alg', ''),
                line.get('mac_alg', ''),

                line.get('compression_alg', ''),
                line.get('kex_alg', ''),
                line.get('host_key_alg', ''),
                line.get('host_key', ''),


            )
        elif 'dhcp' in file_type:
            self.flow: DHCP = DHCP(
                starttime,
                line.get('uids', []),
                line.get('client_addr', ''), #saddr
                line.get('server_addr', ''), #daddr

                line.get('client_addr', ''),
                line.get('server_addr', ''),
                line.get('host_name', ''),
                line.get('mac', ''),  # this is the client mac
                line.get('requested_addr', ''),

            )
        elif 'ftp' in file_type:
            self.flow: FTP = FTP(
                starttime,
                line.get('uids', []),
                line.get('id.orig_h', ''),
                line.get('id.resp_h', ''),

                line.get('data_channel.resp_p', False),
            )
        elif 'smtp' in file_type:
            self.flow: SMTP = SMTP(
                starttime,
                line.get('uid', ''),
                line.get('id.orig_h', ''),
                line.get('id.resp_h', ''),

                line.get('last_reply', '')
            )
        elif 'tunnel' in file_type:
            self.flow: Tunnel = Tunnel(
                starttime,
                line.get('uid', ''),
                line.get('id.orig_h', ''),
                line.get('id.resp_h', ''),

                line.get('id.orig_p', ''),
                line.get('id.resp_p', ''),

                line.get('tunnel_type', ''),
                line.get('action', ''),
            )

        elif 'notice' in file_type:
            self.flow: Notice = Notice(
                starttime,
                line.get('uid', ''),
                line.get('id.orig_h', ''),
                line.get('id.resp_h', ''),

                line.get('id.orig_p', ''),
                line.get('id.resp_p', ''),
                line.get('note', ''),

                line.get('msg', ''),  # we,'re looking for self signed certs in this field
                line.get('p', ''),
                line.get('src', ''), # this is the scanning_ip
                line.get('dst', ''),
            )

        elif 'files.log' in file_type:
            self.flow: Files = Files(
                starttime,
                line.get('conn_uids', [''])[0],
                line.get('id.orig_h', ''),
                line.get('id.resp_h', ''),

                line.get('seen_bytes', ''),  # downloaded file size
                line.get('md5', ''),

                line.get('source', ''),
                line.get('analyzers', ''),
                line.get('sha1', ''),

                line.get('tx_hosts',''),
                line.get('rx_hosts',''),
            )
        elif 'arp' in file_type:
            self.flow: ARP = ARP(
                starttime,
                line.get('uid', ''),
                line.get('orig_h', ''),
                line.get('resp_h', ''),

                line.get('src_mac', ''),
                line.get('dst_mac', ''),

                line.get('orig_hw', ''),
                line.get('resp_hw', ''),
                line.get('operation', ''),

            )

        elif 'software' in file_type:
            self.flow: Software = Software(
                starttime,
                line.get('uid', ''),
                line.get('host', ''),
                line.get('resp_h', ''),

                line.get('software_type', ''),

                line.get('unparsed_version', ''),
                line.get('version.major', ''),
                line.get('version.minor', ''),
            )

        elif 'weird' in file_type:
            self.flow: Weird =  Weird(
                starttime,
                line.get('uid', ''),
                line.get('host', ''),
                line.get('resp_h', ''),

                line.get('name', ''),
                line.get('addl', ''),
            )

        else:
            return False
        return True

    def process_argus_input(self, new_line):
        """
        Process the line and extract columns for argus
        """
        line = new_line['data']
        nline = line.strip().split(self.separator)

        def get_value_of(field_name, default_=False):
            """field_name is used to get the index of
             the field from the column_idx dict"""
            try:
                val = nline[self.column_idx[field_name]]
                return val or default_
            except (IndexError, KeyError):
                return default_

        self.flow: ArgusConn = ArgusConn(
            utils.convert_to_datetime(get_value_of('starttime')),
            get_value_of('endtime'),
            get_value_of('dur'),
            get_value_of('proto'),
            get_value_of('appproto'),
            get_value_of('saddr'),
            get_value_of('sport'),
            get_value_of('dir'),
            get_value_of('daddr'),
            get_value_of('dport'),
            get_value_of('state'),
            int(get_value_of('pkts')),
            int(get_value_of('spkts')),
            int(get_value_of('dpkts')),
            int(get_value_of('bytes')),
            int(get_value_of('sbytes')),
            int(get_value_of('dbytes')),
        )
        return True

    def process_nfdump_input(self, new_line):
        """
        Process the line and extract columns for nfdump
        """
        self.separator = ','
        line = new_line['data']
        nline = line.strip().split(self.separator)

        def get_value_at(indx, default_=False):
            try:
                val = nline[indx]
                return val or default_
            except (IndexError, KeyError):
                return default_
        starttime = utils.convert_format(get_value_at(0), 'unixtimestamp')
        endtime = utils.convert_format(get_value_at(1), 'unixtimestamp')
        self.flow: NfdumpConn = NfdumpConn(
            starttime,
            endtime,
            get_value_at(2),
            get_value_at(7),

            get_value_at(3),
            get_value_at(5),

            get_value_at(22),

            get_value_at(4),
            get_value_at(6),

            get_value_at(8),
            get_value_at(11),
            get_value_at(13),

            get_value_at(12),
            get_value_at(14),
        )
        return True

    def get_suricata_answers(self, line: dict) -> list:
        """
        reads the suricata dns answer and extracts the cname and IPs in the dns answerr=
        """
        line = line.get('dns', False)
        if not line:
            return []

        answers: dict = line.get('grouped', False)
        if not answers:
            return []

        cnames: list = answers.get('CNAME', [])
        ips: list = answers.get('A', [])

        return cnames + ips

    def process_suricata_input(self, line) -> None:
        """Read suricata json input and store it in column_values"""

        # convert to dict if it's not a dict already
        if type(line) == str:
            line = json.loads(line)
        else:
            # line is a dict with data and type as keys
            line = json.loads(line.get('data', False))

        if not line:
            return
        # these fields are common in all suricata lines regardless of the event type
        event_type = line['event_type']
        flow_id = line['flow_id']
        saddr = line['src_ip']
        sport = line['src_port']
        daddr = line['dest_ip']
        dport = line['dest_port']
        proto = line['proto']
        appproto = line.get('app_proto', False)

        try:
            timestamp = utils.convert_to_datetime(line['timestamp'])
        except ValueError:
            # Reason for catching ValueError:
            # "ValueError: time data '1900-01-00T00:00:08.511802+0000'
            # does not match format '%Y-%m-%dT%H:%M:%S.%f%z'"
            # It means some flow do not have valid timestamp. It seems
            # to me if suricata does not know the timestamp, it put
            # there this not valid time.
            timestamp = False

        def get_value_at(field, subfield, default_=False):
            try:
                val = line[field][subfield]
                return val or default_
            except (IndexError, KeyError):
                return default_

        if event_type == 'flow':
            starttime = utils.convert_format(get_value_at('flow', 'start'), 'unixtimestamp')
            endtime = utils.convert_format(get_value_at('flow', 'end'), 'unixtimestamp')
            self.flow: SuricataFlow = SuricataFlow(
                flow_id,
                saddr,
                sport,
                daddr,
                dport,
                proto,
                appproto,

                starttime,
                endtime,

                int(get_value_at('flow', 'pkts_toserver', 0)),
                int(get_value_at('flow', 'pkts_toclient', 0)),

                int(get_value_at('flow', 'bytes_toserver', 0)),
                int(get_value_at('flow', 'bytes_toclient', 0)),

                get_value_at('flow', 'state', ''),
            )

        elif event_type == 'http':
            self.flow: SuricataHTTP = SuricataHTTP(
                timestamp,
                flow_id,
                saddr,
                sport,
                daddr,
                dport,
                proto,
                appproto,
                get_value_at('http', 'http_method', ''),
                get_value_at('http', 'hostname', ''),
                get_value_at('http', 'url', ''),

                get_value_at('http', 'http_user_agent', ''),
                get_value_at('http', 'status', ''),

                get_value_at('http', 'protocol', ''),

                int(get_value_at('http', 'request_body_len', 0)),
                int(get_value_at('http', 'length', 0)),
            )

        elif event_type == 'dns':
            answers: list = self.get_suricata_answers(line)
            self.flow: SuricataDNS = SuricataDNS(
                timestamp,
                flow_id,
                saddr,
                sport,
                daddr,
                dport,
                proto,
                appproto,

                get_value_at('dns', 'rdata', ''),
                get_value_at('dns', 'ttl', ''),
                get_value_at('qtype_name', 'rrtype', ''),
                answers
            )

        elif event_type == 'tls':
            self.flow: SuricataTLS = SuricataTLS(
                timestamp,
                flow_id,
                saddr,
                sport,
                daddr,
                dport,
                proto,
                appproto,

                get_value_at('tls', 'version', ''),
                get_value_at('tls', 'subject', ''),

                get_value_at('tls', 'issuerdn', ''),
                get_value_at('tls', 'sni', ''),

                get_value_at('tls', 'notbefore', ''),
                get_value_at('tls', 'notafter', ''),
                get_value_at('tls', 'sni', ''),
            )

        elif event_type == 'fileinfo':
            self.flow: SuricataFile = SuricataFile(
                timestamp,
                flow_id,
                saddr,
                sport,
                daddr,
                dport,
                proto,
                appproto,
                get_value_at('fileinfo', 'size', ''),

            )
        elif event_type == 'ssh':
            self.flow: SuricataSSH = SuricataSSH(
                timestamp,
                flow_id,
                saddr,
                sport,
                daddr,
                dport,
                proto,
                appproto,
                get_value_at('ssh', 'client', {}).get('software_version', ''),
                get_value_at('ssh', 'client', {}).get('proto_version', ''),
                get_value_at('ssh', 'server', {}).get('software_version', ''),
            )
        else:
            return False
        return True

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
            to_send['host_name'] = host_name
        self.db.publish('new_MAC', json.dumps(to_send))

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
            'weird',
            'tunnel'
        )

        return bool(
            self.flow.starttime is not None
            and self.flow.type_ in supported_types
        )

    def convert_starttime_to_epoch(self):
        try:
            # seconds.
            # make sure starttime is a datetime obj (not a str) so we can get the timestamp
            self.flow.starttime = utils.convert_format(self.flow.starttime, 'unixtimestamp')
        except ValueError:
            self.print(f'We can not recognize time format of self.flow.starttime: {self.flow.starttime}', 0, 1)

    def make_sure_theres_a_uid(self):
        """
        Generates a uid and adds it to the flow if none is found
        """
        # dhcp flows have uids field instead of uid
        if (
                (type(self.flow) == DHCP and not self.flow.uids)
                or
                (type(self.flow) != DHCP and not self.flow.uid)
        ):
            # In the case of other tools that are not Zeek, there is no UID. So we generate a new one here
            # Zeeks uses human-readable strings in Base62 format, from 112 bits usually.
            # We do base64 with some bits just because we need a fast unique way
            self.flow.uid = base64.b64encode(
                binascii.b2a_hex(os.urandom(9))
            ).decode('utf-8')

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

    def publish_to_new_dhcp(self):
        """
        Publish the GW addr in the new_dhcp channel
        """
        epoch_time = utils.convert_format(self.flow.starttime, 'unixtimestamp')
        self.flow.starttime = epoch_time
        # this channel is used for setting the default gw ip,
        # only 1 flow is enough for that
        # on home networks, the router serves as a simple DHCP server
        to_send = {
            'profileid': self.profileid,
            'twid': self.db.get_timewindow(epoch_time, self.profileid),
            'flow': asdict(self.flow)
        }
        self.db.publish('new_dhcp', json.dumps(to_send))


    def publish_to_new_software(self):
        """
        Send the whole flow to new_software channel
        """
        epoch_time = utils.convert_format(self.flow.starttime, 'unixtimestamp')
        self.flow.starttime = epoch_time
        to_send = {
            'sw_flow': asdict(self.flow),
            'twid':  self.db.get_timewindow(epoch_time, self.profileid),
        }

        self.db.publish(
            'new_software', json.dumps(to_send)
        )

    def add_flow_to_profile(self):
        """
        This is the main function that takes the columns of a flow and does all the magic to
        convert it into a working data in our system.
        It includes checking if the profile exists and how to put the flow correctly.
        It interprets each column
        """
        try:
            if not hasattr(self, 'flow'):
                #TODO this is a quick fix
                return False

            if not self.is_supported_flow():
                return False

            self.make_sure_theres_a_uid()
            self.profileid = f'profile_{self.flow.saddr}'

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
        except Exception:
            # For some reason we can not use the output queue here.. check
            self.print(
                f'Error in add_flow_to_profile Profiler Process. {traceback.format_exc()}'
            ,0,1)
            self.print(traceback.print_exc(),0,1)
            return False

    def handle_conn(self):
        role = 'Client'

        tupleid = f'{self.daddr_as_obj}-{self.flow.dport}-{self.flow.proto}'
        # Compute the symbol for this flow, for this TW, for this profile.
        # The symbol is based on the 'letters' of the original Startosphere ips tool
        symbol = self.compute_symbol('OutTuples')
        # Change symbol for its internal data. Symbol is a tuple and is confusing if we ever change the API
        # Add the out tuple
        self.db.add_tuple(
            self.profileid, self.twid, tupleid, symbol, role, self.flow
        )
        # Add the dstip
        self.db.add_ips(self.profileid, self.twid, self.flow, role)
        # Add the dstport
        port_type = 'Dst'
        self.db.add_port(self.profileid, self.twid, self.flow, role, port_type)
        # Add the srcport
        port_type = 'Src'
        self.db.add_port(self.profileid, self.twid, self.flow, role, port_type)
        # store the original flow as benign in sqlite
        self.db.add_flow(
            self.flow,
            self.profileid,
            self.twid,
            'benign'
        )

        self.publish_to_new_MAC(self.flow.smac, self.flow.saddr)
        self.publish_to_new_MAC(self.flow.dmac, self.flow.daddr)

    def handle_dns(self):
        self.db.add_out_dns(
            self.profileid,
            self.twid,
            self.flow
        )
        self.db.add_altflow(
            self.flow,
            self.profileid,
            self.twid,
            'benign'
        )

    def handle_http(self):
        self.db.add_out_http(
            self.profileid,
            self.twid,
            self.flow,
        )

        self.db.add_altflow(
            self.flow,
            self.profileid,
            self.twid,
            'benign'
        )

    def handle_ssl(self):
        self.db.add_out_ssl(
            self.profileid,
            self.twid,
            self.flow
        )
        self.db.add_altflow(
            self.flow,
            self.profileid,
            self.twid,
            'benign'
        )


    def handle_ssh(self):
        self.db.add_out_ssh(
            self.profileid,
            self.twid,
            self.flow
        )
        self.db.add_altflow(
            self.flow,
            self.profileid,
            self.twid,
            'benign'
        )


    def handle_notice(self):
        self.db.add_out_notice(
                self.profileid,
                self.twid,
                self.flow
        )

        if 'Gateway_addr_identified' in self.flow.note:
            # get the gw addr form the msg
            gw_addr = self.flow.msg.split(': ')[-1].strip()
            self.db.set_default_gateway("IP", gw_addr)

        self.db.add_altflow(
            self.flow,
            self.profileid,
            self.twid,
            'benign'
        )

    def handle_ftp(self):
        if used_port := self.flow.used_port:
            self.db.set_ftp_port(used_port)

        self.db.add_altflow(
            self.flow,
            self.profileid,
            self.twid,
            'benign'
        )


    def handle_smtp(self):
        to_send = {
            'flow': asdict(self.flow),
            'profileid': self.profileid,
            'twid': self.twid,
        }
        to_send = json.dumps(to_send)
        self.db.publish('new_smtp', to_send)

        self.db.add_altflow(
            self.flow,
            self.profileid,
            self.twid,
            'benign'
        )


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

    def handle_software(self):
        self.db.add_software_to_profile(self.profileid, self.flow)
        self.publish_to_new_software()

        self.db.add_altflow(
            self.flow,
            self.profileid,
            self.twid,
            'benign'
        )


    def handle_dhcp(self):
        if self.flow.smac:
            # send this to ip_info module to get vendor info about this MAC
            self.publish_to_new_MAC(
                self.flow.smac or False,
                self.flow.saddr,
                host_name=(self.flow.host_name or False)
            )
        if self.flow.server_addr:
            self.db.store_dhcp_server(self.flow.server_addr)
            self.db.mark_profile_as_dhcp(self.profileid)

        self.publish_to_new_dhcp()
        for uid in self.flow.uids:
            # we're modifying the copy of self.flow
            # the goal is to store a copy of this flow for each uid in self.flow.uids
            flow = self.flow
            flow.uid = uid
            self.db.add_altflow(
                self.flow,
                self.profileid,
                self.twid,
                'benign'
            )


    def handle_files(self):
        """ Send files.log data to new_downloaded_file channel in vt module to see if it's malicious"""
        # files slips sees can be of 2 types: suricata or zeek
        to_send = {
            'flow': asdict(self.flow),
            'type': 'suricata' if type(self.flow) == SuricataFile else 'zeek',
            'profileid': self.profileid,
            'twid': self.twid,
        }

        to_send = json.dumps(to_send)
        self.db.publish('new_downloaded_file', to_send)
        self.db.add_altflow(
            self.flow,
            self.profileid,
            self.twid,
            'benign'
        )

    def handle_arp(self):
        to_send = {
            'flow': asdict(self.flow),
            'profileid': self.profileid,
            'twid': self.twid,
        }
        # send to arp module
        to_send = json.dumps(to_send)
        self.db.publish('new_arp', to_send)

        self.publish_to_new_MAC(
            self.flow.dmac, self.flow.daddr
        )
        self.publish_to_new_MAC(
            self.flow.smac, self.flow.saddr
        )
        self.db.add_altflow(
            self.flow,
            self.profileid,
            self.twid,
            'benign'
        )

    def handle_weird(self):
        """
        handles weird.log zeek flows
        """
        to_send = {
            'profileid': self.profileid,
            'twid': self.twid,
            'flow': asdict(self.flow)
        }
        to_send = json.dumps(to_send)
        self.db.publish('new_weird', to_send)
        self.db.add_altflow(
            self.flow,
            self.profileid,
            self.twid,
            'benign'
        )


    def handle_tunnel(self):
        to_send = {
            'profileid': self.profileid,
            'twid': self.twid,
            'flow': asdict(self.flow)
        }
        to_send = json.dumps(to_send)
        self.db.publish('new_tunnel', to_send)

        self.db.add_altflow(
            self.flow,
            self.profileid,
            self.twid,
            'benign'
        )

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
            'tunnel': self.handle_tunnel,
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
        symbol = self.compute_symbol('InTuples')

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
        tupleid = f'{self.daddr_as_obj}-{self.flow.dport}-{self.flow.proto}'

        current_duration = self.flow.dur
        current_size = self.flow.bytes

        try:
            current_duration = float(current_duration)
            current_size = int(current_size)
            now_ts = float(self.flow.starttime)
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
            tt1 = 1.05
            tt2 = 1.3
            tt3 = float(5)
            td1 = 0.1
            td2 = float(10)
            ts1 = float(250)
            ts2 = float(1100)

            # Get the time of the last flow in this tuple, and the last last
            # Implicitely this is converting what we stored as 'now' into 'last_ts' and what we stored as 'last_ts' as 'last_last_ts'
            (last_last_ts, last_ts) = self.db.getT2ForProfileTW(
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
                        TD = T2 / T1 if T2 >= T1 else T1 / T2
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
                """
                Function to compute letter
                based on the periodicity, size, and dur of the flow
                """
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
                T2 = now_ts - last_ts if now_ts and last_ts else False
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
            except TypeError:
                T2 = False
            # self.print("T2:{}".format(T2), 0, 1)
            # p = self.db.start_profiling()
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
                3, 0,
            )
            # p = self.db.end_profiling(p)
            symbol = zeros + letter + timechar
            # Return the symbol, the current time of the flow and the T1 value
            return symbol, (last_ts, now_ts)
        except Exception:
            # For some reason we can not use the output queue here.. check
            self.print('Error in compute_symbol in Profiler Process.', 0, 1)
            self.print('{}'.format(traceback.format_exc()), 0, 1)

    def shutdown_gracefully(self):
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
                line = self.profiler_queue.get(timeout=3)
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
                    f'({utils.convert_format(datetime.now(), utils.alerts_format)})',
                    2,
                    0,
                )
                return 1

            # Received new input data
            # Extract the columns smartly
            self.print(f'< Received Line: {line}', 2, 0)
            self.rec_lines += 1

            if not self.input_type:
                # Find the type of input received
                self.define_type(line)
                # Find the number of flows we're going to receive of input received
                self.output_queue.put("initialize progress bar")

            # What type of input do we have?
            if not self.input_type:
                # the above define_type can't define the type of input
                self.print("Can't determine input type.", 5, 6)

            elif self.input_type == 'zeek':
                # self.print('Zeek line')
                if self.process_zeek_input(line):
                    # Add the flow to the profile
                    self.add_flow_to_profile()

                self.output_queue.put("update progress bar")

            elif self.input_type in ['argus', 'argus-tabs']:
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
                    if self.process_argus_input(line):
                        # Add the flow to the profile
                        self.add_flow_to_profile()
                    self.output_queue.put("update progress bar")
                except (AttributeError, KeyError):
                    # Define columns. Do not add this line to profile, its only headers
                    self.define_columns(line)
            elif self.input_type == 'suricata':
                if self.process_suricata_input(line):
                    # Add the flow to the profile
                    self.add_flow_to_profile()
                # update progress bar anyway because 1 flow was processed even
                # if slips didn't use it
                self.output_queue.put("update progress bar")
            elif self.input_type == 'zeek-tabs':
                # self.print('Zeek-tabs line')
                if self.process_zeek_tabs_input(line):
                    # Add the flow to the profile
                    self.add_flow_to_profile()
                self.output_queue.put("update progress bar")
            elif self.input_type == 'nfdump':
                if self.process_nfdump_input(line):
                    self.add_flow_to_profile()
                self.output_queue.put("update progress bar")
            else:
                self.print("Can't recognize input file type.")
                return False


            # listen on this channel in case whitelist.conf is changed,
            # we need to process the new changes
            if self.get_msg('reload_whitelist'):
                # if whitelist.conf is edited using pycharm
                # a msg will be sent to this channel on every keypress, because pycharm saves file automatically
                # otherwise this channel will get a msg only when whitelist.conf is modified and saved to disk
                self.whitelist.read_whitelist()

        return 1