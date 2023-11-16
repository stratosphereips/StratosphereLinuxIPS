from re import split

from slips_files.common.abstracts.input_type import IInputType
from slips_files.common.slips_utils import utils
from slips_files.core.flows.zeek import (
    Conn, DNS, HTTP, SSL,
    SSH, DHCP, FTP, SMTP,
    Tunnel, Notice, Files, ARP,
    Software, Weird
    )



class ZeekJSON(IInputType):
    def __init__(self): pass
    def process_line(self, new_line: dict):
        """
        Process one zeek line(new_line) and extract columns
        (parse them into column_values dict) to send to the database
        """
        line = new_line['data']
        file_type = new_line['type']
        # all zeek lines recieved from stdin should be of type conn
        if file_type in ('stdin', 'external_module') \
                and new_line.get('line_type', False) == 'zeek':
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
        return self.flow

class ZeekTabs(IInputType):
    separator = '\t'
    def __init__(self): pass


    def process_line(self, new_line: dict) :
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

        # uid = get_value_at(1)
        # saddr = get_value_at(2, '')
        # saddr = get_value_at(3, '')

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
        return self.flow
