import multiprocessing
import json
from datetime import datetime
from datetime import timedelta
import sys
from collections import OrderedDict
import configparser
from slips.core.database import __database__
import time
import ipaddress
import traceback
from typing import Tuple, Dict, Set, Callable


def timing(f):
    """ Function to measure the time another function takes."""
    def wrap(*args):
        time1 = time.time()
        ret = f(*args)
        time2 = time.time()
        print('Function took {:.3f} ms'.format((time2-time1)*1000.0))
        return ret
    return wrap

# Profiler Process
class ProfilerProcess(multiprocessing.Process):
    """ A class to create the profiles for IPs and the rest of data """
    def __init__(self, inputqueue, outputqueue, config, width):
        self.name = 'Profiler'
        multiprocessing.Process.__init__(self)
        self.inputqueue = inputqueue
        self.outputqueue = outputqueue
        self.config = config
        self.width = width
        self.columns_defined = False
        self.timeformat = None
        self.input_type = False
        # Read the configuration
        self.read_configuration()
        # Set the database output queue
        __database__.setOutputQueue(self.outputqueue)

    def print(self, text, verbose=1, debug=0):
        """
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by taking all the prcocesses into account

        Input
         verbose: is the minimum verbosity level required for this text to be printed
         debug: is the minimum debugging level required for this text to be printed
         text: text to print. Can include format like 'Test {}'.format('here')

        If not specified, the minimum verbosity level required is 1, and the minimum debugging level is 0
        """

        vd_text = str(int(verbose) * 10 + int(debug))
        self.outputqueue.put(vd_text + '|' + self.name + '|[' + self.name + '] ' + str(text))

    def read_configuration(self):
        """ Read the configuration file for what we need """
        # Get the home net if we have one from the config
        try:
            self.home_net = ipaddress.ip_network(self.config.get('parameters', 'home_network'))
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.home_net = False

        # Get the time window width, if it was not specified as a parameter
        if not self.width:
            try:
                data = self.config.get('parameters', 'time_window_width')
                self.width = float(data)
            except ValueError:
                # Its not a float
                if 'only_one_tw' in data:
                    # Only one tw. Width is 10 9s, wich is ~11,500 days, ~311 years
                    self.width = 9999999999
            except configparser.NoOptionError:
                # By default we use 300 seconds, 5minutes
                self.width = 300.0
            except (configparser.NoOptionError, configparser.NoSectionError, NameError):
                # There is a conf, but there is no option, or no section or no configuration file specified
                self.width = 300.0
        # Limit any width to be > 0. By default we use 300 seconds, 5minutes
        elif self.width < 0:
            self.width = 300.0
        else:
            self.width = 300.0
        # Report the time window width
        if self.width == 9999999999:
            self.outputqueue.put("10|profiler|Time Windows Width used: Only 1 time windows. Dates in the names of files are 100 years in the past.".format(self.width))
        else:
            self.outputqueue.put("10|profiler|Time Windows Width used: {} seconds.".format(self.width))

        # Get the format of the time in the flows
        try:
            self.timeformat = self.config.get('timestamp', 'format')
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.timeformat = None

        ##
        # Get the direction of analysis
        try:
            self.analysis_direction = self.config.get('parameters', 'analysis_direction')
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            # By default
            self.analysis_direction = 'all'

    def define_type(self, line):
        """
        Try to define very fast the type of input
        Heuristic detection: dict (zeek from pcap of int), json (suricata), or csv (argus), or TAB separated (conn.log only from zeek)?
        Bro actually gives us json, but it was already coverted into a dict
        in inputProcess
        Outputs can be: zeek, suricata, argus, zeek-tabs
        """
        try:
            if type(line) == dict:
                self.input_type = 'zeek'
            else:
                try:
                    data = json.loads(line)
                    if data['event_type'] == 'flow':
                        self.input_type = 'suricata'
                except ValueError:
                    nr_commas = len(line.split(','))
                    nr_tabs = len(line.split('	'))
                    if nr_commas > nr_tabs:
                        # Commas is the separator
                        self.separator = ','
                        if nr_commas > 40:
                            self.input_type = 'nfdump'
                        else:
                            self.input_type = 'argus'

                    elif nr_tabs > nr_commas:
                        # Tabs is the separator
                        # Probably a conn.log file alone from zeek
                        self.separator = '	'
                        self.input_type = 'zeek-tabs'
        except Exception as inst:
            self.print('\tProblem in define_type()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst), 0, 1)
            sys.exit(1)

    def define_columns(self, line):
        """ Define the columns for Argus and Zeek-tabs from the line received """
        # These are the indexes for later fast processing
        self.column_idx = {}
        self.column_idx['starttime'] = False
        self.column_idx['endtime'] = False
        self.column_idx['dur'] = False
        self.column_idx['proto'] = False
        self.column_idx['appproto'] = False
        self.column_idx['saddr'] = False
        self.column_idx['sport'] = False
        self.column_idx['dir'] = False
        self.column_idx['daddr'] = False
        self.column_idx['dport'] = False
        self.column_idx['state'] = False
        self.column_idx['pkts'] = False
        self.column_idx['spkts'] = False
        self.column_idx['dpkts'] = False
        self.column_idx['bytes'] = False
        self.column_idx['sbytes'] = False
        self.column_idx['dbytes'] = False

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
            # Some of the fields were not found probably,
            # so just delete them from the index if their value is False.
            # If not we will believe that we have data on them
            # We need a temp dict because we can not change the size of dict while analyzing it
            temp_dict = {}
            for i in self.column_idx:
                if type(self.column_idx[i]) == bool and self.column_idx[i] == False:
                    continue
                temp_dict[i] = self.column_idx[i]
            self.column_idx = temp_dict
        except Exception as inst:
            self.print('\tProblem in define_columns()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst), 0, 1)
            sys.exit(1)

    def define_time_format(self, time: str) -> str:
        time_format: str = None
        try:
            # Try unix timestamp in seconds.
            datetime.fromtimestamp(float(time))
            time_format = 'unixtimestamp'
        except ValueError:
            try:
                # Try the default time format for suricata.
                datetime.strptime(time, '%Y-%m-%dT%H:%M:%S.%f%z')
                time_format = '%Y-%m-%dT%H:%M:%S.%f%z'
            except ValueError:
                # Let's try the classic time format "'%Y-%m-%d %H:%M:%S.%f'"
                try:
                    datetime.strptime(time, '%Y-%m-%d %H:%M:%S.%f')
                    time_format = '%Y-%m-%d %H:%M:%S.%f'
                except ValueError:
                    try:
                        datetime.strptime(time, '%Y-%m-%d %H:%M:%S')
                        time_format = '%Y-%m-%d %H:%M:%S'
                    except ValueError:
                        try:
                            datetime.strptime(time, '%Y/%m/%d %H:%M:%S.%f')
                            time_format = '%Y/%m/%d %H:%M:%S.%f'
                        except ValueError:
                            # We did not find the right time format.
                            self.outputqueue.put("01|profiler|[Profile] We did not find right time format. Please set the time format in the configuration file.")
        return time_format

    def get_time(self, time: str) -> datetime:
        """
        Take time in string and return datetime object.
        The format of time can be completely different. It can be seconds, or dates with specific formats.
        If user does not define the time format in configuration file, we have to try most frequent cases of time formats.
        """
        if not self.timeformat:
            # The time format was not defined from configuration file neither from last flows.
            self.timeformat = self.define_time_format(time)

        defined_datetime: datetime = None
        if self.timeformat:
            if self.timeformat == 'unixtimestamp':
                # The format of time is in seconds.
                defined_datetime = datetime.fromtimestamp(float(time))
            else:
                try:
                    # The format of time is a complete date.
                    defined_datetime = datetime.strptime(time, self.timeformat)
                except ValueError:
                    defined_datetime = None
        else:
            # We do not know the time format so we can not read it.
            self.outputqueue.put(
                "01|profiler|[Profile] We did not find right time format. Please set the time format in the configuration file.")
        return defined_datetime

    def process_zeek_tabs_input(self, line: str) -> None:
        """
        Process the tab line from zeek.
        """
        line: str = line.rstrip()
        line: list = line.split('\t')

        # Generic fields in Zeek
        self.column_values: dict = {}
        # We need to set it to empty at the beginning so any new flow has the key 'type'
        self.column_values['type'] = ''
        try:
            self.column_values['starttime'] = self.get_time(line[0])
        except KeyError:
            self.column_values['starttime'] = ''
        try:
            self.column_values['uid'] = line[1]
        except KeyError:
            self.column_values['uid'] = False
        try:
            self.column_values['saddr'] = line[2]
        except KeyError:
            self.column_values['saddr'] = ''
        try:
            self.column_values['daddr'] = line[4]
        except KeyError:
            self.column_values['daddr'] = ''

        if 'conn' in line[-1]:
            self.column_values['type'] = 'conn'
            try:
                self.column_values['dur'] = float(line[8])
            except (KeyError, ValueError):
                self.column_values['dur'] = 0
            self.column_values['endtime'] = self.column_values['starttime'] + timedelta(
                seconds=self.column_values['dur'])
            self.column_values['proto'] = line[6]
            try:
                self.column_values['appproto'] = line[7]
            except KeyError:
                # no service recognized
                self.column_values['appproto'] = ''
            self.column_values['sport'] = line[3]
            self.column_values['dir'] = '->'
            self.column_values['dport'] = line[5]
            self.column_values['state'] = line[11]
            try:
                self.column_values['spkts'] = float(line[16])
            except (KeyError, ValueError):
                self.column_values['spkts'] = 0
            try:
                self.column_values['dpkts'] = float(line[18])
            except (KeyError, ValueError):
                self.column_values['dpkts'] = 0
            self.column_values['pkts'] = self.column_values['spkts'] + self.column_values['dpkts']
            try:
                self.column_values['sbytes'] = float(line[9])
            except (KeyError, ValueError):
                self.column_values['sbytes'] = 0
            try:
                self.column_values['dbytes'] = float(line[10])
            except (KeyError, ValueError):
                self.column_values['dbytes'] = 0
            self.column_values['bytes'] = self.column_values['sbytes'] + self.column_values['dbytes']
            try:
                self.column_values['state_hist'] = line[15]
            except KeyError:
                self.column_values['state_hist'] = self.column_values['state']
            # We do not know the indexes of MACs.
            self.column_values['smac'] = ''
            self.column_values['dmac'] = ''
        elif 'dns' in line[-1]:
            self.column_values['type'] = 'dns'
            try:
                self.column_values['query'] = line[9]
            except KeyError:
                self.column_values['query'] = ''
            try:
                self.column_values['qclass_name'] = line[11]
            except KeyError:
                self.column_values['qclass_name'] = ''
            try:
                self.column_values['qtype_name'] = line[13]
            except KeyError:
                self.column_values['qtype_name'] = ''
            try:
                self.column_values['rcode_name'] = line[15]
            except KeyError:
                self.column_values['rcode_name'] = ''
            try:
                self.column_values['answers'] = line[21]
            except KeyError:
                self.column_values['answers'] = ''
            try:
                self.column_values['TTLs'] = line[22]
            except KeyError:
                self.column_values['TTLs'] = ''
        elif 'http' in line[-1]:
            self.column_values['type'] = 'http'
            try:
                self.column_values['method'] = line[7]
            except KeyError:
                self.column_values['method'] = ''
            try:
                self.column_values['host'] = line[8]
            except KeyError:
                self.column_values['host'] = ''
            try:
                self.column_values['uri'] = line[9]
            except KeyError:
                self.column_values['uri'] = ''
            try:
                self.column_values['httpversion'] = line[11]
            except KeyError:
                self.column_values['httpversion'] = ''
            try:
                self.column_values['user_agent'] = line[12]
            except KeyError:
                self.column_values['user_agent'] = ''
            try:
                self.column_values['request_body_len'] = line[13]
            except KeyError:
                self.column_values['request_body_len'] = 0
            try:
                self.column_values['response_body_len'] = line[14]
            except KeyError:
                self.column_values['response_body_len'] = 0
            try:
                self.column_values['status_code'] = line[15]
            except KeyError:
                self.column_values['status_code'] = ''
            try:
                self.column_values['status_msg'] = line[16]
            except KeyError:
                self.column_values['status_msg'] = ''
            try:
                self.column_values['resp_mime_types'] = line[28]
            except KeyError:
                self.column_values['resp_mime_types'] = ''
            try:
                self.column_values['resp_fuids'] = line[26]
            except KeyError:
                self.column_values['resp_fuids'] = ''
        elif 'ssl' in line[-1]:
            self.column_values['type'] = 'ssl'
            try:
                self.column_values['sslversion'] = line[6]
            except KeyError:
                self.column_values['sslversion'] = ''
            try:
                self.column_values['cipher'] = line[7]
            except KeyError:
                self.column_values['cipher'] = ''
            try:
                self.column_values['resumed'] = line[10]
            except KeyError:
                self.column_values['resumed'] = ''
            try:
                self.column_values['established'] = line[13]
            except KeyError:
                self.column_values['established'] = ''
            try:
                self.column_values['cert_chain_fuids'] = line[14]
            except KeyError:
                self.column_values['cert_chain_fuids'] = ''
            try:
                self.column_values['client_cert_chain_fuids'] = line[15]
            except KeyError:
                self.column_values['client_cert_chain_fuids'] = ''
            try:
                self.column_values['subject'] = line[16]
            except KeyError:
                self.column_values['subject'] = ''
            try:
                self.column_values['issuer'] = line[17]
            except KeyError:
                self.column_values['issuer'] = ''
            self.column_values['validation_status'] = ''
            try:
                self.column_values['curve'] = line[8]
            except KeyError:
                self.column_values['curve'] = ''
            try:
                self.column_values['server_name'] = line[9]
            except KeyError:
                self.column_values['server_name'] = ''
        elif 'ssh' in line[-1]:
            self.column_values['type'] = 'ssh'
        elif 'irc' in line[-1]:
            self.column_values['type'] = 'irc'
        elif 'long' in line[-1]:
            self.column_values['type'] = 'long'
        elif 'dhcp' in line[-1]:
            self.column_values['type'] = 'dhcp'
        elif 'dce_rpc' in line[-1]:
            self.column_values['type'] = 'dce_rpc'
        elif 'dnp3' in line[-1]:
            self.column_values['type'] = 'dnp3'
        elif 'ftp' in line[-1]:
            self.column_values['type'] = 'ftp'
        elif 'kerberos' in line[-1]:
            self.column_values['type'] = 'kerberos'
        elif 'mysql' in line[-1]:
            self.column_values['type'] = 'mysql'
        elif 'modbus' in line[-1]:
            self.column_values['type'] = 'modbus'
        elif 'ntlm' in line[-1]:
            self.column_values['type'] = 'ntlm'
        elif 'rdp' in line[-1]:
            self.column_values['type'] = 'rdp'
        elif 'sip' in line[-1]:
            self.column_values['type'] = 'sip'
        elif 'smb_cmd' in line[-1]:
            self.column_values['type'] = 'smb_cmd'
        elif 'smb_files' in line[-1]:
            self.column_values['type'] = 'smb_files'
        elif 'smb_mapping' in line[-1]:
            self.column_values['type'] = 'smb_mapping'
        elif 'smtp' in line[-1]:
            self.column_values['type'] = 'smtp'
        elif 'socks' in line[-1]:
            self.column_values['type'] = 'socks'
        elif 'syslog' in line[-1]:
            self.column_values['type'] = 'syslog'
        elif 'tunnel' in line[-1]:
            self.column_values['type'] = 'tunnel'

    def process_zeek_input(self, line):
        """
        Process the line and extract columns for zeek
        Its a dictionary
        """
        # Generic fields in Zeek
        self.column_values = {}
        # We need to set it to empty at the beggining so any new flow has the key 'type'
        self.column_values['type'] = ''
        try:
            self.column_values['starttime'] = self.get_time(line['ts'])
        except KeyError:
            self.column_values['starttime'] = ''
        try:
            self.column_values['uid'] = line['uid']
        except KeyError:
            self.column_values['uid'] = False
        try:
            self.column_values['saddr'] = line['id.orig_h']
        except KeyError:
            self.column_values['saddr'] = ''
        try:
            self.column_values['daddr'] = line['id.resp_h']
        except KeyError:
            self.column_values['daddr'] = ''

        if 'conn' in line['type']:
            # {'ts': 1538080852.403669, 'uid': 'Cewh6D2USNVtfcLxZe', 'id.orig_h': '192.168.2.12', 'id.orig_p': 56343, 'id.resp_h': '192.168.2.1', 'id.resp_p': 53, 'proto': 'udp', 'service': 'dns', 'duration': 0.008364, 'orig_bytes': 30, 'resp_bytes': 94, 'conn_state': 'SF', 'missed_bytes': 0, 'history': 'Dd', 'orig_pkts': 1, 'orig_ip_bytes': 58, 'resp_pkts': 1, 'resp_ip_bytes': 122, 'orig_l2_addr': 'b8:27:eb:6a:47:b8', 'resp_l2_addr': 'a6:d1:8c:1f:ce:64', 'type': './zeek_files/conn'}
            self.column_values['type'] = 'conn'
            try:
                self.column_values['dur'] = float(line['duration'])
            except KeyError:
                self.column_values['dur'] = 0
            self.column_values['endtime'] = self.column_values['starttime'] + timedelta(seconds=self.column_values['dur'])
            self.column_values['proto'] = line['proto']
            try:
                self.column_values['appproto'] = line['service']
            except KeyError:
                # no service recognized
                self.column_values['appproto'] = ''
            self.column_values['sport'] = line['id.orig_p']
            self.column_values['dir'] = '->'
            self.column_values['dport'] = line['id.resp_p']
            self.column_values['state'] = line['conn_state']
            try:
                self.column_values['spkts'] = line['orig_pkts']
            except KeyError:
                self.column_values['spkts'] = 0
            try:
                self.column_values['dpkts'] = line['resp_pkts']
            except KeyError:
                self.column_values['dpkts'] = 0
            self.column_values['pkts'] = self.column_values['spkts'] + self.column_values['dpkts']
            try:
                self.column_values['sbytes'] = line['orig_bytes']
            except KeyError:
                self.column_values['sbytes'] = 0
            try:
                self.column_values['dbytes'] = line['resp_bytes']
            except KeyError:
                self.column_values['dbytes'] = 0
            self.column_values['bytes'] = self.column_values['sbytes'] + self.column_values['dbytes']
            try:
                self.column_values['state_hist'] = line['history']
            except KeyError:
                self.column_values['state_hist'] = self.column_values['state']
            try:
                self.column_values['smac'] = line['orig_l2_addr']
            except KeyError:
                self.column_values['smac'] = ''
            try:
                self.column_values['dmac'] = line['resp_l2_addr']
            except KeyError:
                self.column_values['dmac'] = ''
        elif 'dns' in line['type']:
            #{"ts":1538080852.403669,"uid":"CtahLT38vq7vKJVBC3","id.orig_h":"192.168.2.12","id.orig_p":56343,"id.resp_h":"192.168.2.1","id.resp_p":53,"proto":"udp","trans_id":2,"rtt":0.008364,"query":"pool.ntp.org","qclass":1,"qclass_name":"C_INTERNET","qtype":1,"qtype_name":"A","rcode":0,"rcode_name":"NOERROR","AA":false,"TC":false,"RD":true,"RA":true,"Z":0,"answers":["185.117.82.70","212.237.100.250","213.251.52.107","183.177.72.201"],"TTLs":[42.0,42.0,42.0,42.0],"rejected":false}
            self.column_values['type'] = 'dns'
            try:
                self.column_values['query'] = line['query']
            except KeyError:
                self.column_values['query'] = ''
            try:
                self.column_values['qclass_name'] = line['qclass_name']
            except KeyError:
                self.column_values['qclass_name'] = ''
            try:
                self.column_values['qtype_name'] = line['qtype_name']
            except KeyError:
                self.column_values['qtype_name'] = ''
            try:
                self.column_values['rcode_name'] = line['rcode_name']
            except KeyError:
                self.column_values['rcode_name'] = ''
            try:
                self.column_values['answers'] = line['answers']
            except KeyError:
                self.column_values['answers'] = ''
            try:
                self.column_values['TTLs'] = line['TTLs']
            except KeyError:
                self.column_values['TTLs'] = ''
        elif 'http' in line['type']:
            # {"ts":158.957403,"uid":"CnNLbE2dyfy5KyqEhh","id.orig_h":"10.0.2.105","id.orig_p":49158,"id.resp_h":"64.182.208.181","id.resp_p":80,"trans_depth":1,"method":"GET","host":"icanhazip.com","uri":"/","version":"1.1","user_agent":"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.38 (KHTML, like Gecko) Chrome/45.0.2456.99 Safari/537.38","request_body_len":0,"response_body_len":13,"status_code":200,"status_msg":"OK","tags":[],"resp_fuids":["FwraVxIOACcjkaGi3"],"resp_mime_types":["text/plain"]}
            self.column_values['type'] = 'http'
            try:
                self.column_values['method'] = line['method']
            except KeyError:
                self.column_values['method'] = ''
            try:
                self.column_values['host'] = line['host']
            except KeyError:
                self.column_values['host'] = ''
            try:
                self.column_values['uri'] = line['uri']
            except KeyError:
                self.column_values['uri'] = ''
            try:
                self.column_values['httpversion'] = line['version']
            except KeyError:
                self.column_values['httpversion'] = ''
            try:
                self.column_values['user_agent'] = line['user_agent']
            except KeyError:
                self.column_values['user_agent'] = ''
            try:
                self.column_values['request_body_len'] = line['request_body_len']
            except KeyError:
                self.column_values['request_body_len'] = 0
            try:
                self.column_values['response_body_len'] = line['response_body_len']
            except KeyError:
                self.column_values['response_body_len'] = 0
            try:
                self.column_values['status_code'] = line['status_code']
            except KeyError:
                self.column_values['status_code'] = ''
            try:
                self.column_values['status_msg'] = line['status_msg']
            except KeyError:
                self.column_values['status_msg'] = ''
            try:
                self.column_values['resp_mime_types'] = line['resp_mime_types']
            except KeyError:
                self.column_values['resp_mime_types'] = ''
            try:
                self.column_values['resp_fuids'] = line['resp_fuids']
            except KeyError:
                self.column_values['resp_fuids'] = ''
        elif 'ssl' in line['type']:
            # {"ts":12087.045499,"uid":"CdoFDp4iW79I5ZmsT7","id.orig_h":"10.0.2.105","id.orig_p":49704,"id.resp_h":"195.211.240.166","id.resp_p":443,"version":"SSLv3","cipher":"TLS_RSA_WITH_RC4_128_SHA","resumed":false,"established":true,"cert_chain_fuids":["FhGp1L3yZXuURiPqq7"],"client_cert_chain_fuids":[],"subject":"OU=DAHUATECH,O=DAHUA,L=HANGZHOU,ST=ZHEJIANG,C=CN,CN=192.168.1.108","issuer":"O=DahuaTech,L=HangZhou,ST=ZheJiang,C=CN,CN=Product Root CA","validation_status":"unable to get local issuer certificate"}
            # {"ts":1382354909.915615,"uid":"C7W6ZA4vI8FxJ9J0bh","id.orig_h":"147.32.83.53","id.orig_p":36567,"id.resp_h":"195.113.214.241","id.resp_p":443,"version":"TLSv12","cipher":"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA","curve":"secp256r1","server_name":"id.google.com.ar","resumed":false,"established":true,"cert_chain_fuids":["FnomJz1vghKIOHtytf","FSvQff1KsaDkRtKXo4","Fif2PF48bytqq6xMDb"],"client_cert_chain_fuids":[],"subject":"CN=*.google.com,O=Google Inc,L=Mountain View,ST=California,C=US","issuer":"CN=Google Internet Authority G2,O=Google Inc,C=US","validation_status":"ok"}
            self.column_values['type'] = 'ssl'
            try:
                self.column_values['sslversion'] = line['version']
            except KeyError:
                self.column_values['sslversion'] = ''
            try:
                self.column_values['cipher'] = line['cipher']
            except KeyError:
                self.column_values['cipher'] = ''
            try:
                self.column_values['resumed'] = line['resumed']
            except KeyError:
                self.column_values['resumed'] = ''
            try:
                self.column_values['established'] = line['established']
            except KeyError:
                self.column_values['established'] = ''
            try:
                self.column_values['cert_chain_fuids'] = line['cert_chain_fuids']
            except KeyError:
                self.column_values['cert_chain_fuids'] = ''
            try:
                self.column_values['client_cert_chain_fuids'] = line['client_cert_chain_fuids']
            except KeyError:
                self.column_values['client_cert_chain_fuids'] = ''
            try:
                self.column_values['subject'] = line['subject']
            except KeyError:
                self.column_values['subject'] = ''
            try:
                self.column_values['issuer'] = line['issuer']
            except KeyError:
                self.column_values['issuer'] = ''
            try:
                self.column_values['validation_status'] = line['validation_status']
            except KeyError:
                self.column_values['validation_status'] = ''
            try:
                self.column_values['curve'] = line['curve']
            except KeyError:
                self.column_values['curve'] = ''
            try:
                self.column_values['server_name'] = line['server_name']
            except KeyError:
                self.column_values['server_name'] = ''
        elif 'ssh' in line['type']:
            self.column_values['type'] = 'ssh'
        elif 'irc' in line['type']:
            self.column_values['type'] = 'irc'
        elif 'long' in line['type']:
            self.column_values['type'] = 'long'
        elif 'dhcp' in line['type']:
            self.column_values['type'] = 'dhcp'
        elif 'dce_rpc' in line['type']:
            self.column_values['type'] = 'dce_rpc'
        elif 'dnp3' in line['type']:
            self.column_values['type'] = 'dnp3'
        elif 'ftp' in line['type']:
            self.column_values['type'] = 'ftp'
        elif 'kerberos' in line['type']:
            self.column_values['type'] = 'kerberos'
        elif 'mysql' in line['type']:
            self.column_values['type'] = 'mysql'
        elif 'modbus' in line['type']:
            self.column_values['type'] = 'modbus'
        elif 'ntlm' in line['type']:
            self.column_values['type'] = 'ntlm'
        elif 'rdp' in line['type']:
            self.column_values['type'] = 'rdp'
        elif 'sip' in line['type']:
            self.column_values['type'] = 'sip'
        elif 'smb_cmd' in line['type']:
            self.column_values['type'] = 'smb_cmd'
        elif 'smb_files' in line['type']:
            self.column_values['type'] = 'smb_files'
        elif 'smb_mapping' in line['type']:
            self.column_values['type'] = 'smb_mapping'
        elif 'smtp' in line['type']:
            self.column_values['type'] = 'smtp'
        elif 'socks' in line['type']:
            self.column_values['type'] = 'socks'
        elif 'syslog' in line['type']:
            self.column_values['type'] = 'syslog'
        elif 'tunnel' in line['type']:
            self.column_values['type'] = 'tunnel'

    def process_argus_input(self, line):
        """
        Process the line and extract columns for argus
        """
        self.column_values = {}
        self.column_values['starttime'] = False
        self.column_values['endtime'] = False
        self.column_values['dur'] = False
        self.column_values['proto'] = False
        self.column_values['appproto'] = False
        self.column_values['saddr'] = False
        self.column_values['sport'] = False
        self.column_values['dir'] = False
        self.column_values['daddr'] = False
        self.column_values['dport'] = False
        self.column_values['state'] = False
        self.column_values['pkts'] = False
        self.column_values['spkts'] = False
        self.column_values['dpkts'] = False
        self.column_values['bytes'] = False
        self.column_values['sbytes'] = False
        self.column_values['dbytes'] = False
        self.column_values['type'] = 'argus'

        # Read the lines fast
        nline = line.strip().split(self.separator)
        try:
            self.column_values['starttime'] = self.get_time(nline[self.column_idx['starttime']])
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
            self.column_values['pkts'] = nline[self.column_idx['pkts']]
        except KeyError:
            pass
        try:
            self.column_values['spkts'] = nline[self.column_idx['spkts']]
        except KeyError:
            pass
        try:
            self.column_values['dpkts'] = nline[self.column_idx['dpkts']]
        except KeyError:
            pass
        try:
            self.column_values['bytes'] = nline[self.column_idx['bytes']]
        except KeyError:
            pass
        try:
            self.column_values['sbytes'] = nline[self.column_idx['sbytes']]
        except KeyError:
            pass
        try:
            self.column_values['dbytes'] = nline[self.column_idx['dbytes']]
        except KeyError:
            pass

    def process_nfdump_input(self, line):
        """
        Process the line and extract columns for argus
        """
        self.column_values = {}
        self.column_values['starttime'] = False
        self.column_values['endtime'] = False
        self.column_values['dur'] = False
        self.column_values['proto'] = False
        self.column_values['appproto'] = False
        self.column_values['saddr'] = False
        self.column_values['sport'] = False
        self.column_values['dir'] = False
        self.column_values['daddr'] = False
        self.column_values['dport'] = False
        self.column_values['state'] = False
        self.column_values['pkts'] = False
        self.column_values['spkts'] = False
        self.column_values['dpkts'] = False
        self.column_values['bytes'] = False
        self.column_values['sbytes'] = False
        self.column_values['dbytes'] = False
        self.column_values['type'] = 'argus'

        # Read the lines fast
        nline = line.strip().split(self.separator)
        try:
            self.column_values['starttime'] = self.get_time(nline[0])
        except IndexError:
            pass
        try:
            self.column_values['endtime'] = self.get_time(nline[1])
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
            self.column_values['pkts'] = self.column_values['spkts'] + self.column_values['dpkts']
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
            self.column_values['bytes'] = self.column_values['sbytes'] + self.column_values['dbytes']
        except IndexError:
            pass

    def process_suricata_input(self, line: str) -> None:
        """ Read suricata json input """
        line = json.loads(line)

        self.column_values: dict = {}
        try:
            self.column_values['starttime'] = self.get_time(line['timestamp'])
        # except (KeyError, ValueError):
        except :
            # Reason for catching ValueError:
            # "ValueError: time data '1900-01-00T00:00:08.511802+0000' does not match format '%Y-%m-%dT%H:%M:%S.%f%z'"
            # It means some flow do not have valid timestamp. It seems to me if suricata does not know the timestamp, it put
            # there this not valid time.
            self.column_values['starttime'] = False
        self.column_values['endtime'] = False
        self.column_values['dur'] = 0
        try:
            self.column_values['flow_id'] = line['flow_id']
        except KeyError:
            self.column_values['flow_id'] = False
        try:
            self.column_values['saddr'] = line['src_ip']
        except KeyError:
            self.column_values['saddr'] = False
        try:
            self.column_values['sport'] = line['src_port']
        except KeyError:
            self.column_values['sport'] = False
        try:
            self.column_values['daddr'] = line['dest_ip']
        except KeyError:
            self.column_values['daddr'] = False
        try:
            self.column_values['dport'] = line['dest_port']
        except KeyError:
            self.column_values['dport'] = False
        try:
            self.column_values['proto'] = line['proto']
        except KeyError:
            self.column_values['proto'] = False
        try:
            self.column_values['type'] = line['event_type']
        except KeyError:
            self.column_values['type'] = False
        self.column_values['dir'] = '->'
        try:
            self.column_values['appproto'] = line['app_proto']
        except KeyError:
            self.column_values['appproto'] = False

        if self.column_values['type']:
            """
            event_type: 
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
                        self.column_values['starttime'] = self.get_time(line['flow']['start'])
                    except KeyError:
                        self.column_values['starttime'] = False
                    try:
                        self.column_values['endtime'] = self.get_time(line['flow']['end'])
                    except KeyError:
                        self.column_values['endtime'] = False

                    try:
                        self.column_values['dur'] = (
                            self.column_values['endtime'] - self.column_values['starttime']).total_seconds()
                    except (KeyError, TypeError):
                        self.column_values['dur'] = 0
                    try:
                        self.column_values['spkts'] = line['flow']['pkts_toserver']
                    except KeyError:
                        self.column_values['spkts'] = 0
                    try:
                        self.column_values['dpkts'] = line['flow']['pkts_toclient']
                    except KeyError:
                        self.column_values['dpkts'] = 0

                    self.column_values['pkts'] = self.column_values['dpkts'] + self.column_values['spkts']

                    try:
                        self.column_values['sbytes'] = line['flow']['bytes_toserver']
                    except KeyError:
                        self.column_values['sbytes'] = 0

                    try:
                        self.column_values['dbytes'] = line['flow']['bytes_toclient']
                    except KeyError:
                        self.column_values['dbytes'] = 0

                    self.column_values['bytes'] = self.column_values['dbytes'] + self.column_values['sbytes']

                    try:
                        self.column_values['state'] = line['flow']['bytes_toclient']
                    except KeyError:
                        self.column_values['state'] = 0
            elif self.column_values['type'] == 'http':
                if line.get('http', None):
                    try:
                        self.column_values['method'] = line['http']['http_method']
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
                        self.column_values['user_agent'] = line['http']['http_user_agent']
                    except KeyError:
                        self.column_values['user_agent'] = ''
                    try:
                        self.column_values['status_code'] = line['http']['status']
                    except KeyError:
                        self.column_values['status_code'] = ''
                    try:
                        self.column_values['httpversion'] = line['http']['protocol']
                    except KeyError:
                        self.column_values['httpversion'] = ''
                    try:
                        self.column_values['response_body_len'] = line['http']['length']
                    except KeyError:
                        self.column_values['response_body_len'] = 0
                    try:
                        self.column_values['request_body_len'] = line['http']['request_body_len']
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
                        self.column_values['qtype_name'] = line['dns']['rrtype']
                    except KeyError:
                        self.column_values['qtype_name'] = ''

                    # can not find in eve.json:
                    self.column_values['qclass_name'] = ''
                    self.column_values['rcode_name'] = ''
                    self.column_values['answers'] = ''


            elif self.column_values['type'] == 'tls':
                if line.get('tls', None):
                    try:
                        self.column_values['sslversion'] = line['tls']['version']
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
                        self.column_values['notbefore'] = datetime.strptime((line['tls']['notbefore']), '%Y-%m-%dT%H:%M:%S')
                    except KeyError:
                        self.column_values['notbefore'] = ''

                    try:
                        self.column_values['notafter'] = datetime.strptime((line['tls']['notafter']), '%Y-%m-%dT%H:%M:%S')
                    except KeyError:
                        self.column_values['notafter'] = ''
            elif self.column_values['type'] == 'alert':
                if line.get('alert', None):
                    try:
                        self.column_values['signature'] = line['alert']['signature']
                    except KeyError:
                        self.column_values['signature'] = ''
                    try:
                        self.column_values['category'] = line['alert']['category']
                    except KeyError:
                        self.column_values['category'] = ''
                    try:
                        self.column_values['severity'] = line['alert']['severity']
                    except KeyError:
                        self.column_values['severity'] = ''
            elif self.column_values['type'] == 'fileinfo':
                try:
                    self.column_values['filesize'] = line['fileinfo']['size']
                except KeyError:
                    self.column_values['filesize'] = ''



    def add_flow_to_profile(self):
        """
        This is the main function that takes the columns of a flow and does all the magic to convert it into a working data in our system.
        It includes checking if the profile exists and how to put the flow correctly.
        It interprets each colum
        """
        try:
            # For now we only process the argus flows and the zeek conn logs
            if not self.column_values:
                return True
            elif not 'ssl' in self.column_values['type'] and not 'http' in self.column_values['type'] and not 'dns' in self.column_values['type'] and not 'conn' in self.column_values['type'] and not 'argus' in self.column_values['type']:
                return True

            # The first change we should do is to take into account different types of flows. A normal netflow is what we have now, but we need all
            # the zeek type of flows. So we need to adapt all the database?

            #########
            # 1st. Get the data from the interpreted columns
            separator = __database__.getFieldSeparator()

            # "self.column_values['starttime']" is for each type of input (zeek, argus, suricata)
            # defined as <class 'datetime.datetime'> object by us.
            if self.column_values['starttime']:
                # Function transform datetime to seconds in UTC.
                starttime = self.column_values['starttime'].timestamp()
            else:
                # We have no data about startime. It means that we did not detect it the time format.
                self.outputqueue.put("01|profiler|[Profile] We can not recognize time format.")

            # This uid check is for when we read things that are not zeek
            try:
                uid = self.column_values['uid']
            except KeyError:
                uid = ''
            flow_type = self.column_values['type']
            saddr = self.column_values['saddr']
            daddr = self.column_values['daddr']
            profileid = 'profile' + separator + str(saddr)

            if 'flow' in flow_type or 'conn' in flow_type or 'argus' in flow_type:
                dur = self.column_values['dur']
                sport = self.column_values['sport']
                dport = self.column_values['dport']
                sport = self.column_values['sport']
                proto = self.column_values['proto']
                state = self.column_values['state']
                pkts = self.column_values['pkts']
                allbytes = self.column_values['bytes']
                spkts = self.column_values['spkts']
                sbytes = self.column_values['sbytes']
                endtime = self.column_values['endtime']
                appproto = self.column_values['appproto']
                direction = self.column_values['dir']
                dpkts = self.column_values['dpkts']
                dbytes = self.column_values['dbytes']

            elif 'dns' in flow_type:
                query = self.column_values['query']
                qclass_name = self.column_values['qclass_name']
                qtype_name = self.column_values['qtype_name']
                rcode_name = self.column_values['rcode_name']
                answers = self.column_values['answers']
                ttls = self.column_values['TTLs']

            # Create the objects of IPs
            try:
                saddr_as_obj = ipaddress.IPv4Address(saddr)
                daddr_as_obj = ipaddress.IPv4Address(daddr)
                # Is ipv4
            except ipaddress.AddressValueError:
                # Is it ipv6?
                try:
                    saddr_as_obj = ipaddress.IPv6Address(saddr)
                    daddr_as_obj = ipaddress.IPv6Address(daddr)
                except ipaddress.AddressValueError:
                    # Its a mac
                    return False

            ##############
            # For Adding the profile only now

            # 2nd. Check home network
            # Check if the ip received (src_ip) is part of our home network. We only crate profiles for our home network
            if self.home_net and saddr_as_obj in self.home_net:
                # Its in our Home network

                # The steps for adding a flow in a profile should be
                # 1. Add the profile to the DB. If it already exists, nothing happens. So now profileid is the id of the profile to work with.
                # The width is unique for all the timewindow in this profile.
                # Also we only need to pass the width for registration in the DB. Nothing operational
                __database__.addProfile(profileid, starttime, self.width)

                # 3. For this profile, find the id in the database of the tw where the flow belongs.
                twid = self.get_timewindow(starttime, profileid)

            elif self.home_net and saddr_as_obj not in self.home_net:
                # The src ip is not in our home net

                # Check that the dst IP is in our home net. Like the flow is 'going' to it.
                if daddr_as_obj in self.home_net:
                    self.outputqueue.put("07|profiler|[Profiler] Flow with dstip in homenet: srcip {}, dstip {}".format(saddr_as_obj, daddr_as_obj))
                    # The dst ip is in the home net. So register this as going to it
                    # 1. Get the profile of the dst ip.
                    rev_profileid = __database__.getProfileIdFromIP(daddr_as_obj)
                    if not rev_profileid:
                        # We do not have yet the profile of the dst ip that is in our home net
                        self.outputqueue.put("07|profiler|[Profiler] The dstip profile was not here... create")
                        # Create a reverse profileid for managing the data going to the dstip.
                        # With the rev_profileid we can now work with data in relation to the dst ip
                        rev_profileid = 'profile' + separator + str(daddr_as_obj)
                        __database__.addProfile(rev_profileid, starttime, self.width)
                        # Try again
                        rev_profileid = __database__.getProfileIdFromIP(daddr_as_obj)
                        # For the profile to the dstip, find the id in the database of the tw where the flow belongs.
                        rev_twid = self.get_timewindow(starttime, rev_profileid)
                        if not rev_profileid:
                            # Too many errors. We should not be here
                            return False
                    self.outputqueue.put("07|profiler|[Profile] Profile for dstip {} : {}".format(daddr_as_obj, profileid))
                    # 2. For this profile, find the id in the databse of the tw where the flow belongs.
                    rev_twid = self.get_timewindow(starttime, profileid)
                elif daddr_as_obj not in self.home_net:
                    # The dst ip is also not part of our home net. So ignore completely
                    return False
            elif not self.home_net:
                # We don't have a home net, so create profiles for everyone

                # Add the profile for the srcip to the DB. If it already exists, nothing happens. So now profileid is the id of the profile to work with.
                __database__.addProfile(profileid, starttime, self.width)
                # Add the profile for the dstip to the DB. If it already exists, nothing happens. So now rev_profileid is the id of the profile to work with.
                rev_profileid = 'profile' + separator + str(daddr_as_obj)
                __database__.addProfile(rev_profileid, starttime, self.width)

                # For the profile from the srcip , find the id in the database of the tw where the flow belongs.
                twid = self.get_timewindow(starttime, profileid)
                # For the profile to the dstip, find the id in the database of the tw where the flow belongs.
                rev_twid = self.get_timewindow(starttime, rev_profileid)


            ##############
            # 4th Define help functions for storing data
            def store_features_going_out(profileid, twid):
                """
                This is an internal function in the add_flow_to_profile function for adding the features going out of the profile
                """

                if 'flow' in flow_type or 'conn' in flow_type or 'argus' in flow_type:
                    # Tuple
                    tupleid = str(daddr_as_obj) + ':' + str(dport) + ':' + proto
                    # Compute the symbol for this flow, for this TW, for this profile
                    # FIX
                    # symbol = ('a', '2019-01-26--13:31:09', 1)
                    symbol = self.compute_symbol(profileid, twid, tupleid, starttime, dur, allbytes, tuple_key='OutTuples')
                    # Add the out tuple
                    __database__.add_tuple(profileid, twid, tupleid, symbol, traffic_out=True)
                    # Add the dstip
                    __database__.add_ips(profileid, twid, daddr_as_obj, self.column_values, traffic_out=True)
                    # Add the dstport
                    __database__.add_port(profileid, twid, daddr_as_obj, self.column_values, traffic_out=True, dst_port=True)
                    # Add the srcport
                    __database__.add_port(profileid, twid, daddr_as_obj, self.column_values, traffic_out=True, dst_port=False)
                    # Add the flow with all the fields interpreted
                    __database__.add_flow(profileid=profileid, twid=twid, stime=starttime, dur=dur, saddr=str(saddr_as_obj), sport=sport, daddr=str(daddr_as_obj), dport=dport, proto=proto, state=state, pkts=pkts, allbytes=allbytes, spkts=spkts, sbytes=sbytes, appproto=appproto, uid=uid)
                elif 'dns' in flow_type:
                    __database__.add_out_dns(profileid, twid, flow_type, uid, query, qclass_name, qtype_name, rcode_name, answers, ttls)
                elif flow_type == 'http':
                    __database__.add_out_http(profileid, twid, flow_type, uid, self.column_values['method'], self.column_values['host'], self.column_values['uri'], self.column_values['httpversion'], self.column_values['user_agent'], self.column_values['request_body_len'], self.column_values['response_body_len'], self.column_values['status_code'], self.column_values['status_msg'], self.column_values['resp_mime_types'], self.column_values['resp_fuids'])
                elif flow_type == 'ssl':
                    __database__.add_out_ssl(profileid, twid, flow_type, uid, self.column_values['sslversion'], self.column_values['cipher'], self.column_values['resumed'], self.column_values['established'], self.column_values['cert_chain_fuids'], self.column_values['client_cert_chain_fuids'], self.column_values['subject'], self.column_values['issuer'], self.column_values['validation_status'], self.column_values['curve'], self.column_values['server_name'])

            def store_features_going_in(profileid, twid):
                """
                This is an internal function in the add_flow_to_profile function for adding the features going in of the profile
                """
                if 'flow' in flow_type or 'conn' in flow_type  or 'argus' in flow_type:
                    # Tuple
                    tupleid = str(saddr_as_obj) + ':' + str(dport) + ':' + proto
                    # Compute symbols.
                    # symbol = ('a', '2019-01-26--13:31:09', 1)
                    symbol = self.compute_symbol(profileid, twid, tupleid, starttime, dur, allbytes, tuple_key='InTuples')
                    # Add the src tuple
                    __database__.add_tuple(profileid, twid, tupleid, symbol, traffic_out=False)
                    # Add the srcip
                    __database__.add_ips(profileid, twid, saddr_as_obj, self.column_values, traffic_out=False)
                    # Add the dstport
                    __database__.add_port(profileid, twid, saddr_as_obj, self.column_values, traffic_out=False,
                                          dst_port=True)
                    # Add the srcport
                    __database__.add_port(profileid, twid, saddr_as_obj, self.column_values, traffic_out=False,
                                          dst_port=False)
                    # Add the flow with all the fields interpreted
                    __database__.add_flow(profileid=profileid, twid=twid, stime=starttime, dur=dur, saddr=str(saddr_as_obj),
                                          sport=sport, daddr=str(daddr_as_obj), dport=dport, proto=proto, state=state,
                                          pkts=pkts, allbytes=allbytes, spkts=spkts, sbytes=sbytes, appproto=appproto)

            ##########################################
            # 5th. Store the data according to the paremeters
            # Now that we have the profileid and twid, add the data from the flow in this tw for this profile
            self.outputqueue.put("07|profiler|[Profiler] Storing data in the profile: {}".format(profileid))

            # In which analysis mode are we?
            # Mode 'out'
            if self.analysis_direction == 'out':
                # Only take care of the stuff going out. Here we don't keep track of the stuff going in
                # If we have a home net and the flow comes from it, or if we don't have a home net and we are in out out.
                if (self.home_net and saddr_as_obj in self.home_net) or not self.home_net:
                    store_features_going_out(profileid, twid)

            # Mode 'all'
            elif self.analysis_direction == 'all':
                # Take care of both the stuff going out and in. In case the profile is for the srcip and for the dstip
                if not self.home_net:
                    # If we don't have a home net, just try to store everything coming OUT and IN to the IP
                    # Out features
                    store_features_going_out(profileid, twid)
                    # IN features
                    store_features_going_in(rev_profileid, rev_twid)
                else:
                    """
                    The flow is going TO homenet or FROM homenet or BOTH together.
                    """
                    # If we have a home net and the flow comes from it. Only the features going out of the IP
                    if saddr_as_obj in self.home_net:
                        store_features_going_out(profileid, twid)
                    # If we have a home net and the flow comes to it. Only the features going in of the IP
                    elif daddr_as_obj in self.home_net:
                        # The dstip was in the homenet. Add the src info to the dst profile
                        store_features_going_in(rev_profileid, rev_twid)

        except Exception as inst:
            # For some reason we can not use the output queue here.. check
            self.outputqueue.put("01|profiler|[Profile] Error in add_flow_to_profile profilerProcess. {}".format(traceback.format_exc()))
            self.outputqueue.put("01|profiler|[Profile] {}".format((type(inst))))
            self.outputqueue.put("01|profiler|[Profile] {}".format(inst))

    def compute_symbol(self, profileid, twid, tupleid, current_time, current_duration, current_size, tuple_key: str):
        """
        This function computes the new symbol for the tuple according to the original stratosphere ips model of letters
        Here we do not apply any detection model, we just create the letters as one more feature
        """
        try:
            current_duration = float(current_duration)
            current_size = int(current_size)
            now_ts = float(current_time)
            self.outputqueue.put("08|profiler|[Profile] Starting compute symbol. Tupleid {}, time:{} ({}), dur:{}, size:{}".format(tupleid, current_time, type(current_time), current_duration, current_size))
            # Variables for computing the symbol of each tuple
            T2 = False
            TD = False
            # Thresholds learng from Stratosphere ips first version
            # Timeout time, after 1hs
            tto = timedelta(seconds=3600)
            tt1 = float(1.05)
            tt2 = float(1.3)
            tt3 = float(5)
            td1 = float(0.1)
            td2 = float(10)
            ts1 = float(250)
            ts2 = float(1100)
            letter = ''
            symbol = ''
            timechar = ''

            # Get T1 (the time diff between the past flow and the past-past flow) from this tuple. T1 is a float in the db. Also get the time of the last flow in this tuple. In the DB prev time is a str
            # (T1, previous_time) = __database__.getT2ForProfileTW(profileid, twid, tupleid)

            (last_last_ts, last_ts) = __database__.getT2ForProfileTW(profileid, twid, tupleid, tuple_key)


            ## BE SURE THAT HERE WE RECEIVE THE PROPER DATA
            #T1 = timedelta(seconds=10)
            #previous_time = datetime.now() - timedelta(seconds=3600)

            # def compute_periodicity(now_ts: float, last_ts: float, last_last_ts: float) -> Tuple(int, str):
            def compute_periodicity(now_ts: float, last_ts: float, last_last_ts: float):
                """ Function to compute the periodicity """
                zeros = ''
                if last_last_ts is False or last_ts is False:
                    TD = -1
                else:
                    # Time diff between the past flow and the past-past flow.
                    T1 = last_ts - last_last_ts
                    # Time diff between the current flow and the past flow.
                    T2 = now_ts - last_ts

                    if T2 >= tto.total_seconds():
                        t2_in_hours = T2 / tto.total_seconds()
                        # Shoud we round it? Because for example:
                        #  7100 / 3600 =~ 1.972  ->  int(1.972) = 1
                        for i in range(int(t2_in_hours)):
                            # Add the 0000 to the symbol object
                            zeros += '0'
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

                return TD, zeros

            def compute_duration():
                """ Function to compute letter of the duration """
                if current_duration <= td1:
                    return 1
                elif current_duration > td1 and current_duration <= td2:
                    return 2
                elif current_duration > td2:
                    return 3

            def compute_size():
                """ Function to compute letter of the size """
                if current_size <= ts1:
                    return 1
                elif current_size > ts1 and current_size <= ts2:
                    return 2
                elif current_size > ts2:
                    return 3

            def compute_letter():
                """ Function to compute letter """
                if periodicity == -1:
                    if size == 1:
                        if duration == 1:
                            return '1'
                        elif duration == 2:
                            return '2'
                        elif duration == 3:
                            return '3'
                    elif size == 2:
                        if duration == 1:
                            return '4'
                        elif duration == 2:
                            return '5'
                        elif duration == 3:
                            return '6'
                    elif size == 3:
                        if duration == 1:
                            return '7'
                        elif duration == 2:
                            return '8'
                        elif duration == 3:
                            return '9'
                elif periodicity == 1:
                    if size == 1:
                        if duration == 1:
                            return 'a'
                        elif duration == 2:
                            return 'b'
                        elif duration == 3:
                            return 'c'
                    elif size == 2:
                        if duration == 1:
                            return 'd'
                        elif duration == 2:
                            return 'e'
                        elif duration == 3:
                            return 'f'
                    elif size == 3:
                        if duration == 1:
                            return 'g'
                        elif duration == 2:
                            return 'h'
                        elif duration == 3:
                            return 'i'
                elif periodicity == 2:
                    if size == 1:
                        if duration == 1:
                            return 'A'
                        elif duration == 2:
                            return 'B'
                        elif duration == 3:
                            return 'C'
                    elif size == 2:
                        if duration == 1:
                            return 'D'
                        elif duration == 2:
                            return 'E'
                        elif duration == 3:
                            return 'F'
                    elif size == 3:
                        if duration == 1:
                            return 'G'
                        elif duration == 2:
                            return 'H'
                        elif duration == 3:
                            return 'I'
                elif periodicity == 3:
                    if size == 1:
                        if duration == 1:
                            return 'r'
                        elif duration == 2:
                            return 's'
                        elif duration == 3:
                            return 't'
                    elif size == 2:
                        if duration == 1:
                            return 'u'
                        elif duration == 2:
                            return 'v'
                        elif duration == 3:
                            return 'w'
                    elif size == 3:
                        if duration == 1:
                            return 'x'
                        elif duration == 2:
                            return 'y'
                        elif duration == 3:
                            return 'z'
                elif periodicity == 4:
                    if size == 1:
                        if duration == 1:
                            return 'R'
                        elif duration == 2:
                            return 'S'
                        elif duration == 3:
                            return 'T'
                    elif size == 2:
                        if duration == 1:
                            return 'U'
                        elif duration == 2:
                            return 'V'
                        elif duration == 3:
                            return 'W'
                    elif size == 3:
                        if duration == 1:
                            return 'X'
                        elif duration == 2:
                            return 'Y'
                        elif duration == 3:
                            return 'Z'

            def compute_timechar():
                """ Function to compute the timechar """
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
                        return '0'

            # Here begins the function's code
            try:
                # Update value of T2
                # T2 = current_time - previous_time
                T2 = now_ts - last_ts
                # Are flows sorted?
                if T2 < 0:
                    # Flows are not sorted!
                    # What is going on here when the flows are not ordered?? Are we losing flows?
                    # Put a warning
                    self.outputqueue.put("01|profiler|[Profile] Warning: Coming flows are not sorted -> Some time diff are less than zero.")
            except TypeError:
                T2 = False
            # self.outputqueue.put("01|profiler|[Profile] T2:{}".format(T2))

            # Compute the rest
            periodicity, zeros = compute_periodicity(now_ts, last_ts, last_last_ts)
            # self.outputqueue.put("01|profiler|[Profile] Periodicity: {}".format(periodicity))
            # if zeros == '':
            duration = compute_duration()
            # self.outputqueue.put("01|profiler|[Profile] Duration: {}".format(duration))
            size = compute_size()
            # self.outputqueue.put("01|profiler|[Profile] Size: {}".format(size))
            letter = compute_letter()
            # self.outputqueue.put("01|profiler|[Profile] Letter: {}".format(letter))

            timechar = compute_timechar()
            # self.outputqueue.put("01|profiler|[Profile] TimeChar: {}".format(timechar))

            symbol = zeros + letter + timechar
            # Return the symbol, the current time of the flow and the T1 value
            return symbol, (last_ts, now_ts)
        except Exception as inst:
            # For some reason we can not use the output queue here.. check
            self.outputqueue.put("01|profiler|[Profile] Error in compute_symbol in profilerProcess.")
            self.outputqueue.put("01|profiler|[Profile] {}".format(type(inst)))
            self.outputqueue.put("01|profiler|[Profile] {}".format(inst))
            self.outputqueue.put("01|profiler|[Profile] {}".format(traceback.format_exc()))

    def get_timewindow(self, flowtime, profileid):
        """"
        This function should get the id of the TW in the database where the flow belong.
        If the TW is not there, we create as many tw as necessary in the future or past until we get the correct TW for this flow.
        - We use this function to avoid retrieving all the data from the DB for the complete profile. We use a separate table for the TW per profile.
        -- Returns the time window id
        THIS IS NOT WORKING:
        - The empty profiles in the middle are not being created!!!
        - The Dtp ips are stored in the first time win
        """
        try:
            # First check of we are not in the last TW. Since this will be the majority of cases
            try:
                [(lasttwid, lasttw_start_time)] = __database__.getLastTWforProfile(profileid)
                lasttw_start_time = float(lasttw_start_time)
                lasttw_end_time = lasttw_start_time + self.width
                flowtime = float(flowtime)
                self.outputqueue.put("04|profiler|[Profiler] The last TW id was {}. Start:{}. End: {}".format(lasttwid, lasttw_start_time, lasttw_end_time))
                # There was a last TW, so check if the current flow belongs here.
                if lasttw_end_time > flowtime and lasttw_start_time <= flowtime:
                    self.outputqueue.put("04|profiler|[Profiler] The flow ({}) is on the last time window ({})".format(flowtime, lasttw_end_time))
                    twid = lasttwid
                elif lasttw_end_time <= flowtime:
                    # The flow was not in the last TW, its NEWER than it
                    self.outputqueue.put("04|profiler|[Profiler] The flow ({}) is NOT on the last time window ({}). Its newer".format(flowtime, lasttw_end_time))
                    amount_of_new_tw = int((flowtime - lasttw_end_time) / self.width)
                    self.outputqueue.put("04|profiler|[Profiler] We have to create {} empty TWs in the midle.".format(amount_of_new_tw))
                    temp_end = lasttw_end_time
                    for id in range(0, amount_of_new_tw + 1):
                        new_start = temp_end
                        twid = __database__.addNewTW(profileid, new_start)
                        self.outputqueue.put("04|profiler|[Profiler] Creating the TW id {}. Start: {}.".format(twid, new_start))
                        temp_end = new_start + self.width
                    # Now get the id of the last TW so we can return it
                elif lasttw_start_time > flowtime:
                    # The flow was not in the last TW, its OLDER that it
                    self.outputqueue.put("04|profiler|[Profiler] The flow ({}) is NOT on the last time window ({}). Its older".format(flowtime, lasttw_end_time))
                    # Find out if we already have this TW in the past
                    data = __database__.getTWforScore(profileid, flowtime)
                    if data:
                        # We found a TW where this flow belongs to
                        (twid, tw_start_time) = data
                        return twid
                    else:
                        # There was no TW that included the time of this flow, so create them in the past
                        # How many new TW we need in the past?
                        # amount_of_new_tw is the total amount of tw we should have under the new situation
                        amount_of_new_tw = int((lasttw_end_time - flowtime) / self.width)
                        # amount_of_current_tw is the real amount of tw we have now
                        amount_of_current_tw = __database__.getamountTWsfromProfile(profileid)
                        # diff is the new ones we should add in the past. (Yes, we could have computed this differently)
                        diff = amount_of_new_tw - amount_of_current_tw
                        self.outputqueue.put("05|profiler|[Profiler] We need to create {} TW before the first".format(diff + 1))
                        # Get the first TW
                        [(firsttwid, firsttw_start_time)] = __database__.getFirstTWforProfile(profileid)
                        firsttw_start_time = float(firsttw_start_time)
                        # The start of the new older TW should be the first - the width
                        temp_start = firsttw_start_time - self.width
                        for id in range(0, diff + 1):
                            new_start = temp_start
                            # The method to add an older TW is the same as to add a new one, just the starttime changes
                            twid = __database__.addNewOlderTW(profileid, new_start)
                            self.outputqueue.put("02|profiler|[Profiler] Creating the new older TW id {}. Start: {}.".format(twid, new_start))
                            temp_start = new_start - self.width
            except ValueError:
                # There is no last tw. So create the first TW
                # If the option for only-one-tw was selected, we should create the TW at least 100 years before the flowtime, to cover for
                # 'flows in the past'. Which means we should cover for any flow that is coming later with time before the first flow
                if self.width == 9999999999:
                    # Seconds in 1 year = 31536000
                    startoftw = float(flowtime - (31536000 * 100))
                else:
                    startoftw = float(flowtime)
                # Add this TW, of this profile, to the DB
                twid = __database__.addNewTW(profileid, startoftw)
                #self.outputqueue.put("01|profiler|First TW ({}) created for profile {}.".format(twid, profileid))
            return twid
        except Exception as e:
            self.outputqueue.put("01|profiler|[Profile] Error in get_timewindow().")
            self.outputqueue.put("01|profiler|[Profile] {}".format(e))

    def run(self):
        # Main loop function
        try:
            rec_lines = 0
            while True:
                line = self.inputqueue.get()
                if 'stop' == line:
                    self.outputqueue.put("01|profiler|[Profile] Stopping Profiler Process. Received {} lines ({})".format(rec_lines, datetime.now().strftime('%Y-%m-%d--%H:%M:%S')))
                    return True
                else:
                    # Received new input data
                    # Extract the columns smartly
                    self.outputqueue.put("03|profiler|[Profile] < Received Line: {}".format(line))
                    rec_lines += 1
                    if not self.input_type:
                        # Find the type of input received
                        # This line will be discarded because
                        self.define_type(line)
                        # We should do this before checking the type of input so we don't lose the first line of input

                    # What type of input do we have?
                    if self.input_type == 'zeek':
                        #self.print('Zeek line')
                        self.process_zeek_input(line)
                        # Add the flow to the profile
                        self.add_flow_to_profile()

                    elif self.input_type == 'argus':
                        #self.print('Argus line')
                        # Argus puts the definition of the columns on the first line only
                        # So read the first line and define the columns

                        # Are the columns defined?
                        try:
                            temp = self.column_idx['starttime']
                            # Yes
                            # Quickly process all lines
                            self.process_argus_input(line)
                            # Add the flow to the profile
                            self.add_flow_to_profile()
                        except AttributeError:
                            # No. Define columns. Do not add this line to profile, its only headers
                            self.define_columns(line)

                    elif self.input_type == 'suricata':
                        #self.print('Suricata line')
                        self.process_suricata_input(line)
                        # Add the flow to the profile
                        self.add_flow_to_profile()

                    elif self.input_type == 'zeek-tabs':
                        #self.print('Zeek-tabs line')
                        self.process_zeek_tabs_input(line)
                        # Add the flow to the profile
                        self.add_flow_to_profile()
                    elif self.input_type == 'nfdump':
                        self.process_nfdump_input(line)
                        self.add_flow_to_profile()
        except KeyboardInterrupt:
            self.outputqueue.put("01|profiler|[Profile] Received {} lines.".format(rec_lines))
            return True
        except Exception as inst:
            self.outputqueue.put("01|profiler|[Profile] Error. Stopped Profiler Process. Received {} lines".format(rec_lines))
            self.outputqueue.put("01|profiler|\tProblem with Profiler Process.")
            self.outputqueue.put("01|profiler|"+str(type(inst)))
            self.outputqueue.put("01|profiler|"+str(inst.args))
            self.outputqueue.put("01|profiler|"+str(inst))
            self.outputqueue.put(
                "01|profiler|[Profile] Error in profilerProcess. {}".format(traceback.format_exc()))
            return True
