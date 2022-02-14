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
import multiprocessing
import json
from datetime import datetime
from datetime import timedelta
import sys
import configparser
from slips_files.core.database import __database__
import time
import ipaddress
import traceback
import os
import binascii
import base64
import subprocess
from re import split
from tzlocal import get_localzone
import validators
import socket
import requests

def timeit(method):
    def timed(*args, **kw):
        ts = time.time()
        result = method(*args, **kw)
        te = time.time()
        if 'log_time' in kw:
            name = kw.get('log_name', method.__name__.upper())
            kw['log_time'][name] = int((te - ts) * 1000)
        else:
            print(f'\t\033[1;32;40mFunction {method.__name__}() took {(te - ts) * 1000:2.2f}ms\033[00m')
        return result
    return timed

# Profiler Process
class ProfilerProcess(multiprocessing.Process):
    """ A class to create the profiles for IPs and the rest of data """
    def __init__(self, inputqueue, outputqueue, verbose, debug, config):
        self.name = 'ProfilerProcess'
        multiprocessing.Process.__init__(self)
        self.inputqueue = inputqueue
        self.outputqueue = outputqueue
        self.config = config
        self.columns_defined = False
        self.timeformat = None
        self.input_type = False
        # Read the configuration
        self.read_configuration()
        # Read the whitelist
        # anything in this list will be ignored
        self.read_whitelist()
        # Start the DB
        __database__.start(self.config)
        # Set the database output queue
        __database__.setOutputQueue(self.outputqueue)
        # 1st. Get the data from the interpreted columns
        self.id_separator = __database__.getFieldSeparator()
        # get the user's local timezone
        self.local_timezone = get_localzone()
        self.verbose = verbose
        self.debug = debug
        # there has to be a timeout or it will wait forever and never receive a new line
        self.timeout = 0.0000001
        self.c1 = __database__.subscribe('reload_whitelist')

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
        self.outputqueue.put(f"{levels}|{self.name}|{text}")

    def read_configuration(self):
        """ Read the configuration file for what we need """
        # Get the home net if we have one from the config
        try:
            self.home_net = ipaddress.ip_network(self.config.get('parameters', 'home_network'))
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no
            # configuration file specified
            self.home_net = False
        try:
            self.whitelist_path = self.config.get('parameters', 'whitelist_path')
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            self.whitelist_path = 'whitelist.conf'

        # Get the time window width, if it was not specified as a parameter
        try:
            data = self.config.get('parameters', 'time_window_width')
            self.width = float(data)
        except ValueError:
            # Its not a float
            if 'only_one_tw' in data:
                # Only one tw. Width is 10 9s, wich is ~11,500 days, ~311 years
                self.width = 9999999999
        except configparser.NoOptionError:
            # By default we use 3600 seconds, 1hs
            self.width = 3600
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no
            # configuration file specified
            self.width = 3600

        # Report the time window width
        if self.width == 9999999999:
            self.print(f'Time Windows Width used: {self.width} seconds. Only 1 time windows. Dates in the names of files are 100 years in the past.', 3, 0)
        else:
            self.print(f'Time Windows Width used: {self.width} seconds.', 3, 0)

        # Get the format of the time in the flows
        try:
            self.timeformat = self.config.get('timestamp', 'format')
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            # This has to be None, beacause we try to detect the time format below, if it is None.
            self.timeformat = None
        ##
        # Get the direction of analysis
        try:
            self.analysis_direction = self.config.get('parameters', 'analysis_direction')
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            # By default
            self.analysis_direction = 'all'
        # Get the default label for all this flow. Used during training usually
        try:
            self.label = self.config.get('parameters', 'label')
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            # By default
            self.label = 'unknown'

    def read_whitelist(self):
        """ Reads the content of whitelist.conf and stores information about each ip/org/domain in the database """

        # since this function can be run when the user modifies whitelist.conf
        # we need to check if the dicts are already there
        whitelisted_IPs = __database__.get_whitelist('IPs')
        whitelisted_domains = __database__.get_whitelist('domains')
        whitelisted_orgs = __database__.get_whitelist('organizations')
        whitelisted_mac = __database__.get_whitelist('mac')

        try:
            with open(self.whitelist_path) as whitelist:
                # Process lines after comments
                line_number = 0
                line = whitelist.readline()
                while line:
                    line_number+=1
                    if line.startswith('"IoCType"'):
                        line = whitelist.readline()
                        continue

                    # check if the user commented an org, ip or domain that was whitelisted
                    if line.startswith('#'):
                        if whitelisted_IPs:
                            for ip in list(whitelisted_IPs):
                                # make sure the user commented the line we have in cache exactly
                                if ip in line and whitelisted_IPs[ip]['from'] in line and whitelisted_IPs[ip]['what_to_ignore'] in line:
                                    # remove that entry from whitelisted_ips
                                    whitelisted_IPs.pop(ip)
                                    break

                        if whitelisted_domains:
                            for domain in list(whitelisted_domains):
                                if domain in line \
                                and whitelisted_domains[domain]['from'] in line \
                                and whitelisted_domains[domain]['what_to_ignore'] in line:
                                    # remove that entry from whitelisted_domains
                                    whitelisted_domains.pop(domain)
                                    break

                        if whitelisted_orgs:
                            for org in list(whitelisted_orgs):
                                if org in line \
                                and whitelisted_orgs[org]['from'] in line \
                                and whitelisted_orgs[org]['what_to_ignore'] in line:
                                    # remove that entry from whitelisted_domains
                                    whitelisted_orgs.pop(org)
                                    break

                        # todo if the user closes slips, changes the whitelist, and reopens slips , slips will still have the old whitelist in the cache!
                        line = whitelist.readline()
                        continue
                    # line should be: ["type","domain/ip/organization","from","what_to_ignore"]
                    line = line.replace("\n","").replace(" ","").split(",")
                    try:
                        type_ , data, from_ , what_to_ignore = (line[0]).lower(), line[1], line[2], line[3]
                    except IndexError:
                        # line is missing a column, ignore it.
                        self.print(f"Line {line_number} in whitelist.conf is missing a column. Skipping.")
                        line = whitelist.readline()
                        continue

                    # Validate the type before processing
                    try:
                        if ('ip' in type_ and
                            (validators.ip_address.ipv6(data) or validators.ip_address.ipv4(data))):
                            whitelisted_IPs[data] = {'from': from_, 'what_to_ignore': what_to_ignore}
                        elif 'domain' in type_ and validators.domain(data):
                            whitelisted_domains[data] = {'from': from_, 'what_to_ignore': what_to_ignore}
                        elif 'mac' in type_ and validators.mac_address(data):
                            whitelisted_mac[data] = {'from': from_, 'what_to_ignore': what_to_ignore}
                        elif 'org' in type_:
                            #organizations dicts look something like this:
                            #  {'google': {'from':'dst',
                            #               'what_to_ignore': 'alerts'
                            #               'IPs': {'34.64.0.0/10': subnet}}
                            try:
                                # org already whitelisted, update info
                                whitelisted_orgs[data]['from'] = from_
                                whitelisted_orgs[data]['what_to_ignore'] = what_to_ignore
                            except KeyError:
                                # first time seeing this org
                                whitelisted_orgs[data] = {'from' : from_, 'what_to_ignore' : what_to_ignore}

                        else:
                            self.print(f"{data} is not a valid {type_}.",1,0)
                    except:
                        self.print(f"Line {line_number} in whitelist.conf is invalid. Skipping.")
                    line = whitelist.readline()
        except FileNotFoundError:
            self.print(f"Can't find {self.whitelist_path}, using slips default whitelist.conf instead")
            if self.whitelist_path != 'whitelist.conf':
                self.whitelist_path = 'whitelist.conf'
                self.read_whitelist()


        # after we're done reading the file, process organizations info and store in the db
        orgs_in_cache = __database__.get_whitelist('organizations')
        for org in whitelisted_orgs:
            # make sure we don't already have info about this org in the cache db
            if orgs_in_cache and org in orgs_in_cache:
                # we have orgs in cache but do we have this org?
                # if we have the org in cache , we have its ips domains and asn, skip it
                continue

            # Store the IPs, domains and asn of this org in the db
            org_subnets = self.load_org_IPs(org)
            if org_subnets:
                # Store the IPs of this org
                whitelisted_orgs[org].update({'IPs' : json.dumps(org_subnets)})

            org_domains = self.load_org_domains(org)
            if org_domains:
                # Store the ASN of this org
                whitelisted_orgs[org].update({'domains' : json.dumps(org_domains)})

            org_asn = self.load_org_asn(org)
            if org_asn:
                # Store the ASN of this org
                whitelisted_orgs[org].update({'asn' : json.dumps(org_asn)})

        # store everything in the cache db because we'll be needing this info in the evidenceProcess
        __database__.set_whitelist("IPs", whitelisted_IPs)
        __database__.set_whitelist("domains", whitelisted_domains)
        __database__.set_whitelist("organizations", whitelisted_orgs)
        __database__.set_whitelist("mac", whitelisted_mac)

        return line_number

    def load_org_asn(self, org) -> list :
        """
        Reads the specified org's asn from slips_files/organizations_info and stores the info in the database
        org: 'google', 'facebook', 'twitter', etc...
        returns a list containing the org's asn
        """
        try:
            # Each file is named after the organization's name followed by _asn
            org_asn =[]
            file = f'slips_files/organizations_info/{org}_asn'
            with open(file,'r') as f:
                line = f.readline()
                while line:
                    # each line will be something like this: 34.64.0.0/10
                    line = line.replace("\n","").strip()
                    org_asn.append(line)
                    line = f.readline()
            return org_asn

        except (FileNotFoundError, IOError):
            # theres no slips_files/organizations_info/{org}_asn for this org
            # see if the org has asn cached in our db
            asn_cache = __database__.get_asn_cache()
            org_asn =[]
            for asn in asn_cache:
                if org in asn.lower():
                    org_asn.append(org)
            if org_asn != []: return org_asn
            return False

    def load_org_domains(self, org) -> list :
        """
        Reads the specified org's domains from slips_files/organizations_info and stores the info in the database
        org: 'google', 'facebook', 'twitter', etc...
        returns a list containing the org's domains
        """
        try:
            # Each file is named after the organization's name followed by _domains
            domains =[]
            file = f'slips_files/organizations_info/{org}_domains'
            with open(file,'r') as f:
                line = f.readline()
                while line:
                    # each line will be something like this: 34.64.0.0/10
                    line = line.replace("\n","").strip()
                    domains.append(line)
                    line = f.readline()
            return domains
        except (FileNotFoundError, IOError):
            return False

    def load_org_IPs(self, org) -> list :
        """
        Reads the specified org's info from slips_files/organizations_info and stores the info in the database
        if there's no file for this org, it get the IP ranges from asnlookup.com
        org: 'google', 'facebook', 'twitter', etc...
        returns a list of this organization's subnets
        """
        try:
            # Each file is named after the organization's name
            # Each line of the file containes an ip range, for example: 34.64.0.0/10
            org_subnets = []
            file = f'slips_files/organizations_info/{org}'
            with open(file,'r') as f:
                line = f.readline()
                while line:
                    # each line will be something like this: 34.64.0.0/10
                    line = line.replace("\n","").strip()
                    try:
                        # make sure this line is a valid network
                        is_valid_line = ipaddress.ip_network(line)
                        org_subnets.append(line)
                    except ValueError:
                        # not a valid line, ignore it
                        pass
                    line = f.readline()
            return org_subnets
        except (FileNotFoundError, IOError):
            # there's no slips_files/organizations_info/{org} for this org
            org_subnets = []
            # see if we can get asn about this org
            try:
                response = requests.get('http://asnlookup.com/api/lookup?org=' + org.replace('_', ' '),
                                        headers ={  'User-Agent': 'ASNLookup PY/Client'}, timeout = 10)
            except requests.exceptions.ConnectionError:
                # Connection reset by peer
                return False
            ip_space = json.loads(response.text)
            if ip_space:
                with open(f'slips_files/organizations_info/{org}','w') as f:
                    for subnet in ip_space:
                        # get ipv4 only
                        if ':' not in subnet:
                            try:
                                # make sure this line is a valid network
                                is_valid_line = ipaddress.ip_network(subnet)
                                f.write(subnet + '\n')
                                org_subnets.append(subnet)
                            except ValueError:
                                # not a valid line, ignore it
                                continue
                return org_subnets
            else:
                # can't get org IPs from asnlookup.com
                return False

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
                # Did data came with the json format?
                data = line['data']
                file_type = line['type']
                # Yes
            except KeyError:
                # No
                data = line
                file_type = ''
                self.print('\tData did not arrived in json format from the input', 0, 1)
                self.print('\tProblem in define_type()', 0, 1)
                return False
            # In the case of Zeek from an interface or pcap,
            # the structure is a JSON
            # So try to convert into a dict
            if type(data) == dict:
                try:
                    _ = data['data']
                    self.separator = '	'
                    self.input_type = 'zeek-tabs'
                except KeyError:
                    self.input_type = 'zeek'
                return self.input_type

            else:
                # data is a str
                try:
                    # data is a serialized json dict
                    # suricata lines have 'event_type' key, either flow, dns, etc..
                    data = json.loads(data)
                    if data['event_type']:
                        # found the key, is suricata
                        self.input_type = 'suricata'
                except ValueError:
                    # not suricata, data is a tab or comma separated str
                    nr_commas = len(data.split(','))
                    nr_tabs = len(data.split('   '))
                    if nr_commas > nr_tabs:
                        # Commas is the separator
                        self.separator = ','
                        if nr_commas > 40:
                            self.input_type = 'nfdump'
                        else:
                            # comma separated argus file
                            self.input_type = 'argus'
                    elif nr_tabs >= nr_commas:
                        # Tabs is the separator
                        # Probably a conn.log file alone from zeek
                        # probably a zeek tab file or a binetflow tab file
                        if '->' in data or 'StartTime' in data:
                            self.separator = '\t'
                            self.input_type = 'argus-tabs'
                        else:
                            self.separator = '	'
                            self.input_type = 'zeek-tabs'

                return self.input_type
        except Exception as inst:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(f'\tProblem in define_type() line {exception_line}', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst), 0, 1)
            sys.exit(1)

    def define_columns(self, new_line):
        """ Define the columns for Argus and Zeek-tabs from the line received """
        # These are the indexes for later fast processing
        line = new_line['data']
        self.column_idx = {
            'starttime' : False,
            'endtime' : False,
            'dur' : False,
            'proto' : False,
            'appproto' : False,
            'saddr' : False,
            'sport' : False,
            'dir' : False,
            'daddr' : False,
            'dport' : False,
            'state' : False,
            'pkts' : False,
            'spkts' : False,
            'dpkts' : False,
            'bytes' : False,
            'sbytes' : False,
            'dbytes' : False}

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
            return self.column_idx
        except Exception as inst:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(f'\tProblem in define_columns() line {exception_line}', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst), 0, 1)
            sys.exit(1)

    def define_time_format(self, time: str) -> str:
        time_format: str = None
        try:
            # Try unix timestamp in seconds.
            datetime.fromtimestamp(float(time))
            time_format = 'unixtimestamp'
            return time_format
        except ValueError:
            pass

        try:
            # Try the default time format for suricata.
            datetime.strptime(time, '%Y-%m-%dT%H:%M:%S.%f%z')
            time_format = '%Y-%m-%dT%H:%M:%S.%f%z'
            return time_format
        except ValueError:
            pass

        # Let's try the classic time format "'%Y-%m-%d %H:%M:%S.%f'"
        try:
            datetime.strptime(time, '%Y-%m-%d %H:%M:%S.%f')
            time_format = '%Y-%m-%d %H:%M:%S.%f'
            return time_format
        except ValueError:
            pass

        try:
            datetime.strptime(time, '%Y-%m-%d %H:%M:%S')
            time_format = '%Y-%m-%d %H:%M:%S'
            return time_format
        except ValueError:
            pass

        try:
            datetime.strptime(time, '%Y/%m/%d %H:%M:%S.%f')
            time_format = '%Y/%m/%d %H:%M:%S.%f'
            return time_format
        except ValueError:
            # We did not find the right time format.
            self.outputqueue.put("01|profiler|[Profile] We did not find right time format. Please set the time format in the configuration file.")


    def get_time(self, time: str) -> datetime:
        """
        Take time in string and return datetime object.
        The format of time can be completely different. It can be seconds, or dates with specific formats.
        If user does not define the time format in configuration file, we have to try most frequent cases of time formats.
        :param time: epoch time
        """

        if not self.timeformat:
            # The time format was not defined from configuration file neither from last flows.
            self.timeformat = self.define_time_format(time)

        defined_datetime: datetime = None
        if self.timeformat:
            if self.timeformat == 'unixtimestamp':
                # The format of time is in epoch unix timestamp.
                # Correct datetime according to the current timezone
                defined_datetime = datetime.fromtimestamp(float(time), self.local_timezone)
            else:
                try:
                    # The format of time is a complete date.
                    # Dont modify it, since
                    # 1) The time is a string, so we dont know the original timezone
                    # 2) the python call datetime.fromtimestamp uses by default
                    # the local zone when nothing is specified.
                    # https://docs.python.org/3/library/datetime.html#datetime.timezone
                    # convert epoch to datetime obj and use the current timezone
                    #self.print(time)
                    #self.print(self.local_timezone)
                    #defined_datetime = datetime.strptime(time, self.timeformat)#.astimezone(self.local_timezone)
                    #defined_datetime = datetime.fromtimestamp(float(time), self.local_timezone)
                    #defined_datetime = datetime.fromtimestamp(float(time), self.local_timezone)
                    # convert dt obj to user specified tiemformat
                    #defined_datetime = defined_datetime.strftime(self.timeformat)
                    defined_datetime = time
                except ValueError:
                    defined_datetime = None
        else:
            # We do not know the time format so we can not read it.
            self.outputqueue.put(
                "01|profiler|[Profile] We did not find right time format. Please set the time format in the configuration file.")

        # if defined_datetime is None and self.timeformat:
            # There is suricata issue with invalid timestamp for examaple: "1900-01-00T00:00:08.511802+0000"
            # pass
        return defined_datetime

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
            self.column_values['starttime'] = self.get_time(line[0])
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

        if 'conn' in new_line['type']:
            self.column_values['type'] = 'conn'
            try:
                self.column_values['dur'] = float(line[8])
            except (IndexError, ValueError):
                self.column_values['dur'] = 0
            self.column_values['endtime'] = str(self.column_values['starttime']) + str(timedelta(seconds=self.column_values['dur']))
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
            self.column_values['pkts'] = self.column_values['spkts'] + self.column_values['dpkts']
            try:
                self.column_values['sbytes'] = float(line[9])
            except (IndexError, ValueError):
                self.column_values['sbytes'] = 0
            try:
                self.column_values['dbytes'] = float(line[10])
            except (IndexError, ValueError):
                self.column_values['dbytes'] = 0
            self.column_values['bytes'] = self.column_values['sbytes'] + self.column_values['dbytes']
            try:
                self.column_values['state_hist'] = line[15]
            except IndexError:
                self.column_values['state_hist'] = self.column_values['state']
            # We do not know the indexes of MACs.
            self.column_values['smac'] = ''
            self.column_values['dmac'] = ''
        elif 'dns' in new_line['type']:
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
                self.column_values['answers'] = line[21]
                if type(self.column_values['answers']) == str:
                    # If the answer is only 1, Zeek gives a string
                    # so convert to a list
                    self.column_values['answers'] =[self.column_values['answers']]
            except IndexError:
                self.column_values['answers'] = ''
            try:
                self.column_values['TTLs'] = line[22]
            except IndexError:
                self.column_values['TTLs'] = ''
        elif 'http' in new_line['type']:
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
        elif 'ssl' in new_line['type']:
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

        elif 'ssh' in new_line['type']:
            self.column_values['type'] = 'ssh'
            try:
                self.column_values['version'] = line[6]
            except IndexError:
                self.column_values['version'] = ''
            # Zeek can put in column 7 the auth success if it has one
            # or the auth attempts only. However if the auth
            # success is there, the auth attempts are too.
            if 'success' in line[7]:
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
            elif 'success' not in line[7]:
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
        elif 'dhcp' in new_line['type']:
            self.column_values['type'] = 'dhcp'
            #  daddr in dhcp.log is the server_addr at index 3, not 4 like most log files
            self.column_values['daddr'] = line[3]
            self.column_values['client_addr'] = line[2] # the same as saddr
            self.column_values['server_addr'] = line[3]
            self.column_values['mac'] = line[4] # this is the client mac
            self.column_values['host_name'] = line[5]
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
        elif 'smtp' in new_line['type']:
            self.column_values['type'] = 'smtp'
        elif 'socks' in new_line['type']:
            self.column_values['type'] = 'socks'
        elif 'syslog' in new_line['type']:
            self.column_values['type'] = 'syslog'
        elif 'tunnel' in new_line['type']:
            self.column_values['type'] = 'tunnel'
        elif 'notice' in new_line['type']:
            #fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	fuid	file_mime_type	file_desc
            # proto	note	msg	sub	src	dst	p	n	peer_descr	actions	suppress_for
            self.column_values['type'] = 'notice'
            # portscan notices don't have id.orig_h or id.resp_h fields, instead they have src and dst
            if self.column_values['saddr'] == '-' :
                try:
                    self.column_values['saddr'] = line[13] #  src field
                except IndexError:
                    # line doesn't have a p field
                    # keep it - as it is
                    pass

            if self.column_values['daddr'] == '-':
                self.column_values['daddr'] = line[14]  #  dst field
                if self.column_values['daddr'] == '-':
                    self.column_values['daddr'] = self.column_values['saddr']

            self.column_values['dport'] = line[5] # id.orig_p
            if self.column_values['dport'] == '-':
                try:
                    self.column_values['dport'] = line[15] # p field
                except IndexError:
                    # line doesn't have a p field
                    # keep it - as it is
                    pass
            self.column_values['sport'] = line[3]
            self.column_values['note'] = line[10]
            self.column_values['scanning_ip'] = self.column_values['saddr']
            self.column_values['scanned_port'] =  self.column_values['dport']
            self.column_values['msg'] = line[11] # we're looking for self signed certs in this field
        elif '/files' in new_line['type']:
            self.column_values['type'] = 'files'
            self.column_values['uid'] = line[4]
            self.column_values['saddr'] = line[2]
            self.column_values['daddr'] = line[3] #rx_hosts
            self.column_values['size'] = line[13]
            self.column_values['md5'] = line[19]
        elif 'arp' in new_line['type']:
            self.column_values['type'] = 'arp'
            self.column_values['operation'] = line[1]
            self.column_values['src_mac'] = line[2]
            self.column_values['dst_mac'] = line[3]
            self.column_values['saddr'] = line[4]
            self.column_values['daddr'] = line[5]
            self.column_values['src_hw'] = line[6]
            self.column_values['dst_hw'] = line[7]

    def process_zeek_input(self, new_line: dict):
        """
        Process one zeek line(new_line) and extract columns
        (parse them into column_values dict) to send to the database
        """
        line = new_line['data']
        file_type = new_line['type']
        # if the zeek dir given to slips has 'conn' in it's name,
        # slips thinks it's reading a conn file
        # because we use the file path as the file 'type'
        # to fix this, only use the file name as file 'type'
        file_type = file_type.split('/')[-1]
        # Generic fields in Zeek
        self.column_values = {}
        # We need to set it to empty at the beggining so any new flow has the key 'type'
        self.column_values['type'] = ''

        # to set the default value to '' if ts isn't found
        ts = line.get('ts',False)
        if ts:
            self.column_values['starttime'] = self.get_time(ts)
        else:
            self.column_values['starttime'] = ''

        self.column_values['uid'] = line.get('uid',False)
        self.column_values['saddr'] = line.get('id.orig_h','')
        self.column_values['daddr'] = line.get('id.resp_h','')

        # Handle each zeek file type separately
        if 'conn' in file_type:
            # {'ts': 1538080852.403669, 'uid': 'Cewh6D2USNVtfcLxZe', 'id.orig_h': '192.168.2.12', 'id.orig_p': 56343,
            # 'id.resp_h': '192.168.2.1', 'id.resp_p': 53, 'proto': 'udp', 'service': 'dns', 'duration': 0.008364,
            # 'orig_bytes': 30, 'resp_bytes': 94, 'conn_state': 'SF', 'missed_bytes': 0, 'history': 'Dd', 'orig_pkts': 1,
            # 'orig_ip_bytes': 58, 'resp_pkts': 1, 'resp_ip_bytes': 122, 'orig_l2_addr': 'b8:27:eb:6a:47:b8',
            # 'resp_l2_addr': 'a6:d1:8c:1f:ce:64', 'type': './zeek_files/conn'}

            self.column_values.update({
                'type' :  'conn',
                'dur': float(line.get('duration',0)),
                'endtime' : str(self.column_values['starttime']) + str(timedelta(seconds=float(line.get('duration',0)))),
                'proto' : line['proto'],
                'appproto' : line.get('service',''),
                'sport' : line.get('id.orig_p',''),
                'dport' : line.get('id.resp_p',''),
                'state' : line.get('conn_state',''),
                'dir' : '->',
                'spkts' : line.get('orig_pkts',0),
                'dpkts' : line.get('resp_pkts',0),
                'sbytes' : line.get('orig_bytes',0),
                'dbytes' : line.get('resp_bytes',0),
                'pkts' : line.get('orig_bytes',0) + line.get('resp_pkts',0),
                'bytes' :  line.get('orig_bytes',0) + line.get('resp_bytes',0),
                'state_hist' : line.get('history', line.get('conn_state','')),
                'smac' : line.get('orig_l2_addr',''),
                'dmac' : line.get('resp_l2_addr','')})

        elif 'dns' in file_type:
            #{"ts":1538080852.403669,"uid":"CtahLT38vq7vKJVBC3","id.orig_h":"192.168.2.12","id.orig_p":56343,"id.resp_h":"192.168.2.1","id.resp_p":53,"proto":"udp","trans_id":2,"rtt":0.008364,"query":"pool.ntp.org","qclass":1,"qclass_name":"C_INTERNET","qtype":1,"qtype_name":"A","rcode":0,"rcode_name":"NOERROR","AA":false,"TC":false,"RD":true,"RA":true,"Z":0,"answers":["185.117.82.70","212.237.100.250","213.251.52.107","183.177.72.201"],"TTLs":[42.0,42.0,42.0,42.0],"rejected":false}
            self.column_values.update({'type' : 'dns',
                                'query' : line.get('query',''),
                                'qclass_name' : line.get('qclass_name',''),
                                'qtype_name' : line.get('qtype_name',''),
                                'rcode_name' : line.get('rcode_name',''),
                                'answers' : line.get('answers',''),
                                'TTLs' : line.get('TTLs','')})

            if type(self.column_values['answers']) == str:
                # If the answer is only 1, Zeek gives a string
                # so convert to a list
                self.column_values.update({'answers' : [self.column_values['answers']] })

        elif 'http' in  file_type:
            # {"ts":158.957403,"uid":"CnNLbE2dyfy5KyqEhh","id.orig_h":"10.0.2.105","id.orig_p":49158,"id.resp_h":"64.182.208.181","id.resp_p":80,"trans_depth":1,"method":"GET","host":"icanhazip.com","uri":"/","version":"1.1","user_agent":"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.38 (KHTML, like Gecko) Chrome/45.0.2456.99 Safari/537.38","request_body_len":0,"response_body_len":13,"status_code":200,"status_msg":"OK","tags":[],"resp_fuids":["FwraVxIOACcjkaGi3"],"resp_mime_types":["text/plain"]}
            self.column_values.update({'type' : 'http',
                 'method' : line.get('method',''),
                 'host' : line.get('host',''),
                 'uri' : line.get('uri',''),
                 'httpversion' : line.get('version',0),
                 'user_agent' : line.get('user_agent',''),
                 'request_body_len' : line.get('request_body_len',0),
                 'response_body_len' : line.get('response_body_len',0),
                 'status_code' : line.get('status_code',''),
                 'status_msg' : line.get('status_msg',''),
                 'resp_mime_types' : line.get('resp_mime_types',''),
                 'resp_fuids' : line.get('resp_fuids','')})

        elif 'ssl' in file_type:
            # {"ts":12087.045499,"uid":"CdoFDp4iW79I5ZmsT7","id.orig_h":"10.0.2.105","id.orig_p":49704,"id.resp_h":"195.211.240.166","id.resp_p":443,"version":"SSLv3","cipher":"TLS_RSA_WITH_RC4_128_SHA","resumed":false,"established":true,"cert_chain_fuids":["FhGp1L3yZXuURiPqq7"],"client_cert_chain_fuids":[],"subject":"OU=DAHUATECH,O=DAHUA,L=HANGZHOU,ST=ZHEJIANG,C=CN,CN=192.168.1.108","issuer":"O=DahuaTech,L=HangZhou,ST=ZheJiang,C=CN,CN=Product Root CA","validation_status":"unable to get local issuer certificate"}
            # {"ts":1382354909.915615,"uid":"C7W6ZA4vI8FxJ9J0bh","id.orig_h":"147.32.83.53","id.orig_p":36567,"id.resp_h":"195.113.214.241","id.resp_p":443,"version":"TLSv12","cipher":"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA","curve":"secp256r1","server_name":"id.google.com.ar","resumed":false,"established":true,"cert_chain_fuids":["FnomJz1vghKIOHtytf","FSvQff1KsaDkRtKXo4","Fif2PF48bytqq6xMDb"],"client_cert_chain_fuids":[],"subject":"CN=*.google.com,O=Google Inc,L=Mountain View,ST=California,C=US","issuer":"CN=Google Internet Authority G2,O=Google Inc,C=US","validation_status":"ok"}
            self.column_values.update({'type' :'ssl',
                 'sslversion' : line.get('version',''),
                 'sport' : line.get('id.orig_p',','),
                 'dport' : line.get('id.resp_p',','),
                 'cipher' : line.get('cipher',''),
                 'resumed' : line.get('resumed',''),
                 'established' : line.get('established',''),
                 'cert_chain_fuids' : line.get('cert_chain_fuids',''),
                 'client_cert_chain_fuids' : line.get('client_cert_chain_fuids',''),
                 'subject' : line.get('subject',''),
                 'issuer' : line.get('issuer',''),
                 'validation_status' : line.get('validation_status',''),
                 'curve' : line.get('curve',''),
                 'server_name' : line.get('server_name',''),
                 'ja3' : line.get('ja3',''),
                 'ja3s' : line.get('ja3s','')})

        elif 'ssh' in file_type:
            self.column_values.update({
                'type': 'ssh',
                'version': line.get('version',''),
                'auth_success': line.get('auth_success',''),
                'auth_attempts': line.get('auth_attempts',''),
                'client': line.get('client',''),
                'server': line.get('server',''),
                'cipher_alg': line.get('cipher_alg',''),
                'mac_alg': line.get('mac_alg',''),
                'compression_alg': line.get('compression_alg',''),
                'kex_alg': line.get('kex_alg',''),
                'host_key_alg': line.get('host_key_alg',''),
                'host_key': line.get('host_key','')})

        elif 'irc' in file_type:
            self.column_values.update({'type': 'irc'})
        elif 'long' in file_type:
            self.column_values.update({'type': 'long'})
        elif 'dhcp' in file_type:
            self.column_values.update({
                'type' :  'dhcp',
                'client_addr' : line.get('client_addr',''),
                'server_addr' : line.get('server_addr',''),
                'host_name' : line.get('host_name',''),
                'mac' : line.get('mac',''), # this is the client mac
                'saddr' : line.get('client_addr',''),
                'daddr' : line.get('server_addr','')})

            # self.column_values['domain'] = line.get('domain','')
            # self.column_values['assigned_addr'] = line.get('assigned_addr','')

             # Some zeek flow don't have saddr or daddr, seen in dhcp.log and notice.log use the mac address instead
            if (self.column_values['saddr'] == '' and self.column_values['daddr'] == ''
                and line.get('mac',False) ):
                self.column_values.update({'saddr' : line.get('mac','')})

        elif 'dce_rpc' in file_type:
            self.column_values.update({'type': 'dce_rpc'})
        elif 'dnp3' in file_type:
            self.column_values.update({'type': 'dnp3'})
        elif 'ftp' in file_type:
            self.column_values.update({
                'type': 'ftp',
                'used_port': line.get("data_channel.resp_p",False)})

        elif 'kerberos' in file_type:
            self.column_values.update({'type':'kerberos'})
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
            self.column_values.update({'type': 'smtp'})
        elif 'socks' in file_type:
            self.column_values.update({'type': 'socks'})
        elif 'syslog' in file_type:
            self.column_values.update({'type': 'syslog'})
        elif 'tunnel' in file_type:
            self.column_values.update({'type': 'tunnel'})
        elif 'notice' in file_type:
            """ Parse the fields we're interested in in the notice.log file """
            # notice fields: ts - uid id.orig_h(saddr) - id.orig_p(sport) - id.resp_h(daddr) - id.resp_p(dport) - note - msg
            self.column_values.update({'type' : 'notice',
                                'sport' : line.get('id.orig_p', ''),
                                'dport' : line.get('id.resp_p', ''),
                                # self.column_values['scanned_ip'] = line.get('dst', '')
                                'note' : line.get('note', ''),
                                'msg' : line.get('msg', ''), # we,'re looking for self signed certs in this field
                                'scanned_port' : line.get('p', ''),
                                'scanning_ip' : line.get('src', '')})

            # portscan notices don't have id.orig_h or id.resp_h fields, instead they have src and dst
            if self.column_values['saddr'] == '' :
                self.column_values.update({'saddr' : line.get('src','' )})
            if self.column_values['daddr'] == '':
                # set daddr to src for now because the notice that contains portscan doesn't have a dst field and slips needs it to work
                self.column_values.update({'daddr' : line.get('dst', self.column_values['saddr']) })

        elif 'files' in file_type:
            """ Parse the fields we're interested in in the files.log file """
            # the slash before files to distinguish between 'files' in the dir name and file.log
            self.column_values.update({'type' :'files',
                                'uid' : line.get('conn_uids',[''])[0],
                                'saddr' : line.get('tx_hosts',[''])[0],
                                'daddr' : line.get('rx_hosts',[''])[0],
                                'size' : line.get('seen_bytes', ''), # downloaded file size
                                'md5' : line.get('md5', ''),
                                # used for detecting ssl certs
                                'source' : line.get('source', ''),
                                'analyzers' : line.get('analyzers', ''),
                                'sha1' : line.get('sha1', '')})

            #todo process zeek tabs files.log
        elif 'arp' in file_type:
            self.column_values.update({'type' : 'arp',
                                'src_mac' : line.get('src_mac', ''),
                                'dst_mac' : line.get('dst_mac', ''),
                                'saddr' : line.get('orig_h',''),
                                'daddr' : line.get('resp_h',''),
                                'dst_hw' : line.get('resp_hw',''),
                                'src_hw' : line.get('orig_hw',''),
                                'operation' : line.get('operation','') })
        elif 'known_services' in file_type:
            self.column_values.update({'type' : 'known_services',
                                'saddr' : line.get('host', ''),
                                # this file doesn't have a daddr field, but we need it in add_flow_to_profile
                                'daddr' : '0.0.0.0',
                                'port_num' : line.get('port_num', ''),
                                'port_proto' : line.get('port_proto', ''),
                                'service' : line.get('service', '')})
        else:
            return False
        return True

    def process_argus_input(self, new_line):
        """
        Process the line and extract columns for argus
        """
        line = new_line['data']
        self.column_values = {
            'starttime' : False,
            'endtime' : False,
            'dur' : False,
            'proto' : False,
            'appproto' : False,
            'saddr' : False,
            'sport' : False,
            'dir' : False,
            'daddr' : False,
            'dport' : False,
            'state' : False,
            'pkts' : False,
            'spkts' : False,
            'dpkts' : False,
            'bytes' : False,
            'sbytes' : False,
            'dbytes' : False,
            'type' : 'argus'}

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
            self.column_values['sbytes'] = int(nline[self.column_idx['sbytes']])
        except KeyError:
            pass
        try:
            self.column_values['dbytes'] = int(nline[self.column_idx['dbytes']])
        except KeyError:
            pass

    def process_nfdump_input(self, new_line):
        """
        Process the line and extract columns for nfdump
        """
        self.column_values = {
            'starttime' : False,
            'endtime' : False,
            'dur' : False,
            'proto' : False,
            'appproto' : False,
            'saddr' : False,
            'sport' : False,
            'dir' : False,
            'daddr' : False,
            'dport' : False,
            'state' : False,
            'pkts' : False,
            'spkts' : False,
            'dpkts' : False,
            'bytes' : False,
            'sbytes' : False,
            'dbytes' : False,
            'type' : 'nfdump'}
        # Read the lines fast
        line = new_line['data']
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

    def process_suricata_input(self, line) -> None:
        """ Read suricata json input """

        # convert to dict if it's not a dict already
        if type(line)== str:
            # lien is the actual data
            line = json.loads(line)
        else:
            # line is a dict with data and type as keys
            try:
                line = json.loads(line['data'])
            except KeyError:
                # can't find the line!
                return True


        self.column_values: dict = {}
        try:
            self.column_values['starttime'] = self.get_time(line['timestamp'])
        # except (KeyError, ValueError):
        except ValueError:
            # Reason for catching ValueError:
            # "ValueError: time data '1900-01-00T00:00:08.511802+0000' does not match format '%Y-%m-%dT%H:%M:%S.%f%z'"
            # It means some flow do not have valid timestamp. It seems to me if suricata does not know the timestamp, it put
            # there this not valid time.
            self.column_values['starttime'] = False
        self.column_values['endtime'] = False
        self.column_values['dur'] = 0
        self.column_values['flow_id'] = line.get('flow_id',False)
        self.column_values['saddr'] = line.get('src_ip',False)
        self.column_values['sport'] = line.get('src_port',False)
        self.column_values['daddr'] = line.get('dest_ip',False)
        self.column_values['dport'] = line.get('dest_port',False)
        self.column_values['proto'] = line.get('proto',False)
        self.column_values['type'] = line.get('event_type',False)
        self.column_values['dir'] = '->'
        self.column_values['appproto'] = line.get('app_proto',False)

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
                        self.column_values['dur'] = (self.column_values['endtime'] - self.column_values['starttime']).total_seconds()
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
                    if type(self.column_values['answers']) == str:
                        # If the answer is only 1, Zeek gives a string
                        # so convert to a list
                        self.column_values['answers'] = [self.column_values['answers']]
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

    def get_domains_of_flow(self):
        """ Returns the domains of each ip (src and dst) that appeard in this flow """
        # These separate lists, hold the domains that we should only check if they are SRC or DST. Not both
        domains_to_check_src = []
        domains_to_check_dst = []
        try:
            #self.print(f"IPData of src IP {self.column_values['saddr']}: {__database__.getIPData(self.column_values['saddr'])}")
            ip_data = __database__.getIPData(self.column_values['saddr'])
            if ip_data:
                sni_info = ip_data.get('SNI',[{}])[0]
                if sni_info: domains_to_check_src.append(sni_info.get('server_name'))
        except (KeyError, TypeError):
            pass
        try:
            #self.print(f"DNS of src IP {self.column_values['saddr']}: {__database__.get_dns_resolution(self.column_values['saddr'])}")
            src_dns_domains = __database__.get_dns_resolution(self.column_values['saddr'])
            for dns_domain in src_dns_domains:
                domains_to_check_src.append(dns_domain)
        except (KeyError, TypeError):
            pass
        try:
            # self.print(f"IPData of dst IP {self.column_values['daddr']}: {__database__.getIPData(self.column_values['daddr'])}")
            ip_data = __database__.getIPData(self.column_values['daddr'])
            if ip_data:
                sni_info = ip_data.get('SNI',[{}])[0]
                if sni_info : domains_to_check_dst.append(sni_info.get('server_name'))
        except (KeyError, TypeError):
            pass
        return domains_to_check_dst, domains_to_check_src

    def is_whitelisted(self) -> bool:
        """
        Checks if the src IP or dst IP or domain or organization of this flow is whitelisted.
        """

        #self.print(f'List of whitelist: Domains: {whitelisted_domains}, IPs: {whitelisted_IPs}, Orgs: {whitelisted_orgs}')

        # check if we have domains whitelisted
        whitelisted_domains = __database__.get_whitelist('domains')
        if whitelisted_domains:
            #self.print('Check the domains')
            # Check if the domain is whitelisted
            # Domain names are stored in different zeek files using different names.
            # Try to get the domain from each file.
            domains_to_check = []
            ssl_domain = self.column_values.get('server_name','') # ssl.log
            domains_to_check.append(ssl_domain)
            http_domain = self.column_values.get('host','') # http.log
            domains_to_check.append(http_domain)
            notice_domain = self.column_values.get('sub','').replace("CN=","") # in notice.log
            domains_to_check.append(notice_domain)

            domains_to_check_dst, domains_to_check_src = self.get_domains_of_flow()

            try:
                #self.print(f"DNS of dst IP {self.column_values['daddr']}: {__database__.get_dns_resolution(self.column_values['daddr'])}")
                dst_dns_domains = __database__.get_dns_resolution(self.column_values['daddr'])
                for dns_domain in dst_dns_domains:
                    domains_to_check_dst.append(dns_domain)
            except (KeyError, TypeError):
                pass

            #self.print(f'Domains to check from flow: {domains_to_check}, {domains_to_check_dst} {domains_to_check_src}')
            # Go through each whitelisted domain and check if what arrived is there
            for domain in list(whitelisted_domains.keys()):
                what_to_ignore = whitelisted_domains[domain]['what_to_ignore']
                # Here we iterate over all the domains to check so we can find
                # subdomains. If slack.com was whitelisted, then test.slack.com
                # should be ignored too. But not 'slack.com.test'
                for domain_to_check in domains_to_check:
                    main_domain = domain_to_check[-len(domain):]
                    if domain in main_domain:
                        # We can ignore flows or alerts, what is it?
                        if 'flows' in what_to_ignore or 'both' in what_to_ignore:
                            #self.print(f'Whitelisting the domain {domain_to_check} due to whitelist of {domain}')
                            return True

                # do we wanna whitelist flows coming from or going to this domain or both?
                from_ = whitelisted_domains[domain]['from']

                # Now check the related domains of the src IP
                if 'src' in from_ or 'both' in from_:
                    for domain_to_check in domains_to_check_src:
                        main_domain = domain_to_check[-len(domain):]
                        if domain in main_domain:
                            # We can ignore flows or alerts, what is it?
                            if 'flows' in what_to_ignore or 'both' in what_to_ignore:
                                #self.print(f"Whitelisting the domain {domain_to_check} because is related to domain {domain} of src IP {self.column_values['saddr']}")
                                return True

                # Now check the related domains of the dst IP
                if 'dst' in from_ or 'both' in from_:
                    for domain_to_check in domains_to_check_dst:
                        main_domain = domain_to_check[-len(domain):]
                        if domain in main_domain:
                            # We can ignore flows or alerts, what is it?
                            if 'flows' in what_to_ignore or 'both' in what_to_ignore:
                                # self.print(f"Whitelisting the domain {domain_to_check} because is related"
                                #            f" to domain {domain} of dst IP {self.column_values['daddr']}")
                                return True

        saddr = self.column_values['saddr']
        daddr = self.column_values['daddr']

        # check if we have IPs whitelisted
        whitelisted_IPs = __database__.get_whitelist('IPs')

        if whitelisted_IPs:
            #self.print('Check the IPs')
            # Check if the IPs are whitelisted
            ips_to_whitelist = list(whitelisted_IPs.keys())

            if saddr in ips_to_whitelist:
                # The flow has the src IP to whitelist
                from_ = whitelisted_IPs[saddr]['from']
                what_to_ignore = whitelisted_IPs[saddr]['what_to_ignore']
                if ('src' in from_ or 'both' in from_) and ('flows' in what_to_ignore or 'both' in what_to_ignore):
                    # self.print(f"Whitelisting the src IP {self.column_values['saddr']}")
                    return True

            if daddr in ips_to_whitelist: # should be if and not elif
                # The flow has the dst IP to whitelist
                from_ = whitelisted_IPs[daddr]['from']
                what_to_ignore = whitelisted_IPs[daddr]['what_to_ignore']
                if ('dst' in from_  or 'both' in from_) and ('flows' in what_to_ignore or 'both' in what_to_ignore):
                    # self.print(f"Whitelisting the dst IP {self.column_values['daddr']}")
                    return True

        # check if we have orgs whitelisted
        whitelisted_orgs = __database__.get_whitelist('organizations')

        # Check if the orgs are whitelisted
        if whitelisted_orgs:
            #self.print('Check if the organization is whitelisted')
            # Check if IP belongs to a whitelisted organization range
            # Check if the ASN of this IP is any of these organizations

            for org in whitelisted_orgs:
                from_ =  whitelisted_orgs[org]['from'] # src or dst or both
                what_to_ignore = whitelisted_orgs[org]['what_to_ignore'] # flows, alerts or both
                #self.print(f'Checking {org}, from:{from_} type {what_to_ignore}')

                # get the domains of this flow
                domains_to_check_dst, domains_to_check_src = self.get_domains_of_flow()

                if 'flows' in what_to_ignore or 'both' in what_to_ignore:
                    # We want to block flows from this org. get the domains of this flow based on the direction.
                    if 'both' in from_ : domains_to_check = domains_to_check_src + domains_to_check_dst
                    elif 'src' in from_: domains_to_check = domains_to_check_src
                    elif 'dst' in from_: domains_to_check = domains_to_check_dst
                    # get the ips of this org?? #todo
                    org_subnets = json.loads(whitelisted_orgs[org].get('IPs','{}'))


                    if 'src' in from_ or 'both' in from_:
                        # Method 1 Check if src IP belongs to a whitelisted organization range
                        for network in org_subnets:
                            try:
                                ip = ipaddress.ip_address(saddr)
                                if ip in ipaddress.ip_network(network):
                                    # self.print(f"The src IP {saddr} is in the range {network} or org {org}. Whitelisted.")
                                    return True
                            except ValueError:
                                # Some flows don't have IPs, but mac address or just - in some cases
                                return False


                        # Method 2 Check if the ASN of this src IP is any of these organizations
                        ip_data = __database__.getIPData(saddr)
                        try:
                            ip_asn = ip_data['asn']['asnorg']
                            if ip_asn and ip_asn != 'Unknown' and (org.lower() in ip_asn.lower() or ip_asn in whitelisted_orgs[org]['asn']):
                                # this ip belongs to a whitelisted org, ignore flow
                                # self.print(f"The ASN {ip_asn} of IP {saddr} is in the values of org {org}. Whitelisted.")
                                return True
                        except (KeyError, TypeError):
                            # No asn data for src ip
                            pass

                        # Method 3 Check if the domains of this flow belong to this org
                        org_domains = json.loads(whitelisted_orgs[org].get('domains','{}'))
                        # domains to check are usually 1 or 2 domains
                        for flow_domain in domains_to_check:
                            if org in flow_domain:
                                # self.print(f"The domain of this flow ({flow_domain}) belongs to the domains of {org}")
                                return True

                            flow_TLD = flow_domain.split(".")[-1]
                            for org_domain in org_domains:
                                org_domain_TLD = org_domain.split(".")[-1]
                                # make sure the 2 domains have the same same top level domain
                                if flow_TLD != org_domain_TLD: continue

                                # match subdomains too
                                # if org has org.com, and the flow_domain is xyz.org.com whitelist it
                                if org_domain in flow_domain:
                                    # print(f"The src domain of this flow ({flow_domain}) is "
                                    #            f"a subdomain of {org} domain: {org_domain}")
                                    return True
                                # if org has xyz.org.com, and the flow_domain is org.com whitelist it
                                if flow_domain in org_domain :
                                    # print(f"The domain of {org} ({org_domain}) is a subdomain of "
                                    #       f"this flow domain ({flow_domain})")
                                    return True

                    if 'dst' in from_ or 'both' in from_:
                        # Method 1 Check if dst IP belongs to a whitelisted organization range
                        for network in org_subnets:
                            try:
                                ip = ipaddress.ip_address(self.column_values['daddr'])
                                if ip in ipaddress.ip_network(network):
                                    # self.print(f"The dst IP {self.column_values['daddr']} "
                                    #            f"is in the range {network} or org {org}. Whitelisted.")
                                    return True
                            except ValueError:
                                # Some flows don't have IPs, but mac address or just - in some cases
                                return False
                        # Method 2 Check if the ASN of this dst IP is any of these organizations
                        ip_data = __database__.getIPData(self.column_values['daddr'])
                        try:
                            ip_asn = ip_data['asn']['asnorg']
                            if ip_asn and ip_asn != 'Unknown' and (org.lower() in ip_asn.lower() or ip_asn in whitelisted_orgs[org]['asn']):
                                # this ip belongs to a whitelisted org, ignore flow
                                # self.print(f"The ASN {ip_asn} of IP {self.column_values['daddr']} "
                                #            f"is in the values of org {org}. Whitelisted.")
                                return True
                        except (KeyError, TypeError):
                            # No asn data for src ip
                            pass

                        # Method 3 Check if the domains of this flow belong to this org
                        for domain in org_domains:
                            # domains to check are usually 1 or 2 domains
                            for flow_domain in domains_to_check:
                                # match subdomains too
                                if domain in flow_domain:
                                    # self.print(f"The dst domain of this flow ({flow_domain}) is "
                                    #            f"a subdomain of {org} domain: {domain}")
                                    return True

                    # check if we have mac addresses whitelisted
                    whitelisted_mac = __database__.get_whitelist('mac')

                    if whitelisted_mac:

                        # try to get the mac address of the current flow
                        src_mac =  self.column_values.get('src_mac',False)
                        if not src_mac: src_mac = self.column_values.get('mac',False)
                        if not src_mac:
                            src_mac = __database__.get_mac_addr_from_profile(f'profile_{saddr}')[0]

                        if src_mac and src_mac in list(whitelisted_mac.keys()):
                            # the src mac of this flow is whitelisted, but which direction?
                            from_ = whitelisted_mac[src_mac]['from']
                            if 'src' in from_ or 'both' in from_:
                                # self.print(f"The source MAC of this flow {src_mac} is whitelisted")
                                return True

                        dst_mac = self.column_values.get('dst_mac',False)
                        if dst_mac and dst_mac in list(whitelisted_mac.keys()):
                            # the dst mac of this flow is whitelisted, but which direction?
                            from_ = whitelisted_mac[dst_mac]['from']
                            if 'dst' in from_ or 'both' in from_:
                                # self.print(f"The dst MAC of this flow {dst_mac} is whitelisted")
                                return True

        return False

    def add_flow_to_profile(self):
        """
        This is the main function that takes the columns of a flow and does all the magic to convert it into a working data in our system.
        It includes checking if the profile exists and how to put the flow correctly.
        It interprets each column
        A flow has two IP addresses, so treat both of them correctly.
        """
        try:

            # Define which type of flows we are going to process

            if not self.column_values:
                    return True
            elif self.column_values['type'] not in ('ssh','ssl','http','dns','conn','flow','argus','nfdump','notice',
                                                    'dhcp','files', 'known_services', 'arp','ftp'):
                # Not a supported type
                return True
            elif self.column_values['starttime'] is None:
                # There is suricata issue with invalid timestamp for examaple: "1900-01-00T00:00:08.511802+0000"
                return True


            try:
                # seconds.
                # make sure starttime is a datetime obj (not a str) so we can get the timestamp
                if type(self.column_values['starttime']) == str:
                    datetime_obj = datetime.strptime( self.column_values['starttime'] , self.timeformat)
                    starttime = datetime_obj.timestamp()
                else:
                    starttime = self.column_values['starttime'].timestamp()
            except ValueError:
                # date
                try:
                    # This file format is very extended, but we should consider more options. Maybe we should detect the time format.
                    # Some times if there is no microseconds, the datatime object just give us '2018-12-18 14:00:00' instead of '2018-12-18 14:00:00.000000' so the format fails
                    try:
                        date_time = datetime.strptime(str(self.column_values['starttime']), '%Y-%m-%d %H:%M:%S.%f')
                    except ValueError:
                        date_time = datetime.strptime(str(self.column_values['starttime']) + '.000000', '%Y-%m-%d %H:%M:%S.%f')
                    starttime = date_time.timestamp()
                except ValueError as e:
                    self.print("We can not recognize time format.", 0, 1)
                    self.print("{}".format((type(e))), 0, 1)

            # This uid check is for when we read things that are not zeek
            if 'uid' not in self.column_values or not self.column_values.get('uid',''):
                # In the case of other tools that are not Zeek, there is no UID. So we generate a new one here
                # Zeeks uses human-readable strings in Base62 format, from 112 bits usually. We do base64 with some bits just because we need a fast unique way
                self.column_values['uid'] = base64.b64encode(binascii.b2a_hex(os.urandom(9))).decode('utf-8')
            uid = self.column_values['uid']
            flow_type = self.column_values['type']
            self.saddr = self.column_values['saddr']
            self.daddr = self.column_values['daddr']
            profileid = 'profile' + self.id_separator + str(self.saddr)

            if self.saddr == '' and self.daddr == '':
                # some zeek flow don't have saddr or daddr, seen in dhcp.log and notice.log! don't store them in the db
                return False

            # Check if the flow is whitelisted and we should not process
            if self.is_whitelisted():
                return True

            def get_rev_profile(starttime, daddr_as_obj):
                # Compute the rev_profileid
                rev_profileid = __database__.getProfileIdFromIP(daddr_as_obj)
                if not rev_profileid:
                    self.print("The dstip profile was not here... create", 3, 0)
                    # Create a reverse profileid for managing the data going to the dstip.
                    rev_profileid = 'profile' + self.id_separator + str(daddr_as_obj)
                    __database__.addProfile(rev_profileid, starttime, self.width)
                    # Try again
                    rev_profileid = __database__.getProfileIdFromIP(daddr_as_obj)
                    # For the profile to the dstip, find the id in the database of the tw where the flow belongs.
                rev_twid = self.get_timewindow(starttime, rev_profileid)
                return rev_profileid, rev_twid

            if 'flow' in flow_type or 'conn' in flow_type or 'argus' in flow_type or 'nfdump' in flow_type:
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
                if type(answers) == str:
                    # If the answer is only 1, Zeek gives a string
                    # so convert to a list
                    answers = [answers]
                ttls = self.column_values['TTLs']
            elif 'dhcp' in flow_type:
                # client mac addr and client_addr is optional in zeek, so sometimes it may not be there
                client_addr = self.column_values.get('client_addr', False)
                mac_addr = self.column_values.get('mac', False)
                host_name = self.column_values.get('host_name', False)
                server_addr = self.column_values.get('server_addr', False)

                if client_addr:
                    profileid = get_rev_profile(starttime, client_addr)[0]
                if mac_addr:
                    # send this to IP_Info module to get vendor info about this MAC
                    to_send = {'MAC': mac_addr,
                               'profileid': profileid}
                    if host_name: to_send.update({'host_name': host_name})
                    __database__.publish('new_MAC', json.dumps(to_send))

                if server_addr:
                    __database__.store_dhcp_server(server_addr)
                    __database__.mark_profile_as_dhcp(profileid)

            # Create the objects of IPs
            try:
                saddr_as_obj = ipaddress.IPv4Address(self.saddr)
                daddr_as_obj = ipaddress.IPv4Address(self.daddr)
                # Is ipv4
            except ipaddress.AddressValueError:
                # Is it ipv6?
                try:
                    saddr_as_obj = ipaddress.IPv6Address(self.saddr)
                    daddr_as_obj = ipaddress.IPv6Address(self.daddr)
                except ipaddress.AddressValueError:
                    # Its a mac
                    return False

            ##############
            # 4th Define help functions for storing data
            def store_features_going_out(profileid, twid, starttime):
                """
                This is an internal function in the add_flow_to_profile function for adding the features going out of the profile
                """
                role = 'Client'
                # self.print(f'Storing features going out for profile {profileid} and tw {twid}')
                if 'flow' in flow_type or 'conn' in flow_type or 'argus' in flow_type or 'nfdump' in flow_type:
                    # Tuple
                    tupleid = f'{daddr_as_obj}-{dport}-{proto}'
                    # Compute the symbol for this flow, for this TW, for this profile. The symbol is based on the 'letters' of the original Startosphere ips tool
                    symbol = self.compute_symbol(profileid, twid, tupleid, starttime, dur, allbytes, tuple_key='OutTuples')
                    # Change symbol for its internal data. Symbol is a tuple and is confusing if we ever change the API
                    # Add the out tuple
                    __database__.add_tuple(profileid, twid, tupleid, symbol, role, starttime, uid)
                    # Add the dstip
                    __database__.add_ips(profileid, twid, daddr_as_obj, self.column_values, role)
                    # Add the dstport
                    port_type = 'Dst'
                    __database__.add_port(profileid, twid, daddr_as_obj, self.column_values, role, port_type)
                    # Add the srcport
                    port_type = 'Src'
                    __database__.add_port(profileid, twid, daddr_as_obj, self.column_values, role, port_type)
                    # Add the flow with all the fields interpreted
                    __database__.add_flow(profileid=profileid, twid=twid, stime=starttime, dur=dur,
                                          saddr=str(saddr_as_obj), sport=sport, daddr=str(daddr_as_obj),
                                          dport=dport, proto=proto, state=state, pkts=pkts, allbytes=allbytes,
                                          spkts=spkts, sbytes=sbytes, appproto=appproto, uid=uid,
                                          label=self.label, flow_type=flow_type)
                elif 'dns' in flow_type:
                    __database__.add_out_dns(profileid, twid, starttime, flow_type, uid, query, qclass_name,
                                             qtype_name, rcode_name, answers, ttls)
                elif flow_type == 'http':

                    __database__.add_out_http(profileid, twid, starttime, flow_type, uid, self.column_values['method'],
                                              self.column_values['host'], self.column_values['uri'],
                                              self.column_values['httpversion'], self.column_values['user_agent'],
                                              self.column_values['request_body_len'], self.column_values['response_body_len'],
                                              self.column_values['status_code'], self.column_values['status_msg'],
                                              self.column_values['resp_mime_types'], self.column_values['resp_fuids'])
                elif flow_type == 'ssl':
                    __database__.add_out_ssl(profileid, twid, starttime, daddr_as_obj,self.column_values['dport'],
                                             flow_type, uid, self.column_values['sslversion'],
                                             self.column_values['cipher'], self.column_values['resumed'],
                                             self.column_values['established'], self.column_values['cert_chain_fuids'],
                                             self.column_values['client_cert_chain_fuids'], self.column_values['subject'],
                                             self.column_values['issuer'], self.column_values['validation_status'],
                                             self.column_values['curve'], self.column_values['server_name'],
                                             self.column_values['ja3'], self.column_values['ja3s'])
                elif flow_type == 'ssh':
                    __database__.add_out_ssh(profileid, twid, starttime, flow_type, uid, self.column_values['version'],
                                             self.column_values['auth_attempts'], self.column_values['auth_success'],
                                             self.column_values['client'], self.column_values['server'],
                                             self.column_values['cipher_alg'], self.column_values['mac_alg'],
                                             self.column_values['compression_alg'], self.column_values['kex_alg'],
                                             self.column_values['host_key_alg'], self.column_values['host_key'])
                elif flow_type == 'notice':
                     __database__.add_out_notice(profileid,twid,
                                                 starttime,
                                                 self.column_values['daddr'],
                                                 self.column_values['sport'],
                                                 self.column_values['dport'],
                                                 self.column_values['note'],
                                                 self.column_values['msg'],
                                                 self.column_values['scanned_port'],
                                                 self.column_values['scanning_ip'],
                                                 self.column_values['uid']
                                                 )
                elif flow_type == 'ftp':
                    used_port = self.column_values['used_port']
                    if used_port:
                        __database__.set_ftp_port(used_port)

                elif flow_type == 'files':
                    """" Send files.log data to new_downloaded_file channel in vt module to see if it's malicious """
                    to_send = {
                        'uid' : self.column_values['uid'],
                        'daddr': self.column_values['daddr'],
                        'saddr': self.column_values['saddr'],
                        'size' : self.column_values['size'],
                        'md5':  self.column_values['md5'],
                        'sha1':  self.column_values['sha1'],
                        'analyzers':  self.column_values['analyzers'],
                        'source':  self.column_values['source'],
                        'profileid' : profileid,
                        'twid' : twid,
                        'ts' : starttime
                    }
                    to_send = json.dumps(to_send)
                    __database__.publish('new_downloaded_file', to_send)

                elif flow_type == 'known_services':
                    # Send known_services.log data to new_service channel in flowalerts module
                    to_send = {
                        'uid' : self.column_values['uid'],
                        'saddr': self.column_values['saddr'],
                        'port_num' : self.column_values['port_num'],
                        'port_proto':  self.column_values['port_proto'],
                        'service':  self.column_values['service'],
                        'profileid' : profileid,
                        'twid' : twid,
                        'ts' : starttime
                    }
                    to_send = json.dumps(to_send)
                    __database__.publish("new_service",to_send)

                elif flow_type == 'arp':
                    to_send = {
                        'uid' : self.column_values['uid'],
                        'daddr': self.column_values['daddr'],
                        'saddr': self.column_values['saddr'],
                        'dst_mac': self.column_values['dst_mac'],
                        'src_mac': self.column_values['src_mac'],
                        'dst_hw': self.column_values['dst_hw'],
                        'src_hw': self.column_values['src_hw'],
                        'operation': self.column_values['operation'],
                        'ts' : starttime,
                        'profileid' : profileid,
                        'twid' : twid,
                    }
                    # send to arp module
                    to_send = json.dumps(to_send)
                    __database__.publish('new_arp', to_send)

                    # send the src and dst MAC to IP_Info module to get vendor info about this MAC
                    to_send = {'MAC': self.column_values['dst_mac'],
                               'profileid': f'profile_{self.daddr}'}
                    __database__.publish('new_MAC', json.dumps(to_send))

                    to_send = {'MAC': self.column_values['src_mac'],
                               'profileid': f'profile_{self.saddr}'}
                    __database__.publish('new_MAC', json.dumps(to_send))

                    # Add the flow with all the fields interpreted
                    __database__.add_flow(profileid=profileid, twid=twid, stime=starttime, dur='0',
                                          saddr=str(saddr_as_obj), daddr=str(daddr_as_obj),
                                          proto='ARP', uid=uid)

            def store_features_going_in(profileid, twid, starttime):
                """
                This is an internal function in the add_flow_to_profile function for adding the features going in of the profile
                """
                role = 'Server'
                # self.print(f'Storing features going in for profile {profileid} and tw {twid}')
                if 'flow' in flow_type or 'conn' in flow_type or 'argus' in flow_type or 'nfdump' in flow_type:
                    # Tuple. We use the src ip, but the dst port still!
                    tupleid = str(saddr_as_obj) + '-' + str(dport) + '-' + proto
                    # Compute symbols.
                    symbol = self.compute_symbol(profileid, twid, tupleid, starttime, dur, allbytes, tuple_key='InTuples')
                    # Add the src tuple
                    __database__.add_tuple(profileid, twid, tupleid, symbol, role, starttime, uid)
                    # Add the srcip
                    __database__.add_ips(profileid, twid, saddr_as_obj, self.column_values, role)
                    # Add the dstport
                    port_type = 'Dst'
                    __database__.add_port(profileid, twid, daddr_as_obj, self.column_values, role, port_type)
                    # Add the srcport
                    port_type = 'Src'
                    __database__.add_port(profileid, twid, daddr_as_obj, self.column_values, role, port_type)
                    # Add the flow with all the fields interpreted
                    __database__.add_flow(profileid=profileid, twid=twid, stime=starttime, dur=dur,
                                          saddr=str(saddr_as_obj), sport=sport, daddr=str(daddr_as_obj), dport=dport,
                                          proto=proto, state=state, pkts=pkts, allbytes=allbytes, spkts=spkts, sbytes=sbytes,
                                          appproto=appproto, uid=uid, label=self.label)
                    # No dns check going in. Probably ok.

            ##########################################
            # 5th. Store the data according to the paremeters
            # Now that we have the profileid and twid, add the data from the flow in this tw for this profile
            self.print("Storing data in the profile: {}".format(profileid), 3, 0)

            # For this 'forward' profile, find the id in the database of the tw where the flow belongs.
            twid = self.get_timewindow(starttime, profileid)

            if self.home_net:
                # Home. Create profiles for home IPs only
                if self.analysis_direction == 'out':
                    # Home and only out. Check if the src IP is in the home. If yes, store only out
                    if saddr_as_obj in self.home_net:
                        __database__.addProfile(profileid, starttime, self.width)
                        store_features_going_out(profileid, twid, starttime)
                elif self.analysis_direction == 'all':
                    # Home and all. Check if src IP or dst IP are in home. Store all
                    if saddr_as_obj in self.home_net:
                        __database__.addProfile(profileid, starttime, self.width)
                        store_features_going_out(profileid, twid, starttime)
                    if daddr_as_obj in self.home_net:
                        rev_profileid, rev_twid = get_rev_profile(starttime, daddr_as_obj)
                        store_features_going_in(rev_profileid, rev_twid, starttime)
            elif not self.home_net:
                # No home. Create profiles for everybody
                if self.analysis_direction == 'out':
                    # No home. Only store out
                    __database__.addProfile(profileid, starttime, self.width)
                    store_features_going_out(profileid, twid, starttime)
                elif self.analysis_direction == 'all':
                    # No home. Store all
                    __database__.addProfile(profileid, starttime, self.width)
                    rev_profileid, rev_twid = get_rev_profile(starttime, daddr_as_obj)
                    store_features_going_out(profileid, twid, starttime)
                    store_features_going_in(rev_profileid, rev_twid, starttime)

            """
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
                    self.print("Flow with dstip in homenet: srcip {}, dstip {}".format(saddr_as_obj, daddr_as_obj), 0, 7)
                    # The dst ip is in the home net. So register this as going to it
                    # 1. Get the profile of the dst ip.
                    rev_profileid = __database__.getProfileIdFromIP(daddr_as_obj)
                    if not rev_profileid:
                        # We do not have yet the profile of the dst ip that is in our home net
                        self.print("The dstip profile was not here... create", 0, 7)
                        # Create a reverse profileid for managing the data going to the dstip.
                        # With the rev_profileid we can now work with data in relation to the dst ip
                        rev_profileid = 'profile' + self.id_separator + str(daddr_as_obj)
                        __database__.addProfile(rev_profileid, starttime, self.width)
                        # Try again
                        rev_profileid = __database__.getProfileIdFromIP(daddr_as_obj)
                        # For the profile to the dstip, find the id in the database of the tw where the flow belongs.
                        rev_twid = self.get_timewindow(starttime, rev_profileid)
                        if not rev_profileid:
                            # Too many errors. We should not be here
                            return False
                    self.print("Profile for dstip {} : {}".format(daddr_as_obj, profileid), 0, 7)
                    # 2. For this profile, find the id in the databse of the tw where the flow belongs.
                    rev_twid = self.get_timewindow(starttime, profileid)
                elif daddr_as_obj not in self.home_net:
                    # The dst ip is also not part of our home net. So ignore completely
                    return False
            elif not self.home_net:
                # We don't have a home net, so create profiles for everyone. 
    
                # Add the profile for the srcip to the DB. If it already exists, nothing happens. So now profileid is the id of the profile to work with.
                __database__.addProfile(profileid, starttime, self.width)
                # Add the profile for the dstip to the DB. If it already exists, nothing happens. So now rev_profileid is the id of the profile to work with. 
                rev_profileid = 'profile' + self.id_separator + str(daddr_as_obj)
                __database__.addProfile(rev_profileid, starttime, self.width)
    
                # For the profile from the srcip , find the id in the database of the tw where the flow belongs.
                twid = self.get_timewindow(starttime, profileid)
                # For the profile to the dstip, find the id in the database of the tw where the flow belongs.
                rev_twid = self.get_timewindow(starttime, rev_profileid)
    
            # In which analysis mode are we?
            # Mode 'out'
            if self.analysis_direction == 'out':
                # Only take care of the stuff going out. Here we don't keep track of the stuff going in
                # If we have a home net and the flow comes from it, or if we don't have a home net and we are in out out.
                if (self.home_net and saddr_as_obj in self.home_net) or not self.home_net:
                    store_features_going_out(profileid, twid, starttime)
    
            # Mode 'all'
            elif self.analysis_direction == 'all':
                # Take care of both the stuff going out and in. In case the profile is for the srcip and for the dstip
                if not self.home_net:
                    # If we don't have a home net, just try to store everything coming OUT and IN to the IP
                    # Out features
                    store_features_going_out(profileid, twid, starttime)
                    # IN features
                    store_features_going_in(rev_profileid, rev_twid, starttime)
                else:
                    # The flow is going TO homenet or FROM homenet or BOTH together.
                    # If we have a home net and the flow comes from it. Only the features going out of the IP
                    if saddr_as_obj in self.home_net:
                        store_features_going_out(profileid, twid, starttime)
                    # If we have a home net and the flow comes to it. Only the features going in of the IP
                    elif daddr_as_obj in self.home_net:
                        # The dstip was in the homenet. Add the src info to the dst profile
                        self.print('Features going in')
                        store_features_going_in(rev_profileid, rev_twid, starttime)
                    # If the flow is going from homenet to homenet.
                    elif daddr_as_obj in self.home_net and saddr_as_obj in self.home_net:
                        store_features_going_out(profileid, twid, starttime)
                        self.print('Features going in')
                        store_features_going_in(rev_profileid, rev_twid, starttime)
            """
            return profileid,twid
        except Exception as inst:
            # For some reason we can not use the output queue here.. check
            self.print("Error in add_flow_to_profile profilerProcess. {}".format(traceback.format_exc()), 0, 1)
            self.print("{}".format((type(inst))), 0, 1)
            self.print("{}".format(inst), 0, 1)
            return False

    def compute_symbol(self, profileid, twid, tupleid, current_time, current_duration, current_size, tuple_key: str):
        """
        This function computes the new symbol for the tuple according to the
        original stratosphere ips model of letters
        Here we do not apply any detection model, we just create the letters
        as one more feature current_time is the starttime of the flow
        """
        try:
            current_duration = float(current_duration)
            current_size = int(current_size)
            now_ts = float(current_time)
            self.print("Starting compute symbol. Profileid: {}, Tupleid {}, time:{} ({}), dur:{}, size:{}".format(profileid, tupleid, current_time, type(current_time), current_duration, current_size), 3, 0)
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
            (last_last_ts, last_ts) = __database__.getT2ForProfileTW(profileid, twid, tupleid, tuple_key)
            # self.print(f'Profileid: {profileid}. Data extracted from DB. last_ts: {last_ts}, last_last_ts: {last_last_ts}', 0, 5)

            def compute_periodicity(now_ts: float, last_ts: float, last_last_ts: float):
                """ Function to compute the periodicity """
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
                self.print("Compute Periodicity: Profileid: {}, Tuple: {}, T1={}, T2={}, TD={}".format(profileid, tupleid, T1, T2, TD), 3,0)
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
                # format of this map is as follows
                # {periodicity: {'size' : {duration: letter, duration: letter, etc.}}
                periodicity_map = {
                    # every key in this dict represents a periodicity
                    '-1': {
                        # every key in this dict is a size 1,2,3
                        # 'size' : {duration: letter, diration: letter, etc.}
                        '1': {'1': '1', '2': '2', '3': '3'},
                        '2': {'1': '4', '2': '5', '3': '6'},
                        '3' : {'1': '7', '2': '8', '3': '9'},
                    },
                    '1': {
                        '1': {'1': 'a', '2': 'b', '3': 'c'},
                        '2': {'1': 'd', '2': 'e', '3': 'f'},
                        '3' : {'1': 'g', '2': 'h', '3':'i'},
                    },
                    '2': {
                        '1': {'1': 'A', '2': 'B', '3': 'C'},
                        '2': {'1': 'D', '2': 'E', '3': 'F'},
                        '3' : {'1': 'G', '2': 'H', '3':'I'},
                    },
                    '3': {
                        '1': {'1': 'r', '2': 's', '3': 't'},
                        '2': {'1': 'u', '2': 'v', '3': 'w'},
                        '3' : {'1': 'x', '2': 'y', '3':'z'},
                    },
                    '4': {
                        '1': {'1': 'R', '2': 'S', '3': 'T'},
                        '2': {'1': 'U', '2': 'V', '3': 'W'},
                        '3' : {'1': 'X', '2': 'Y', '3':'Z'},
                    }
                }
                return periodicity_map[str(periodicity)][str(size)][str(duration)]

            def compute_timechar():
                """ Function to compute the timechar """
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
                    self.print("Warning: Coming flows are not sorted -> Some time diff are less than zero.", 0, 2)
                    pass
            except TypeError:
                T2 = False
            # self.print("T2:{}".format(T2), 0, 1)
            # p = __database__.start_profiling()
            # Compute the rest
            periodicity, zeros = compute_periodicity(now_ts, last_ts, last_last_ts)
            duration = compute_duration()
            # self.print("Duration: {}".format(duration), 0, 1)
            size = compute_size()
            # self.print("Size: {}".format(size), 0, 1)
            letter = compute_letter()
            # self.print("Letter: {}".format(letter), 0, 1)
            timechar = compute_timechar()
            # self.print("TimeChar: {}".format(timechar), 0, 1)
            self.print("Profileid: {}, Tuple: {}, Periodicity: {}, Duration: {}, Size: {}, Letter: {}. TimeChar: {}".format(profileid, tupleid, periodicity, duration, size, letter, timechar),  3, 0)
            # p = __database__.end_profiling(p)
            symbol = zeros + letter + timechar
            # Return the symbol, the current time of the flow and the T1 value
            return symbol, (last_ts, now_ts)
        except Exception as inst:
            # For some reason we can not use the output queue here.. check
            self.print("Error in compute_symbol in profilerProcess.", 0, 1)
            self.print("{}".format(type(inst)), 0, 1)
            self.print("{}".format(inst), 0, 1)
            self.print("{}".format(traceback.format_exc()), 0, 1)

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
            # First check if we are not in the last TW. Since this will be the majority of cases
            try:
                [(lasttwid, lasttw_start_time)] = __database__.getLastTWforProfile(profileid)
                lasttw_start_time = float(lasttw_start_time)
                lasttw_end_time = lasttw_start_time + self.width
                flowtime = float(flowtime)
                self.print('The last TW id for profile {} was {}. Start:{}. End: {}'.format(profileid, lasttwid, lasttw_start_time, lasttw_end_time), 3, 0)
                # There was a last TW, so check if the current flow belongs here.
                if lasttw_end_time > flowtime and lasttw_start_time <= flowtime:
                    self.print("The flow ({}) is on the last time window ({})".format(flowtime, lasttw_end_time), 3, 0)
                    twid = lasttwid
                elif lasttw_end_time <= flowtime:
                    # The flow was not in the last TW, its NEWER than it
                    self.print("The flow ({}) is NOT on the last time window ({}). Its newer".format(flowtime, lasttw_end_time), 3, 0)
                    amount_of_new_tw = int((flowtime - lasttw_end_time) / self.width)
                    self.print("We have to create {} empty TWs in the midle.".format(amount_of_new_tw), 3, 0)
                    temp_end = lasttw_end_time
                    for id in range(0, amount_of_new_tw + 1):
                        new_start = temp_end
                        twid = __database__.addNewTW(profileid, new_start)
                        self.print("Creating the TW id {}. Start: {}.".format(twid, new_start), 3, 0)
                        temp_end = new_start + self.width
                    # Now get the id of the last TW so we can return it
                elif lasttw_start_time > flowtime:
                    # The flow was not in the last TW, its OLDER that it
                    self.print("The flow ({}) is NOT on the last time window ({}). Its older".format(flowtime, lasttw_end_time), 3, 0)
                    # Find out if we already have this TW in the past
                    data = __database__.getTWofTime(profileid, flowtime)
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
                        self.print("We need to create {} TW before the first".format(diff + 1), 3, 0)
                        # Get the first TW
                        [(firsttwid, firsttw_start_time)] = __database__.getFirstTWforProfile(profileid)
                        firsttw_start_time = float(firsttw_start_time)
                        # The start of the new older TW should be the first - the width
                        temp_start = firsttw_start_time - self.width
                        for id in range(0, diff + 1):
                            new_start = temp_start
                            # The method to add an older TW is the same as to add a new one, just the starttime changes
                            twid = __database__.addNewOlderTW(profileid, new_start)
                            self.print("Creating the new older TW id {}. Start: {}.".format(twid, new_start), 3, 0)
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
                #self.print("First TW ({}) created for profile {}.".format(twid, profileid), 0, 1)
            return twid
        except Exception as e:
            self.print("Error in get_timewindow().", 0, 1)
            self.print("{}".format(e), 0, 1)

    def run(self):
        rec_lines = 0
        # Main loop function
        while True:
            try:
                line = self.inputqueue.get()
                if 'stop' in line:
                    # if timewindows are not updated for a long time (see at logsProcess.py), we will stop slips automatically.The 'stop_process' line is sent from logsProcess.py.
                    # can't use self.name because multiprocessing library adds the child number to the name so it's not const
                    __database__.publish('finished_modules', 'ProfilerProcess')
                    self.print("Stopping Profiler Process. Received {} lines ({})".format(rec_lines, datetime.now().strftime('%Y-%m-%d--%H:%M:%S')), 2,0)
                    return True
                else:
                    # Received new input data
                    # Extract the columns smartly
                    self.print("< Received Line: {}".format(line),2,0)
                    rec_lines += 1
                    if not self.input_type:
                        # Find the type of input received
                        # This line will be discarded because
                        self.define_type(line)
                        # We should do this before checking the type of input so we don't lose the first line of input
                    # What type of input do we have?
                    if not self.input_type:
                        # can't definee the type of input
                        self.print("Can't determine input type.",5,6)
                    elif self.input_type == 'zeek':
                        # self.print('Zeek line')
                        self.process_zeek_input(line)
                        # Add the flow to the profile
                        self.add_flow_to_profile()
                    elif self.input_type == 'argus' or self.input_type == 'argus-tabs':
                        # self.print('Argus line')
                        # Argus puts the definition of the columns on the first line only
                        # So read the first line and define the columns
                        try:
                            # Are the columns defined? Just try to access them
                            _ = self.column_idx['starttime']
                            # Yes
                            # Quickly process all lines
                            self.process_argus_input(line)
                            # Add the flow to the profile
                            self.add_flow_to_profile()
                        except AttributeError:
                            # No. Define columns. Do not add this line to profile, its only headers
                            self.define_columns(line)
                        except KeyError:
                            # When the columns are not there. Not sure if it works
                            self.define_columns(line)
                    elif self.input_type == 'suricata':
                        # self.print('Suricata line')
                        self.process_suricata_input(line)
                        # Add the flow to the profile
                        self.add_flow_to_profile()
                    elif self.input_type == 'zeek-tabs':
                        # self.print('Zeek-tabs line')
                        self.process_zeek_tabs_input(line)
                        # Add the flow to the profile
                        self.add_flow_to_profile()
                    elif self.input_type == 'nfdump':
                        self.process_nfdump_input(line)
                        self.add_flow_to_profile()
                    else:
                        self.print("Can't recognize input file type.")

                # listen on this channel in case whitelist.conf is changed, we need to process the new changes
                message = self.c1.get_message(timeout=self.timeout)
                if message and message['data'] == 'stop_process':
                    __database__.publish('finished_modules', 'ProfilerProcess')
                    return True
                if message and message['channel'] == 'reload_whitelist' and type(message['data']) == str:
                    # if whitelist.conf is edited using pycharm
                    # a msg will be sent to this channel on every keypress, becausse pycharm saves file automatically
                    # otherwise this channel will get a msg only when whitelist.conf is modified and saved to disk
                    self.read_whitelist()

            except KeyboardInterrupt:
                # self.print("Received {} lines.".format(rec_lines), 0, 1)
                continue
            except Exception as inst:
                exception_line = sys.exc_info()[2].tb_lineno
                self.print("Error. Stopped Profiler Process. Received {} lines".format(rec_lines), 0, 1)
                self.print(f"\tProblem with Profiler Process. line {exception_line}", 0, 1)
                self.print(str(type(inst)), 0, 1)
                self.print(str(inst.args), 0, 1)
                self.print(str(inst), 0, 1)
                self.print(traceback.format_exc())
                return True
