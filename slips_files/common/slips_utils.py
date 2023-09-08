import hashlib
from datetime import datetime, timedelta
from re import findall
import validators
from git import Repo
import socket
import requests
import json
import platform
import os
import sys
import ipaddress
import communityid
from hashlib import sha1
from base64 import b64encode


IS_IN_A_DOCKER_CONTAINER = os.environ.get('IS_IN_A_DOCKER_CONTAINER', False)

class Utils(object):
    name = 'utils'
    description = 'Common functions used by different modules of slips.'
    authors = ['Alya Gomaa']


    def __init__(self):
        self.home_network_ranges_str = (
            '192.168.0.0/16',
            '172.16.0.0/12',
            '10.0.0.0/8',
        )
        # IPv4Network objs
        self.home_network_ranges = list(map(ipaddress.ip_network, self.home_network_ranges_str))
        self.supported_orgs = (
            'google',
            'microsoft',
            'apple',
            'facebook',
            'twitter',
        )
        self.home_networks = ('192.168.0.0', '172.16.0.0', '10.0.0.0')
        self.threat_levels = {
            'info': 0,
            'low': 0.2,
            'medium': 0.5,
            'high': 0.8,
            'critical': 1,
        }
        self.time_formats = (
            '%Y-%m-%dT%H:%M:%S.%f%z',
            '%Y-%m-%d %H:%M:%S.%f',
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%d %H:%M:%S.%f%z',
            '%Y/%m/%d %H:%M:%S.%f%z',
            '%Y/%m/%d %H:%M:%S.%f',
            '%Y/%m/%d %H:%M:%S',
            '%Y-%m-%d %H:%M:%S%z',
            "%Y-%m-%dT%H:%M:%S",
            '%Y-%m-%dT%H:%M:%S%z',
            '%Y/%m/%d-%H:%M:%S',
            '%Y-%m-%dT%H:%M:%S'

         )
        # this format will be used accross all modules and logfiles of slips
        self.alerts_format = '%Y/%m/%d %H:%M:%S.%f%z'
        self.local_tz = self.get_local_timezone()
        self.community_id = communityid.CommunityID()

    def get_cidr_of_ip(self, ip):
        """
        returns the cidr/range of the given private ip
        :param ip: should be  a private ips
        """
        if validators.ipv4(ip):
            first_octet = ip.split('.')[0]
            # see if the first octet of the given ip matches any of the
            # home network ranges
            for network_range in self.home_network_ranges_str:
                if first_octet in network_range:
                    return network_range


    def threat_level_to_string(self, threat_level: float):
        for str_lvl, int_value in self.threat_levels.items():
            if threat_level <= int_value:
                return str_lvl

    def is_valid_threat_level(self, threat_level):
        return threat_level in self.threat_levels

    def sanitize(self, string):
        """
        Sanitize strings taken from the user
        """
        string = string.replace(';', '')
        string = string.replace('\`', '')
        string = string.replace('&', '')
        string = string.replace('|', '')
        string = string.replace('$(', '')
        string = string.replace('\n', '')
        return string

    def detect_data_type(self, data):
        """
        Detects the type of incoming data: ipv4, ipv6, domain, ip range, asn, md5, etc
        """
        data = data.strip()
        try:
            ipaddress.ip_address(data)
            return 'ip'
        except (ipaddress.AddressValueError, ValueError):
            pass

        try:
            ipaddress.ip_network(data)
            return 'ip_range'
        except ValueError:
            pass

        if validators.md5(data):
            return 'md5'

        if validators.domain(data):
            return 'domain'

        # some ti files have / at the end of domains, remove it
        if data.endswith('/'):
            data = data[:-1]

        domain = data
        if domain.startswith('http://'):
            data = data[7:]
        elif domain.startswith('https://'):
            data = data[8:]

        if validators.domain(data):
            return 'domain'
        elif '/' in data:
            return 'url'

        if validators.sha256(data):
            return 'sha256'

        if data.startswith("AS"):
            return 'asn'

    def get_first_octet(self, ip):
        # the ranges stored are sorted by first octet
        if '.' in ip:
            return ip.split('.')[0]
        elif ':' in ip:
            return ip.split(':')[0]
        else:
            # invalid ip
            return


    def drop_root_privs(self):
        """
        Drop root privileges if the module doesn't need them
        Shouldn't be called from __init__ because then, it affects the parent process too
        """

        if platform.system() != 'Linux':
            return
        try:
            # Get the uid/gid of the user that launched sudo
            sudo_uid = int(os.getenv('SUDO_UID'))
            sudo_gid = int(os.getenv('SUDO_GID'))
        except TypeError:
            # env variables are not set, you're not root
            return
        # Change the current process’s real and effective uids and gids to that user
        # -1 means value is not changed.
        os.setresgid(sudo_gid, sudo_gid, -1)
        os.setresuid(sudo_uid, sudo_uid, -1)
        return


    def convert_format(self, ts, required_format: str):
        """
        Detects and converts the given ts to the given format
        :param required_format: can be any format like '%Y/%m/%d %H:%M:%S.%f' or 'unixtimestamp', 'iso'
        """
        given_format = self.define_time_format(ts)
        if given_format == required_format:
            return ts

        if given_format == 'datetimeobj':
            datetime_obj = ts
        else:
            datetime_obj = self.convert_to_datetime(ts)

        # convert to the req format
        if required_format == 'iso':
            return datetime_obj.astimezone().isoformat()
        elif required_format == 'unixtimestamp':
            return datetime_obj.timestamp()
        else:
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

    def is_datetime_obj(self, ts):
        """
        checks if the given ts is a datetime obj
        """
        try:
            ts.strftime('%Y-%m-%dT%H:%M:%S.%f%z')
            return True
        except AttributeError:
            return False

    def convert_to_datetime(self, ts):
        if self.is_datetime_obj(ts):
            return ts

        given_format = self.define_time_format(ts)

        return (
            datetime.fromtimestamp(float(ts))
            if given_format == 'unixtimestamp'
            else datetime.strptime(ts, given_format)
        )


    def define_time_format(self, time: str) -> str:

        if self.is_datetime_obj(time):
            return 'datetimeobj'

        try:
            # Try unix timestamp in seconds.
            datetime.fromtimestamp(float(time))
            return 'unixtimestamp'
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

    def get_own_IPs(self) -> list:
        """
        Returns a list of our local and public IPs
        """
        if '-i' not in sys.argv:
            # this method is only valid when running on an interface
            return []

        IPs = []
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('10.255.255.255', 1))
            IPs.append(s.getsockname()[0])
        except Exception:
            IPs.append('127.0.0.1')
        finally:
            s.close()

        # get public ip

        try:
            response = requests.get(
                'http://ipinfo.io/json',
                timeout=5,
            )
        except (
                requests.exceptions.ConnectionError,
                requests.exceptions.ChunkedEncodingError,
                requests.exceptions.ReadTimeout
        ):
            return IPs

        if response.status_code != 200:
            return IPs
        if 'Connection timed out' in response.text:
            return IPs
        try:
            response = json.loads(response.text)
        except json.decoder.JSONDecodeError:
            return IPs
        public_ip = response['ip']
        IPs.append(public_ip)
        return IPs

    def convert_to_mb(self, bytes):
        return int(bytes)/(10**6)

    def is_ignored_ip(self, ip) -> bool:
        """
        This function checks if an IP is a special list of IPs that
        should not be alerted for different reasons
        """
        ip_obj = ipaddress.ip_address(ip)
        # Is the IP multicast, private? (including localhost)
        # local_link or reserved?
        # The broadcast address 255.255.255.255 is reserved.
        return bool(
            (
                ip_obj.is_multicast
                or ip_obj.is_private
                or ip_obj.is_link_local
                or ip_obj.is_reserved
                or '.255' in ip_obj.exploded
            )
        )

    def get_hash_from_file(self, filename):
        """
        Compute the sha256 hash of a file
        """
        # The size of each read from the file
        BLOCK_SIZE = 65536
        # Create the hash object, can use something other
        # than `.sha256()` if you wish
        file_hash = hashlib.sha256()
        # Open the file to read it's bytes
        with open(filename, 'rb') as f:
            # Read from the file. Take in the amount declared above
            fb = f.read(BLOCK_SIZE)
            # While there is still data being read from the file
            while len(fb) > 0:
                # Update the hash
                file_hash.update(fb)
                # Read the next block from the file
                fb = f.read(BLOCK_SIZE)
        return file_hash.hexdigest()

    def is_msg_intended_for(self, message, channel):
        """
        Function to check
            1. If the given message is intended for this channel
            2. The msg has valid data
        """

        return (
            message
            and type(message['data']) == str
            and message['channel'] == channel
        )

    def change_logfiles_ownership(self, file: str, UID, GID):
        """
        if slips is running in docker, the owner of the alerts log files is always root
        this function changes it to the user ID and GID in slips.conf to be able to
        rwx the files from outside of docker
        """
        if not (IS_IN_A_DOCKER_CONTAINER and UID and GID):
            # they should be anything other than 0
            return

        os.system(f"chown {UID}:{GID} {file}")

    def get_branch_info(self):
        """
        Returns a tuple containing (commit,branch)
        """
        try:
            repo = Repo('.')
            # add branch name and commit
            branch = repo.active_branch.name
            commit = repo.active_branch.commit.hexsha
            return (commit, branch)
        except Exception:
            # when in docker, we copy the repo instead of clone it so there's no .git files
            # we can't add repo metadata
            return False


    def get_time_diff(self, start_time: float, end_time: float, return_type='seconds') -> float:
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
        # if there are days diff between the flows, diff will be something like 1 day, 17:25:57.458395
        try:
            # calculate the days difference
            diff_in_days = float(
                diff.split(', ')[0].split(' ')[0]
            )
            diff = diff.split(', ')[1]
        except (IndexError, ValueError):
            # no days different
            diff = diff.split(', ')[0]
            diff_in_days = 0

        diff_in_hrs, diff_in_mins, diff_in_seconds = [float(i) for i in diff.split(':')]


        diff_in_seconds = diff_in_seconds  + (24 * diff_in_days * 60 + diff_in_hrs * 60 + diff_in_mins)*60
        units = {
            'days': diff_in_seconds /(60*60*24),
            'hours':diff_in_seconds/(60*60),
            'minutes': diff_in_seconds/60,
            'seconds':  diff_in_seconds
        }

        return units[return_type]

    def remove_milliseconds_decimals(self, ts: str) -> str:
        """
        remove the milliseconds from the given ts
        :param ts: time in unix format
        """
        ts = str(ts)
        if '.' not in ts:
            return ts

        return ts.split('.')[0]



    def assert_microseconds(self, ts: str):
        """
        adds microseconds to the given ts if not present
        :param ts: unix ts
        :return: ts
        """
        ts = self.convert_format(ts, 'unixtimestamp')

        ts = str(ts)
        # pattern of unix ts with microseconds
        pattern = r'\b\d+\.\d{6}\b'
        matches = findall(pattern, ts)

        if not matches:
            # fill the missing microseconds and milliseconds with 0
            # 6 is the decimals we need after the . in the unix ts
            ts = ts + "0" * (6 - len(ts.split('.')[-1]))
        return ts

    def get_aid(self, flow):
        """
        calculates the flow SHA1(cid+ts) aka All-ID of the flow
        because we need the flow ids to be unique to be able to compare them
        """
        #TODO document this
        community_id = self.get_community_id(flow)
        ts = flow.starttime
        ts: str = self.assert_microseconds(ts)

        aid = f"{community_id}-{ts}"

        # convert the input string to bytes (since hashlib works with bytes)
        aid: str = sha1(aid.encode('utf-8')).hexdigest()
        aid: str = b64encode(aid.encode()).decode()
        return aid


    def get_community_id(self, flow):
        """
        calculates the flow community id based of the protocol
        """
        proto = flow.proto.lower()
        cases = {
            'tcp': communityid.FlowTuple.make_tcp,
            'udp': communityid.FlowTuple.make_udp,
            'icmp': communityid.FlowTuple.make_icmp,
        }
        try:
            tpl = cases[proto](flow.saddr, flow.daddr, flow.sport, flow.dport)
            return self.community_id.calc(tpl)
        except KeyError:
            # proto doesn't have a community_id.FlowTuple  method
            return ''

    def IDEA_format(
        self,
        srcip,
        evidence_type,
        attacker_direction,
        attacker,
        description,
        confidence,
        category,
        conn_count,
        source_target_tag,
        port,
        proto,
        evidence_id
    ):
        """
        Function to format our evidence according to Intrusion Detection Extensible Alert (IDEA format).
        Detailed explanation of IDEA categories: https://idea.cesnet.cz/en/classifications
        """
        IDEA_dict = {
            'Format': 'IDEA0',
            'ID': evidence_id,
            # both times represet the time of the detection, we probably don't need flow_datetime
            'DetectTime': datetime.now(self.local_tz).isoformat(),
            'EventTime': datetime.now(self.local_tz).isoformat(),
            'Category': [category],
            'Confidence': confidence,
            'Source': [{}],
        }

        # is the srcip ipv4/ipv6 or mac?
        if validators.ipv4(srcip):
            IDEA_dict['Source'][0].update({'IP4': [srcip]})
        elif validators.ipv6(srcip):
            IDEA_dict['Source'][0].update({'IP6': [srcip]})
        elif validators.mac_address(srcip):
            IDEA_dict['Source'][0].update({'MAC': [srcip]})
        elif validators.url(srcip):
            IDEA_dict['Source'][0].update({'URL': [srcip]})


        # When someone communicates with C&C, both sides of communication are
        # sources, differentiated by the Type attribute, 'C&C' or 'Botnet'
        if evidence_type == 'Command-and-Control-channels-detection':
            # get the destination IP
            dstip = description.split('destination IP: ')[1].split(' ')[0]

            if validators.ipv4(dstip):
                ip_version = 'IP4'
            elif validators.ipv6(dstip):
                ip_version = 'IP6'

            IDEA_dict['Source'].append({ip_version: [dstip], 'Type': ['CC']})

        # some evidence have a dst ip
        if 'dstip' in attacker_direction or 'dip' in attacker_direction:
            # is the dstip ipv4/ipv6 or mac?
            if validators.ipv4(attacker):
                IDEA_dict['Target'] = [{'IP4': [attacker]}]
            elif validators.ipv6(attacker):
                IDEA_dict['Target'] = [{'IP6': [attacker]}]
            elif validators.mac_address(attacker):
                IDEA_dict['Target'] = [{'MAC': [attacker]}]
            elif validators.url(attacker):
                IDEA_dict['Target'][0].update({'URL': [srcip]})

            # try to extract the hostname/SNI/rDNS of the dstip form the description if available
            hostname = False
            try:
                hostname = description.split('rDNS: ')[1]
            except IndexError:
                pass
            try:
                hostname = description.split('SNI: ')[1]
            except IndexError:
                pass
            if hostname:
                IDEA_dict['Target'][0].update({'Hostname': [hostname]})

            # update the dstip description if specified in the evidence
            if source_target_tag:    # https://idea.cesnet.cz/en/classifications#sourcetargettagsourcetarget_classification
                IDEA_dict['Target'][0].update({'Type': [source_target_tag]})

        elif 'domain' in attacker_direction:
            # the ioc is a domain
            attacker_type = 'Hostname' if validators.domain(attacker) else 'URL'
            target_info = {attacker_type: [attacker]}
            IDEA_dict['Target'] = [target_info]

            # update the dstdomain description if specified in the evidence
            if source_target_tag:
                IDEA_dict['Target'][0].update({'Type': [source_target_tag]})
        elif source_target_tag:
            # the ioc is the srcip, therefore the tag is desscribing the source
            IDEA_dict['Source'][0].update({'Type': [source_target_tag]})



        # add the port/proto
        # for all alerts, the srcip is in IDEA_dict['Source'][0] and the dstip is in IDEA_dict['Target'][0]
        # for alert that only have a source, this is the port/proto of the source ip
        key = 'Source'
        idx = 0   # this idx is used for selecting the right dict to add port/proto

        if 'Target' in IDEA_dict:
            # if the alert has a target, add the port/proto to the target(dstip)
            key = 'Target'
            idx = 0

        # for C&C alerts IDEA_dict['Source'][0] is the Botnet aka srcip and IDEA_dict['Source'][1] is the C&C aka dstip
        if evidence_type == 'Command-and-Control-channels-detection':
            # idx of the dict containing the dstip, we'll use this to add the port and proto to this dict
            key = 'Source'
            idx = 1

        if port:
            IDEA_dict[key][idx].update({'Port': [int(port)]})
        if proto:
            IDEA_dict[key][idx].update({'Proto': [proto.lower()]})

        # add the description
        attachment = {
            'Attach': [
                {
                    'Content': description,
                    'ContentType': 'text/plain',
                }
            ]
        }
        IDEA_dict.update(attachment)

        # only evidence of type scanning have conn_count
        if conn_count:
            IDEA_dict['ConnCount'] = conn_count

        if 'MaliciousDownloadedFile' in evidence_type:
            IDEA_dict['Attach'] = [
                {
                    'Type': ['Malware'],
                    'Hash': [f'md5:{attacker}'],
                }

            ]
            if 'size' in description:
                IDEA_dict.update(
                    {'Size': int(description.replace(".",'').split('size:')[1].split('from')[0])}
                )

        return IDEA_dict

utils = Utils()
