
from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database.database import __database__
from slips_files.common.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
import sys
import traceback
import json
import urllib
import requests
import dpkt
import socket
import sys
import os
from repoze.lru import LRUCache
from sets import Set
from multiprocessing import Pool, Manager, Queue, Lock

PORT_SET = {80} #only inspect TCP port 80
manager = Manager()
results = Queue()
lock = Lock()

class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'HTTP Analyzer'
    description = 'Analyze HTTP flows'
    authors = ['Alya Gomaa']

    def __init__(self, outputqueue, redis_port):
        multiprocessing.Process.__init__(self)
        # The outputqueue is connected to another process called OutputProcess
        self.outputqueue = outputqueue
        __database__.start(redis_port)
        self.c1 = __database__.subscribe('new_http')
        self.connections_counter = {}
        self.empty_connections_threshold = 4
        # this is a list of hosts known to be resolved by malware
        # to check your internet connection
        self.hosts = ['bing.com', 'google.com', 'yandex.com', 'yahoo.com', 'duckduckgo.com']
        self.read_configuration()

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
        self.pastebin_downloads_threshold = conf.get_pastebin_download_threshold()

    def check_suspicious_user_agents(
        self, uid, host, uri, timestamp, user_agent, profileid, twid
    ):
        """Check unusual user agents and set evidence"""

        suspicious_user_agents = (
            'httpsend',
            'chm_msdn',
            'pb',
            'jndi',
            'tesseract',
        )
        for suspicious_ua in suspicious_user_agents:
            if suspicious_ua.lower() in user_agent.lower():
                attacker_direction = 'srcip'
                source_target_tag = 'SuspiciousUserAgent'
                attacker = profileid.split('_')[1]
                evidence_type = 'SuspiciousUserAgent'
                threat_level = 'high'
                category = 'Anomaly.Behaviour'
                confidence = 1
                description = f'suspicious user-agent: {user_agent} while connecting to {host}{uri}'
                __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence,
                                         description, timestamp, category, source_target_tag=source_target_tag,
                                         profileid=profileid, twid=twid, uid=uid)
                return True
        return False

    def check_multiple_empty_connections(
        self, uid, contacted_host, timestamp, request_body_len, profileid, twid
    ):
        """
        Detects more than 4 empty connections to google, bing, yandex and yahoo on port 80
        """
        # to test this wget google.com:80 twice
        # wget makes multiple connections per command,
        # 1 to google.com and another one to www.google.com

        for host in self.hosts:
            if (
                (contacted_host == host
                 or contacted_host == f'www.{host}')
                and request_body_len == 0
            ):
                try:
                    # this host has past connections, add to counter
                    uids, connections = self.connections_counter[host]
                    connections +=1
                    uids.append(uid)
                    self.connections_counter[host] = (uids, connections)
                except KeyError:
                    # first empty connection to this host
                    self.connections_counter.update({host: ([uid], 1)})
                break
        else:
            # it's an http connection to a domain that isn't
            # in self.hosts, or simply not an empty connection
            # ignore it
            return False

        uids, connections = self.connections_counter[host]
        if connections == self.empty_connections_threshold:
            evidence_type = 'EmptyConnections'
            attacker_direction = 'srcip'
            attacker = profileid.split('_')[0]
            threat_level = 'medium'
            category = 'Anomaly.Connection'
            confidence = 1
            description = f'multiple empty HTTP connections to {host}'
            __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence,
                                     description, timestamp, category, profileid=profileid, twid=twid, uid=uids)
            # reset the counter
            self.connections_counter[host] = ([], 0)
            return True
        return False

    def set_evidence_incompatible_user_agent(
        self, host, uri, vendor, user_agent, timestamp, profileid, twid, uid
    ):
        attacker_direction = 'srcip'
        source_target_tag = 'IncompatibleUserAgent'
        attacker = profileid.split('_')[1]
        evidence_type = 'IncompatibleUserAgent'
        threat_level = 'high'
        category = 'Anomaly.Behaviour'
        confidence = 1
        os_type = user_agent.get('os_type', '').lower()
        os_name = user_agent.get('os_name', '').lower()
        browser = user_agent.get('browser', '').lower()
        user_agent = user_agent.get('user_agent', '')
        description = (
            f'using incompatible user-agent that belongs to OS: {os_name} type: {os_type} browser: {browser}. '
            f'while connecting to {host}{uri}. '
            f'IP has MAC vendor: {vendor.capitalize()}'
        )
        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag, profileid=profileid,
                                 twid=twid, uid=uid)



    def check_incompatible_user_agent(
        self, host, uri, timestamp, profileid, twid, uid
    ):
        """
        Compare the user agent of this profile to the MAC vendor and check incompatibility
        """
        # get the mac vendor
        vendor = __database__.get_mac_vendor_from_profile(profileid)
        if not vendor:
            return False
        vendor = vendor.lower()

        user_agent: dict = __database__.get_user_agent_from_profile(profileid)
        if not user_agent or type(user_agent) != dict:
            return False

        os_type = user_agent.get('os_type', '').lower()
        os_name = user_agent.get('os_name', '').lower()
        browser = user_agent.get('browser', '').lower()
        # user_agent = user_agent.get('user_agent', '')
        if 'safari' in browser and 'apple' not in vendor:
            self.set_evidence_incompatible_user_agent(
                host, uri, vendor, user_agent, timestamp, profileid, twid, uid
            )
            return True

        # make sure all of them are lowercase
        # no user agent should contain 2 keywords from different tuples
        os_keywords = [
            ('macos', 'ios', 'apple', 'os x', 'mac', 'macintosh', 'darwin'),
            ('microsoft', 'windows', 'nt'),
            ('android', 'google'),
        ]

        # check which tuple does the vendor belong to
        found_vendor_tuple = False
        for tuple_ in os_keywords:
            for keyword in tuple_:
                if keyword in vendor:
                    # this means this computer belongs to this org
                    # create a copy of the os_keywords list without the correct org
                    # FOR EXAMPLE if the mac vendor is apple, the os_keyword should be
                    # [('microsoft', 'windows', 'NT'), ('android'), ('linux')]
                    os_keywords.pop(os_keywords.index(tuple_))
                    found_vendor_tuple = True
                    break
            if found_vendor_tuple:
                break

        if not found_vendor_tuple:
            # MAC vendor isn't apple, microsoft  or google
            # we don't know how to check for incompatibility  #todo
            return False

        # see if the os name and type has any keyword of the rest of the tuples
        for tuple_ in os_keywords:
            for keyword in tuple_:
                if keyword in f'{os_name} {os_type}':
                    # from the same example,
                    # this means that one of these keywords [('microsoft', 'windows', 'NT'), ('android'), ('linux')]
                    # is found in the UA that belongs to an apple device
                    self.set_evidence_incompatible_user_agent(
                        host,
                        uri,
                        vendor,
                        user_agent,
                        timestamp,
                        profileid,
                        twid,
                        uid,
                    )

                    return True

    def get_ua_info_online(self, user_agent):
        """
        Get OS and browser info about a use agent from an online database http://useragentstring.com
        """
        url = f'http://useragentstring.com/'
        params = {
            'uas': user_agent,
            'getJSON':'all'
        }
        params = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
        try:

            response = requests.get(url, params=params, timeout=5)
            if response.status_code != 200 or not response.text:
                raise requests.exceptions.ConnectionError
        except requests.exceptions.ConnectionError:
            return False

        # returns the following
        # {"agent_type":"Browser","agent_name":"Internet Explorer","agent_version":"8.0",
        # "os_type":"Windows","os_name":"Windows 7","os_versionName":"","os_versionNumber":"",
        # "os_producer":"","os_producerURL":"","linux_distibution":"Null","agent_language":"","agent_languageTag":""}
        try:
            # responses from this domain are broken for now. so this is a temp fix until they fix it from their side
            json_response = json.loads(response.text)
        except json.decoder.JSONDecodeError:
            # unexpected server response
            return False
        return json_response

    def get_user_agent_info(self, user_agent: str, profileid: str):
        """
        Get OS and browser info about a user agent online
        """
        # some zeek http flows don't have a user agent field
        if not user_agent:
            return False

        # don't make a request again if we already have a user agent associated with this profile
        if __database__.get_user_agent_from_profile(profileid) != None:
            # this profile already has a user agent
            return False

        UA_info = {
            'user_agent': user_agent,
            'os_type' : '',
            'os_name': ''
        }

        ua_info = self.get_ua_info_online(user_agent)
        if ua_info:
            # the above website returns unknown if it has no info about this UA,
            # remove the 'unknown' from the string before storing in the db
            os_type = (
                ua_info.get('os_type', '')
                .replace('unknown', '')
                .replace('  ', '')
            )
            os_name = (
                ua_info.get('os_name', '')
                .replace('unknown', '')
                .replace('  ', '')
            )
            browser = (
                ua_info.get('agent_name', '')
                .replace('unknown', '')
                .replace('  ', '')
            )

            UA_info.update(
                {
                    'os_name': os_name,
                    'os_type': os_type,
                    'browser': browser,
                }
            )

        __database__.add_user_agent_to_profile(profileid, json.dumps(UA_info))
        return UA_info

    def extract_info_from_UA(self, user_agent, profileid):
        """
        Zeek sometimes collects info about a specific UA, in this case the UA starts with
        'server-bag'
        """
        if __database__.get_user_agent_from_profile(profileid) != None:
            # this profile already has a user agent
            return True
        # for example: server-bag[macOS,11.5.1,20G80,MacBookAir10,1]
        user_agent = (
            user_agent.replace('server-bag', '')
            .replace(']', '')
            .replace('[', '')
        )
        UA_info = {'user_agent': user_agent}
        os_name = user_agent.split(',')[0]
        os_type = os_name + user_agent.split(',')[1]
        UA_info.update(
            {
                'os_name': os_name,
                'os_type': os_type,
                # server bag UAs don't have browser info
                'browser': '',
            }
        )
        UA_info = json.dumps(UA_info)
        __database__.add_user_agent_to_profile(profileid, UA_info)
        return UA_info

    def check_multiple_UAs(
        self,
        cached_ua: dict,
        user_agent: dict,
        timestamp,
        profileid,
        twid,
        uid,
    ):
        """
        Detect if the user is using an Apple UA, then android, then linux etc.
        Doesn't check multiple ssh clients
        :param user_agent: UA of the current flow
        :param cached_ua: UA of this profile from the db
        """
        if not cached_ua or not user_agent:
            return False
        os_type = cached_ua['os_type']
        os_name = cached_ua['os_name']
        # todo now the first UA seen is considered the only valid one and slips
        #  will setevidence everytime another one is used, is that correct?
        for keyword in (os_type, os_name):
            # loop through each word in UA
            if keyword in user_agent:
                # for example if the os of the cached UA is Linux and the current UA
                # is Mozilla/5.0 (X11; Fedora;Linux x86; rv:60.0)
                # we will find the keyword 'Linux' in both UAs, so we shouldn't alert
                return False

        attacker_direction = 'srcip'
        source_target_tag = 'MultipleUserAgent'
        attacker = profileid.split('_')[1]
        evidence_type = 'IncompatibleUserAgent'
        threat_level = 'info'
        category = 'Anomaly.Behaviour'
        confidence = 1
        ua = cached_ua.get('user_agent', '')
        description = (
            f'using multiple user-agents: {ua} then {user_agent}'
        )
        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag, profileid=profileid,
                                 twid=twid, uid=uid)
        return True

    def check_pastebin_downloads(
            self,
            daddr,
            response_body_len,
            method,
            profileid,
            twid,
            timestamp,
            uid
    ):
        try:
            response_body_len = int(response_body_len)
        except ValueError:
            return False

        ip_identification = __database__.getIPIdentification(daddr)
        if ('pastebin' in ip_identification
            and response_body_len > self.pastebin_downloads_threshold
            and method == 'GET'):
            attacker_direction = 'dstip'
            source_target_tag = 'Malware'
            attacker = daddr
            evidence_type = 'PastebinDownload'
            threat_level = 'info'
            category = 'Anomaly.Behaviour'
            confidence = 1
            response_body_len = utils.convert_to_mb(response_body_len)
            description = (
               f'A downloaded file from pastebin.com. size: {response_body_len} MBs'
            )
            __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence,
                                     description, timestamp, category, source_target_tag=source_target_tag,
                                     profileid=profileid, twid=twid, uid=uid)
            return True

    def detect_binary_downloads(
            self,
            resp_mime_types,
            daddr,
            host,
            uri,
            timestamp,
            profileid,
            twid,
            uid
    ):
        if not resp_mime_types or not ('application/x-dosexec' in resp_mime_types):
            return False

        attacker_direction = 'dstdomain'
        source_target_tag = 'Malware'
        attacker = f'{host}{uri}'
        evidence_type = 'DOSExecutableDownload'
        threat_level = 'low'
        category = 'Information'
        confidence = 1
        description = (
            f'DOS executable binary download from IP: {daddr} {attacker}'
        )
        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag, profileid=profileid,
                                 twid=twid, uid=uid)
        return True


    def shutdown_gracefully(self):
        __database__.publish('finished_modules', self.name)

    def run(self):
        utils.drop_root_privs()
        # Main loop function
        while True:
            try:
                message = __database__.get_message(self.c1)
                if message and message['data'] == 'stop_process':
                    self.shutdown_gracefully()
                    return True

                if utils.is_msg_intended_for(message, 'new_http'):
                    message = json.loads(message['data'])
                    profileid = message['profileid']
                    twid = message['twid']
                    flow = json.loads(message['flow'])
                    uid = flow['uid']
                    host = flow['host']
                    uri = flow['uri']
                    daddr = flow['daddr']
                    timestamp = flow.get('stime', '')
                    user_agent = flow.get('user_agent', False)
                    request_body_len = flow.get('request_body_len')
                    response_body_len = flow.get('response_body_len')
                    method = flow.get('method')
                    resp_mime_types = flow.get('resp_mime_types')

                    self.check_suspicious_user_agents(
                        uid, host, uri, timestamp, user_agent, profileid, twid
                    )
                    self.check_multiple_empty_connections(
                        uid, host, timestamp, request_body_len, profileid, twid
                    )
                    # find the UA of this profileid if we don't have it
                    # get the last used ua of this profile
                    cached_ua = __database__.get_user_agent_from_profile(
                        profileid
                    )
                    if cached_ua:
                        self.check_multiple_UAs(
                            cached_ua,
                            user_agent,
                            timestamp,
                            profileid,
                            twid,
                            uid,
                        )

                    if (
                        not cached_ua
                        or (type(cached_ua) == dict
                            and cached_ua.get('user_agent', '') != user_agent
                            and 'server-bag' not in user_agent)
                    ):
                        # only UAs of type dict are browser UAs, skips str UAs as they are SSH clients
                        self.get_user_agent_info(
                            user_agent,
                            profileid
                        )

                    if 'server-bag' in user_agent:
                        self.extract_info_from_UA(
                            user_agent,
                            profileid
                        )

                    self.check_incompatible_user_agent(
                        host,
                        uri,
                        timestamp,
                        profileid,
                        twid,
                        uid
                    )

                    self.check_pastebin_downloads(
                        daddr,
                        response_body_len,
                        method,
                        profileid,
                        twid,
                        timestamp,
                        uid
                    )

                    self.detect_binary_downloads(
                        resp_mime_types,
                        daddr,
                        host,
                        uri,
                        timestamp,
                        profileid,
                        twid,
                        uid
                    )

            except KeyboardInterrupt:
                self.shutdown_gracefully()
                return True
            except Exception as inst:
                exception_line = sys.exc_info()[2].tb_lineno
                self.print(f'Problem on the run() line {exception_line}', 0, 1)
                self.print(traceback.format_exc(), 0, 1)
                return True
            
    


    def get_key(ip, tcp):
        five_tuple = ip.src + ":" + str(tcp.sport) + "\t" + ip.dst + ":" + str(tcp.dport)
        return five_tuple + "\t" + str(tcp.seq)

    def get_five_tuple_string(ip, tcp):
        return socket.inet_ntoa(ip.src) + ":" + str(tcp.sport) + "-" + socket.inet_ntoa(ip.dst) + ":" + str(tcp.dport)


    def get_ip_packet(self, buf, pcap):

        if pcap.datalink() == dpkt.pcap.DLT_LINUX_SLL:
            sll = dpkt.sll.SLL(buf)
            return sll.data
        elif pcap.datalink() == dpkt.pcap.DLT_IEEE802 or pcap.datalink() == dpkt.pcap.DLT_EN10MB:
            try:
                ethernet = dpkt.ethernet.Ethernet(buf)
                if(ethernet.type == dpkt.ethernet.ETH_TYPE_IP):
                    return ethernet.data
                else:
                    return None
            except dpkt.UnpackError as e:
                return None
        elif pcap.datalink() == dpkt.pcap.DLT_RAW or pcap.datalink() == dpkt.pcap.DLT_LOOP:
            #Raw IP only supported for ETH_TYPE 0x0c. Type 0x65 is not supported by DPKT
            return dpkt.ip.IP(buf)
        elif pcap.datalink() == dpkt.pcap.DLT_NULL:
            frame = dpkt.loopback.Loopback(buf)
            return frame.data
        else:
            self.print(sys.stderr, "unknown datalink!")
            exit

    def injection_found(self, fn,ip, tcp, old_tcp_data):
        res=dict()
        res["filename"]=fn
        res["5tuple"]=get_five_tuple_string(ip,tcp)
        res["seq"]=str(tcp.seq)
        res["first"]=repr(old_tcp_data)
        res["last"]=repr(tcp.data)
        #results.append(res)
        results.put(res)
        lock.acquire()
        self.print(fn + " - INJECTION FOUND!")
        self.print("5-tuple:       \t" + res["5tuple"])
        self.print("Sequence numer:\t" + res["seq"])
        self.print("First:         \t" + res["first"])
        self.print("Last:          \t" + res["last"])
        sys.stdout.flush()
        lock.release()


    def find_injections(self, pcap_file):
        _cache = LRUCache(10000) #100.000 entries - should last at least 100 msec on a 100% utilized gigabit network
        _hitset = Set()
        with open(pcap_file, "rb") as f:
            try:
                pcap = dpkt.pcap.Reader(f)
                for ts, buf in pcap:
                    ip = get_ip_packet(buf, pcap)
                    try:
                        if(ip is not None and ip.p == dpkt.ip.IP_PROTO_TCP):
                            tcp = ip.data
                            if((tcp.sport in PORT_SET or tcp.dport in PORT_SET) and len(tcp.data) > 1):
                                key = get_key(ip, tcp)
                                #ip.len    : 11 bits
                                #ip.ttl    : 8 bits
                                #tcp.flags : 8 bits (normally)
                                value = ip.ttl<<24 ^ (tcp.flags<<16) ^ ip.len
                                if(_cache.get(key) is None):
                                    _cache.put(key, value)
                                else:
                                    if(_cache.get(key) != value):
                                        _hitset.add(key)
                    except: pass

            except dpkt.dpkt.NeedData: pass
            except ValueError:
                if(len(_cache.data) == 0):
                    self.print >> sys.stderr, "Unable to parse " + pcap_file + ", incorrect file format!"
                    return
        injection_count = 0
        if(len(_hitset) > 0):
            _cache = LRUCache(1024)
            with open(pcap_file, "rb") as f:
                pcap = dpkt.pcap.Reader(f)
                try:
                    for ts, buf in pcap:
                        ip = get_ip_packet(buf, pcap)
                        try:
                            if(ip is not None and ip.p == dpkt.ip.IP_PROTO_TCP and (ip.data.sport in PORT_SET or ip.data.dport in PORT_SET)):
                                key = get_key(ip, ip.data)
                                if(key in _hitset and len(ip.data.data) > 1):
                                    tcp = ip.data
                                    _cached_tcp_data = _cache.get(key)
                                    if(_cached_tcp_data is None):
                                        _cache.put(key, tcp.data)
                                    else:
                                        if(tcp.data != _cached_tcp_data):
                                            if(len(tcp.data) > len(_cached_tcp_data)):
                                                #new data is longer, store that
                                                if(tcp.data[:len(_cached_tcp_data)] != _cached_tcp_data):
                                                    injection_found(pcap_file,ip, tcp, _cached_tcp_data)
                                                    injection_count+=1
                                                _cache.put(key, tcp.data)
                                            elif(len(tcp.data) < len(_cached_tcp_data)):
                                                if(tcp.data != _cached_tcp_data[:len(tcp.data)]):
                                                    injection_found(pcap_file,ip, tcp, _cached_tcp_data)
                                                    injection_count+=1
                                            else:
                                                injection_found(pcap_file,ip, tcp, _cached_tcp_data)
                                                injection_count+=1
                        except AttributeError: pass
                except dpkt.dpkt.NeedData: pass
        if(injection_count == 0):
            lock.acquire()
            self.print(pcap_file+" - no injections")
            sys.stdout.flush()
            lock.release()


if len(sys.argv) < 2:
    sys.exit('Usage: %s dump.pcap' % sys.argv[0])

flist = list()
pool = Pool(processes=4)
for file in sys.argv[1:]:
    if not os.path.exists(file):
        self.print("ERROR: File %s does not exist!" % file)
    else:
        flist.append(file)
pool.map(find_injections, flist)

