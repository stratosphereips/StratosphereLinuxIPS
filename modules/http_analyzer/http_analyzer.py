from slips_files.common.imports import *
import json
import urllib
import requests


class HTTPAnalyzer(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'HTTP Analyzer'
    description = 'Analyze HTTP flows'
    authors = ['Alya Gomaa']

    def init(self):
        self.c1 = self.db.subscribe('new_http')
        self.channels = {
            'new_http': self.c1
        }
        self.connections_counter = {}
        self.empty_connections_threshold = 4
        # this is a list of hosts known to be resolved by malware
        # to check your internet connection
        self.hosts = ['bing.com', 'google.com', 'yandex.com', 'yahoo.com', 'duckduckgo.com', 'gmail.com']
        self.read_configuration()
        self.executable_mime_types = [
            'application/x-msdownload',
            'application/x-ms-dos-executable',
            'application/x-ms-exe',
            'application/x-exe',
            'application/x-winexe',
            'application/x-winhlp',
            'application/x-winhelp',
            'application/octet-stream',
            'application/x-dosexec'
        ]


    def read_configuration(self):
        conf = ConfigParser()
        self.pastebin_downloads_threshold = conf.get_pastebin_download_threshold()

    def detect_executable_mime_types(self, resp_mime_types: list) -> bool:
        """
        detects the type of file in the http response,
        returns true if it's an executable
        """
        if not resp_mime_types:
            return False

        for mime_type in resp_mime_types:
            if mime_type in self.executable_mime_types:
                return True
        return False

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
                victim = f'{host}{uri}'
                description = f'suspicious user-agent: {user_agent} while connecting to {victim}'
                self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence,
                                         description, timestamp, category, source_target_tag=source_target_tag,
                                         profileid=profileid, twid=twid, uid=uid, victim=victim)
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
            if contacted_host in [host, f'www.{host}'] and request_body_len == 0:
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
            self.db.setEvidence(evidence_type,
                                attacker_direction,
                                attacker,
                                threat_level,
                                confidence,
                                description,
                                timestamp,
                                category,
                                profileid=profileid,
                                twid=twid,
                                uid=uids,
                                victim=host)
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
        victim = f'{host}{uri}'
        description = (
            f'using incompatible user-agent ({user_agent}) that belongs to OS: {os_name} '
            f'type: {os_type} browser: {browser}. '
            f'while connecting to {victim}. '
            f'IP has MAC vendor: {vendor.capitalize()}'
        )
        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag, profileid=profileid,
                                 twid=twid, uid=uid, victim=victim)
        
    def report_executable_mime_type(self, mime_type, attacker, profileid, twid, uid, timestamp):
        confidence = 1
        threat_level = 'low'
        source_target_tag = 'ExecutableMIMEType'
        category = 'Anomaly.File'
        evidence_type = 'ExecutableMIMEType'
        attacker_direction = 'dstip'
        srcip = profileid.split('_')[1]
        ip_identification = self.db.get_ip_identification(attacker)
        description = f'download of an executable with mime type: {mime_type} ' \
                      f'by {srcip} from {attacker} {ip_identification}.'

        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag, profileid=profileid,
                                 twid=twid, uid=uid)


    def check_incompatible_user_agent(
        self, host, uri, timestamp, profileid, twid, uid
    ):
        """
        Compare the user agent of this profile to the MAC vendor and check incompatibility
        """
        # get the mac vendor
        vendor = self.db.get_mac_vendor_from_profile(profileid)
        if not vendor:
            return False
        vendor = vendor.lower()

        user_agent: dict = self.db.get_user_agent_from_profile(profileid)
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
        url = 'http://useragentstring.com/'
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

        # keep a history of the past user agents
        self.db.add_all_user_agent_to_profile(profileid, user_agent)

        # don't make a request again if we already have a user agent associated with this profile
        if self.db.get_user_agent_from_profile(profileid) is not None:
            # this profile already has a user agent
            return False

        UA_info = {
            'user_agent': user_agent,
            'os_type' : '',
            'os_name': ''
        }

        if ua_info := self.get_ua_info_online(user_agent):
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

        self.db.add_user_agent_to_profile(profileid, json.dumps(UA_info))
        return UA_info

    def extract_info_from_UA(self, user_agent, profileid):
        """
        Zeek sometimes collects info about a specific UA, in this case the UA starts with
        'server-bag'
        """
        if self.db.get_user_agent_from_profile(profileid) is not None:
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
        self.db.add_user_agent_to_profile(profileid, UA_info)
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
        evidence_type = 'MultipleUserAgent'
        threat_level = 'info'
        category = 'Anomaly.Behaviour'
        confidence = 1
        ua = cached_ua.get('user_agent', '')
        description = (
            f'using multiple user-agents: "{ua}" then "{user_agent}"'
        )
        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag, profileid=profileid,
                                 twid=twid, uid=uid)
        return True


    def set_evidence_http_traffic(self, daddr, profileid, twid, uid, timestamp):
        """
        Detect when a new HTTP flow is found stating that the traffic is unencrypted
        """
        confidence = 1
        threat_level = 'low'
        source_target_tag = 'SendingUnencryptedData'
        category = 'Anomaly.Traffic'
        evidence_type = 'HTTPtraffic'
        attacker_direction = 'dstip'
        attacker = daddr
        saddr = profileid.split('_')[-1]
        description = (f'Unencrypted HTTP traffic from {saddr} to {daddr}.')

        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
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

        ip_identification = self.db.get_ip_identification(daddr)
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
            self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence,
                                     description, timestamp, category, source_target_tag=source_target_tag,
                                     profileid=profileid, twid=twid, uid=uid)
            return True


    def pre_main(self):
        utils.drop_root_privs()

    def main(self):
        if msg:= self.get_msg('new_http'):
            message = json.loads(msg['data'])
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
            cached_ua = self.db.get_user_agent_from_profile(
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

            if self.detect_executable_mime_types(resp_mime_types):
                self.report_executable_mime_type(
                    resp_mime_types,
                    daddr,
                    profileid,
                    twid,
                    uid,
                    timestamp
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


            self.set_evidence_http_traffic(
                daddr,
                profileid,
                twid,
                uid,
                timestamp
            )
