# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import asyncio
import json
import urllib
import requests
from typing import Union, Dict, Optional, List, Tuple
import time
import bisect
from multiprocessing import Lock

from modules.http_analyzer.set_evidence import SetEvidenceHelper
from slips_files.common.flow_classifier import FlowClassifier
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
from slips_files.common.abstracts.async_module import AsyncModule


ESTAB = "Established"


class HTTPAnalyzer(AsyncModule):
    # Name: short name of the module. Do not use spaces
    name = "HTTP Analyzer"
    description = "Analyze HTTP flows"
    authors = ["Alya Gomaa"]

    def init(self):
        self.c1 = self.db.subscribe("new_http")
        self.c2 = self.db.subscribe("new_weird")
        self.c3 = self.db.subscribe("new_flow")
        self.channels = {
            "new_http": self.c1,
            "new_weird": self.c2,
            "new_flow": self.c3,
        }
        self.set_evidence = SetEvidenceHelper(self.db)
        self.connections_counter = {}
        self.empty_connections_threshold = 4
        # this is a list of hosts known to be resolved by malware
        # to check your internet connection
        # usually malware makes empty connections to these hosts while
        # checking for internet
        self.empty_connection_hosts = [
            "bing.com",
            "google.com",
            "yandex.com",
            "yahoo.com",
            "duckduckgo.com",
            "gmail.com",
        ]
        self.read_configuration()
        self.executable_mime_types = [
            "application/x-msdownload",
            "application/x-ms-dos-executable",
            "application/x-ms-exe",
            "application/x-exe",
            "application/x-winexe",
            "application/x-winhlp",
            "application/x-winhelp",
            "application/octet-stream",
            "application/x-dosexec",
        ]
        self.classifier = FlowClassifier()
        self.http_recognized_flows: Dict[Tuple[str, str], List[float]] = {}
        self.ts_of_last_cleanup_of_http_recognized_flows = time.time()
        self.http_recognized_flows_lock = Lock()
        self.condition = asyncio.Condition()

    def read_configuration(self):
        conf = ConfigParser()
        self.pastebin_downloads_threshold = (
            conf.get_pastebin_download_threshold()
        )

    def detect_executable_mime_types(self, twid, flow) -> bool:
        """
        detects the type of file in the http response,
        returns true if it's an executable
        """
        if not flow.resp_mime_types:
            return False

        for mime_type in flow.resp_mime_types:
            if mime_type in self.executable_mime_types:
                self.set_evidence.executable_mime_type(twid, flow)
                return True
        return False

    def check_suspicious_user_agents(self, profileid, twid, flow):
        """Check unusual user agents and set evidence"""

        suspicious_user_agents = (
            "httpsend",
            "chm_msdn",
            "pb",
            "jndi",
            "tesseract",
        )

        for suspicious_ua in suspicious_user_agents:
            if suspicious_ua.lower() not in flow.user_agent.lower():
                continue
            self.set_evidence.suspicious_user_agent(flow, profileid, twid)
            return True
        return False

    def check_multiple_empty_connections(self, twid: str, flow):
        """
        Detects more than 4 empty connections to
            google, bing, yandex and yahoo on port 80
        an evidence is generted only when the 4 conns have an empty uri
        """
        # to test this wget google.com:80 twice
        # wget makes multiple connections per command,
        # 1 to google.com and another one to www.google.com
        if flow.uri != "/":
            # emtpy detections are only done when we go to bing.com,
            # bing.com/something seems benign
            return False

        if not utils.is_valid_domain(flow.host):
            # may be an ip
            return False

        for host in self.empty_connection_hosts:
            if (
                flow.host in [host, f"www.{host}"]
                and flow.request_body_len == 0
            ):
                try:
                    # this host has past connections, add to counter
                    uids, connections = self.connections_counter[host]
                    connections += 1
                    uids.append(flow.uid)
                    self.connections_counter[host] = (uids, connections)
                except KeyError:
                    # first empty connection to this host
                    self.connections_counter.update({host: ([flow.uid], 1)})
                break
        else:
            # it's an http connection to a domain that isn't
            # in self.hosts, or simply not an empty connection
            # ignore it
            return False

        uids, connections = self.connections_counter[host]
        if connections != self.empty_connections_threshold:
            return False

        self.set_evidence.multiple_empty_connections(flow, host, uids, twid)
        # reset the counter
        self.connections_counter[host] = ([], 0)
        return True

    def check_incompatible_user_agent(self, profileid, twid, flow):
        """
        Compare the user agent of this profile to the MAC vendor
        and check incompatibility
        """
        vendor: Union[str, None] = self.db.get_mac_vendor_from_profile(
            profileid
        )
        if not vendor:
            return False
        vendor = vendor.lower()

        user_agent: dict = self.db.get_user_agent_from_profile(profileid)
        if not user_agent or not isinstance(user_agent, dict):
            return False

        os_type = user_agent.get("os_type", "").lower()
        os_name = user_agent.get("os_name", "").lower()
        browser = user_agent.get("browser", "").lower()
        # user_agent = user_agent.get('user_agent', '')
        if "safari" in browser and "apple" not in vendor:
            self.set_evidence.incompatible_user_agent(
                twid, flow, user_agent, vendor
            )
            return True

        # make sure all of them are lowercase
        # no user agent should contain 2 keywords from different tuples
        os_keywords = [
            ("macos", "ios", "apple", "os x", "mac", "macintosh", "darwin"),
            ("microsoft", "windows", "nt"),
            ("android", "google"),
        ]

        # check which tuple does the vendor belong to
        found_vendor_tuple = False
        for tuple_ in os_keywords:
            for keyword in tuple_:
                if keyword in vendor:
                    # this means this computer belongs to this org
                    # create a copy of the os_keywords list
                    # without the correct org
                    # FOR EXAMPLE if the mac vendor is apple,
                    # the os_keyword should be
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
                if keyword in f"{os_name} {os_type}":
                    # from the same example,
                    # this means that one of these keywords
                    # [('microsoft', 'windows', 'NT'), ('android'), ('linux')]
                    # is found in the UA that belongs to an apple device
                    self.set_evidence.incompatible_user_agent(
                        twid, flow, user_agent, vendor
                    )
                    return True

    def get_ua_info_online(self, user_agent):
        """
        Get OS and browser info about a use agent from an online database
         http://useragentstring.com
        """
        url = "http://useragentstring.com/"
        params = {"uas": user_agent, "getJSON": "all"}
        params = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
        try:
            response = requests.get(url, params=params, timeout=5)
            if response.status_code != 200 or not response.text:
                raise requests.exceptions.ConnectionError
        except (
            requests.exceptions.ConnectionError,
            requests.exceptions.ReadTimeout,
        ):
            return False

        # returns the following
        # {"agent_type":"Browser","agent_name":"Internet Explorer",
        # "agent_version":"8.0", "os_type":"Windows","os_name":"Windows 7",
        # "os_versionName":"","os_versionNumber":"",
        # "os_producer":"","os_producerURL":"","linux_distibution"
        # :"Null","agent_language":"","agent_languageTag":""}
        try:
            # responses from this domain are broken for now. so this
            # is a temp fix until they fix it from their side
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

        # don't make a request again if we already have a
        # user agent associated with this profile
        if self.db.get_user_agent_from_profile(profileid) is not None:
            # this profile already has a user agent
            return False

        UA_info = {"user_agent": user_agent, "os_type": "", "os_name": ""}

        if ua_info := self.get_ua_info_online(user_agent):
            # the above website returns unknown if it has
            # no info about this UA, remove the 'unknown' from the string
            # before storing in the db
            os_type = (
                ua_info.get("os_type", "")
                .replace("unknown", "")
                .replace("  ", "")
            )
            os_name = (
                ua_info.get("os_name", "")
                .replace("unknown", "")
                .replace("  ", "")
            )
            browser = (
                ua_info.get("agent_name", "")
                .replace("unknown", "")
                .replace("  ", "")
            )

            UA_info.update(
                {
                    "os_name": os_name,
                    "os_type": os_type,
                    "browser": browser,
                }
            )

        self.db.add_user_agent_to_profile(profileid, json.dumps(UA_info))
        return UA_info

    def extract_info_from_ua(self, user_agent, profileid):
        """
        Zeek sometimes collects info about a specific UA,
        in this case the UA starts with 'server-bag'
        """
        if "server-bag" not in user_agent:
            return

        if self.db.get_user_agent_from_profile(profileid) is not None:
            # this profile already has a user agent
            return True

        # for example: server-bag[macOS,11.5.1,20G80,MacBookAir10,1]
        user_agent = (
            user_agent.replace("server-bag", "")
            .replace("]", "")
            .replace("[", "")
        )
        ua_info = {"user_agent": user_agent}
        os_name = user_agent.split(",")[0]
        os_type = os_name + user_agent.split(",")[1]
        ua_info.update(
            {
                "os_name": os_name,
                "os_type": os_type,
                # server bag UAs don't have browser info
                "browser": "",
            }
        )
        ua_info = json.dumps(ua_info)
        self.db.add_user_agent_to_profile(profileid, ua_info)
        return ua_info

    def check_multiple_user_agents_in_a_row(
        self,
        flow,
        twid,
        cached_ua: dict,
    ):
        """
        Detect if the user is using an Apple UA, then android, then linux etc.
        Doesn't check multiple ssh clients
        :param user_agent: UA of the current flow
        :param cached_ua: UA of this profile from the db
        """
        if not cached_ua or not flow.user_agent:
            return False

        os_type = cached_ua["os_type"]
        os_name = cached_ua["os_name"]

        for keyword in (os_type, os_name):
            # loop through each word in UA
            if keyword in flow.user_agent:
                # for example if the os of the cached UA is
                # Linux and the current UA is Mozilla/5.0 (X11;
                # Fedora;Linux x86; rv:60.0) we will find the keyword
                # 'Linux' in both UAs, so we shouldn't alert
                return False

        ua: str = cached_ua.get("user_agent", "")
        self.set_evidence.multiple_user_agents_in_a_row(flow, ua, twid)
        return True

    def check_pastebin_downloads(self, twid, flow):
        try:
            response_body_len = int(flow.response_body_len)
        except ValueError:
            return False

        ip_identification: Dict[str, str] = self.db.get_ip_identification(
            flow.daddr, get_ti_data=False
        )
        ip_identification = utils.get_ip_identification_as_str(
            ip_identification
        )

        if not (
            "pastebin" in ip_identification.lower()
            and response_body_len > self.pastebin_downloads_threshold
            and flow.method == "GET"
        ):
            return False

        self.set_evidence.pastebin_downloads(flow, twid)
        return True

    async def check_weird_http_method(self, msg: Dict[str, str]):
        """
        detect weird http methods in zeek's weird.log
        """
        flow = self.classifier.convert_to_flow_obj(msg["flow"])
        twid = msg["twid"]
        # what's the weird.log about
        if "unknown_HTTP_method" not in flow.name:
            return False

        conn_log_flow: Optional[dict]
        conn_log_flow = utils.get_original_conn_flow(flow, self.db)
        if not conn_log_flow:
            await asyncio.sleep(15)
            conn_log_flow = utils.get_original_conn_flow(flow, self.db)
            if not conn_log_flow:
                return

        self.set_evidence.weird_http_method(twid, flow, conn_log_flow)

    def keep_track_of_http_flow(self, flow, key) -> None:
        """keeps track of the given http flow in http_recognized_flows"""
        # we're using locks here because this is a part of an asyncio
        # function and there's another garbage collector that may be
        # modifying the dict at the same time.
        self.http_recognized_flows_lock.acquire()
        try:
            ts_list = self.http_recognized_flows[key]
            # to store the ts sorted for faster lookups
            bisect.insort(ts_list, float(flow.starttime))
        except KeyError:
            self.http_recognized_flows[key] = [float(flow.starttime)]

        self.http_recognized_flows_lock.release()

    def is_http_proto_recognized_by_zeek(self, flow) -> bool:
        """
        if the conn was an http conn recognized by zeek, the 'service'
        field aka appproto should be 'http'
        """
        return flow.appproto and str(flow.appproto.lower()) == "http"

    def is_tcp_established_port_80_non_empty_flow(self, flow) -> bool:
        state = self.db.get_final_state_from_flags(flow.state, flow.pkts)
        return (
            str(flow.dport) == "80"
            and flow.proto.lower() == "tcp"
            and state == ESTAB
            and (flow.sbytes + flow.dbytes) != 0
        )

    def search_http_recognized_flows_for_ts_range(
        self, flow, start, end
    ) -> List[float]:
        """
        Searches for a flow that matches the given flow in
        self.http_recognized_flows.

        given the start and end time, returns the timestamps within that
        range.

        2 flows match if they share the src and dst IPs
        """

        # Handle the case where the key might not exist
        try:
            sorted_timestamps_of_past_http_flows = self.http_recognized_flows[
                (flow.saddr, flow.daddr)
            ]
        except KeyError:
            return []

        # Find the left and right boundaries
        left_idx = bisect.bisect_left(
            sorted_timestamps_of_past_http_flows, start
        )
        right_idx = bisect.bisect_right(
            sorted_timestamps_of_past_http_flows, end
        )

        return sorted_timestamps_of_past_http_flows[left_idx:right_idx]

    async def check_non_http_port_80_conns(
        self, twid, flow, timeout_reached=False
    ):
        """
        alerts on established connections on port 80 that are not http
        This is how we do the detection.
        for every detected non http flow, we check 5 mins back for
        matching flows that were detected as http by zeek. if found,
        we discard the evidence. if not found, we check for future 5 mins
        of matching zeek flows that were detected as http by zeek.
         if found, we dont set an evidence, if not found, we set an evidence
        :kwarg timeout_reached: did we wait 5 mins in future AND in the
        past for the http of the given flow to arrive?
        """
        if not self.is_tcp_established_port_80_non_empty_flow(flow):
            # we're not interested in that flow
            return False

        # key for looking up matching http flows in http_recognized_flows
        key = (flow.saddr, flow.daddr)

        if self.is_http_proto_recognized_by_zeek(flow):
            # not a fp, thats a recognized http flow
            self.keep_track_of_http_flow(flow, key)
            return False

        flow.starttime = float(flow.starttime)
        # in seconds
        five_mins = 5 * 60

        # timeout reached indicates that we did search in the past once,
        # we need to srch in the future now
        if timeout_reached:
            # look in the future
            matching_http_flows: List[float] = (
                self.search_http_recognized_flows_for_ts_range(
                    flow, flow.starttime, flow.starttime + five_mins
                )
            )
        else:
            # look in the past
            matching_http_flows: List[float] = (
                self.search_http_recognized_flows_for_ts_range(
                    flow, flow.starttime - five_mins, flow.starttime
                )
            )

        if matching_http_flows:
            # awesome! discard evidence. FP dodged.
            return False

        # reaching here means we looked in the past 5 mins and
        # found no timestamps, did we look in the future 5 mins?
        if timeout_reached:
            # yes we did. set an evidence
            self.set_evidence.non_http_port_80_conn(twid, flow)
            return True

        # ts not reached
        # wait 5 mins real-time (to give slips time to
        # read more flows) maybe the recognized http arrives
        # within that time?
        await self.wait_for_new_flows_or_timeout(five_mins)
        # we can safely await here without blocking the main thread because
        # once we run this func with timeout_reached=True, this function will
        # never sleep again, it'll either set the evidence or discard it
        await self.check_non_http_port_80_conns(
            twid, flow, timeout_reached=True
        )
        return False

    async def wait_for_new_flows_or_timeout(self, timeout: float):
        """
        waits for new incoming flows, but interrupts the wait if profiler
        stop sending new flows within the timeout period.
        because that means no more flows are coming during the wait period,
        no need to wait.

        :param timeout: the maximum time to wait before resuming execution.
        """

        # repeatedly check if slips is no longer receiving new flows
        async def will_slips_have_new_incoming_flows():
            """if slips will have no incoming flows, aka profiler stopped.
            this function will return False immediately"""
            while self.db.will_slips_have_new_incoming_flows():
                await asyncio.sleep(1)  # sleep to avoid busy looping
            return False

        try:
            # wait until either:
            # - will_slips_have_new_incoming_flows() returns False (no new flows)
            # - timeout is reached (5 minutes)
            await asyncio.wait_for(
                will_slips_have_new_incoming_flows(), timeout
            )

        except asyncio.TimeoutError:
            pass  # timeout reached

    async def update_flows_status(self):
        """
        notifies waiting tasks that the status of incoming flows has changed.
        should be called whenever new flows are processed.
        """
        async with self.condition:
            self.condition.notify_all()

    def remove_old_entries_from_http_recognized_flows(self) -> None:
        """
        the goal of this is to not have the http_recognized_flows dict
        growing forever, so here we remove all timestamps older than the last
        one-5 mins (zeek time)
        meaning, it ensures that all lists have max 5mins worth of timestamps
        changes the http_recognized_flows to the cleaned one
        """
        # Runs every 5 mins real time, to reduce unnecessary cleanups every
        # 1s
        now = time.time()
        time_since_last_cleanup = utils.get_time_diff(
            self.ts_of_last_cleanup_of_http_recognized_flows,
            now,
            "minutes",
        )

        if time_since_last_cleanup < 5:
            return

        clean_http_recognized_flows = {}
        for ips, timestamps in self.http_recognized_flows.items():
            ips: Tuple[str, str]
            timestamps: List[float]

            end: float = float(timestamps[-1])
            start = end - 5 * 60

            left = bisect.bisect_right(timestamps, start)
            right = bisect.bisect_left(timestamps, end)
            # thats the range we wanna remove from the list bc it's too old
            garbage = timestamps[left:right]
            clean_http_recognized_flows[ips] = [
                ts for ts in timestamps if ts not in garbage
            ]

        self.http_recognized_flows_lock.acquire()
        self.http_recognized_flows = clean_http_recognized_flows
        self.http_recognized_flows_lock.release()
        self.ts_of_last_cleanup_of_http_recognized_flows = now

    async def shutdown_gracefully(self):
        """wait for all the tasks created by self.create_task()"""
        await asyncio.gather(*self.tasks, return_exceptions=True)

    def pre_main(self):
        utils.drop_root_privs()

    async def main(self):
        if msg := self.get_msg("new_http"):
            msg = json.loads(msg["data"])
            profileid = msg["profileid"]
            twid = msg["twid"]
            flow = self.classifier.convert_to_flow_obj(msg["flow"])
            self.check_suspicious_user_agents(profileid, twid, flow)
            self.check_multiple_empty_connections(twid, flow)
            # find the UA of this profileid if we don't have it
            # get the last used ua of this profile
            cached_ua = self.db.get_user_agent_from_profile(profileid)
            if cached_ua:
                self.check_multiple_user_agents_in_a_row(
                    flow,
                    twid,
                    cached_ua,
                )

            if not cached_ua or (
                isinstance(cached_ua, dict)
                and cached_ua.get("user_agent", "") != flow.user_agent
                and "server-bag" not in flow.user_agent
            ):
                # only UAs of type dict are browser UAs,
                # skips str UAs as they are SSH clients
                self.get_user_agent_info(flow.user_agent, profileid)

            self.extract_info_from_ua(flow.user_agent, profileid)
            self.detect_executable_mime_types(twid, flow)
            self.check_incompatible_user_agent(profileid, twid, flow)
            self.check_pastebin_downloads(twid, flow)
            self.set_evidence.http_traffic(twid, flow)

        if msg := self.get_msg("new_weird"):
            msg = json.loads(msg["data"])
            await self.check_weird_http_method(msg)

        if msg := self.get_msg("new_flow"):
            msg = json.loads(msg["data"])
            twid = msg["twid"]
            flow = self.classifier.convert_to_flow_obj(msg["flow"])
            self.create_task(self.check_non_http_port_80_conns, twid, flow)

        self.remove_old_entries_from_http_recognized_flows()
