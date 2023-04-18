import time
import json
import traceback
import ipaddress
import sys
import validators
from slips_files.common.slips_utils import utils

class ProfilingFlowsDatabase(object):
    def __init__(self):
        # The name is used to print in the outputprocess
        self.name = 'DB'
        self.separator = '_'
        self.prefix = ''

    def set_prefix(self, prefix):
        self.prefix = prefix

    def publish(self, channel, data):
        """Publish something"""
        self.r.publish(self.prefix + self.separator + str(channel), data)

    def getIPData(self, ip: str) -> dict:
        """
        Return information about this IP from IPsInfo
        Returns a dictionary or False if there is no IP in the database
        We need to separate these three cases:
        1- IP is in the DB without data. Return empty dict.
        2- IP is in the DB with data. Return dict.
        3- IP is not in the DB. Return False
        """
        if type(ip) in [ipaddress.IPv4Address, ipaddress.IPv6Address]:
            ip = ip
        data = self.rcache.hget('IPsInfo', ip)
        data = json.loads(data) if data else False
        return data

    def setNewIP(self, ip: str):
        """
        1- Stores this new IP in the IPs hash
        2- Publishes in the channels that there is a new IP, and that we want
            data from the Threat Intelligence modules
        Sometimes it can happend that the ip comes as an IP object, but when
        accessed as str, it is automatically
        converted to str
        """
        data = self.getIPData(ip)
        if data is False:
            # If there is no data about this IP
            # Set this IP for the first time in the IPsInfo
            # Its VERY important that the data of the first time we see an IP
            # must be '{}', an empty dictionary! if not the logic breaks.
            # We use the empty dictionary to find if an IP exists or not
            self.rcache.hset('IPsInfo', ip, '{}')
            # Publish that there is a new IP ready in the channel
            self.publish('new_ip', ip)

    def init_ti_queue(self):
        """used when the TI module starts to initialize the queue size """
        self.r.set('threat_intelligence_q_size', 0)

    def mark_as_analyzed_by_ti_module(self):
        """
        everytime an ip/domain is analyzed by the ti module, this function will decrease the
        ti queue by 1
        """
        self.r.incrby('threat_intelligence_q_size', -1)

    def get_ti_queue_size(self):
        return self.r.get('threat_intelligence_q_size')

    def give_threat_intelligence(
            self, profileid, twid, ip_state, starttime, uid, daddr, proto=False, lookup='', extra_info:dict =False
    ):
        data_to_send = {
                'to_lookup': str(lookup),
                'profileid': str(profileid),
                'twid': str(twid),
                'proto': str(proto),
                'ip_state': ip_state,
                'stime': starttime,
                'uid': uid,
                'daddr': daddr
        }
        if extra_info:
            # sometimes we want to send teh dns query/answer to check it for blacklisted ips/domains
            data_to_send.update(extra_info)

        self.publish(
            'give_threat_intelligence', json.dumps(data_to_send)
        )
        # this is a trick to know how many ips/domains that slips needs to analyze before stopping
        self.r.incr("threat_intelligence_q_size")

        return data_to_send

    def ask_for_ip_info(self, ip, profileid, twid, proto, starttime, uid, ip_state, daddr=False):
        """
        is the ip param src or dst
        """
        # if the daddr key arg is not given, we know for sure that the ip given is the daddr
        daddr = daddr or ip
        data_to_send = self.give_threat_intelligence(
            profileid,
            twid,
            ip_state,
            starttime,
            uid,
            daddr,
            proto=proto,
            lookup=ip
        )

        if ip in self.our_ips:
            # dont ask p2p about your own ip
            return

        # ask other peers their opinion about this IP
        cache_age = 1000
         # the p2p module is expecting these 2 keys
        data_to_send.update({
            'cache_age': cache_age,
            'ip': str(ip)
        })
        self.publish('p2p_data_request', json.dumps(data_to_send))

    def update_times_contacted(self, ip, direction, profileid, twid):
        """
        :param ip: the ip that we want to update the times we contacted
        """

        # Get the hash of the timewindow
        profileid_twid = f'{profileid}{self.separator}{twid}'

        # Get the DstIPs data for this tw in this profile
        # The format is {'1.1.1.1' :  3}
        ips_contacted = self.r.hget(self.prefix + self.separator + profileid_twid, f'{direction}IPs')
        if not ips_contacted:
            ips_contacted = {}

        try:
            ips_contacted = json.loads(ips_contacted)
            # Add 1 because we found this ip again
            ips_contacted[ip] += 1
        except (TypeError, KeyError):
            # There was no previous data stored in the DB
            ips_contacted[ip] = 1

        ips_contacted = json.dumps(ips_contacted)
        self.r.hset(self.prefix + self.separator + profileid_twid, f'{direction}IPs', str(ips_contacted))

    def getFinalStateFromFlags(self, state, pkts):
        """
        Analyze the flags given and return a summary of the state. Should work with Argus and Bro flags
        We receive the pakets to distinguish some Reset connections
        """
        try:
            # self.outputqueue.put('06|database|[DB]: State received {}'.format(state))
            pre = state.split('_')[0]
            try:
                # Try suricata states
                """
                There are different states in which a flow can be.
                Suricata distinguishes three flow-states for TCP and two for UDP. For TCP,
                these are: New, Established and Closed,for UDP only new and established.
                For each of these states Suricata can employ different timeouts.
                """
                if 'new' in state or 'established' in state:
                    return 'Established'
                elif 'closed' in state:
                    return 'Not Established'
                # We have varius type of states depending on the type of flow.
                # For Zeek
                if (
                    'S0' in state
                    or 'REJ' in state
                    or 'RSTOS0' in state
                    or 'RSTRH' in state
                    or 'SH' in state
                    or 'SHR' in state
                ):
                    return 'Not Established'
                elif (
                    'S1' in state
                    or 'SF' in state
                    or 'S2' in state
                    or 'S3' in state
                    or 'RSTO' in state
                    or 'RSTP' in state
                    or 'OTH' in state
                ):
                    return 'Established'
                # For Argus
                suf = state.split('_')[1]
                if 'S' in pre and 'A' in pre and 'S' in suf and 'A' in suf:
                    """
                    Examples:
                    SA_SA
                    SR_SA
                    FSRA_SA
                    SPA_SPA
                    SRA_SPA
                    FSA_FSA
                    FSA_FSPA
                    SAEC_SPA
                    SRPA_SPA
                    FSPA_SPA
                    FSRPA_SPA
                    FSPA_FSPA
                    FSRA_FSPA
                    SRAEC_SPA
                    FSPA_FSRPA
                    FSAEC_FSPA
                    FSRPA_FSPA
                    SRPAEC_SPA
                    FSPAEC_FSPA
                    SRPAEC_FSRPA
                    """
                    return 'Established'
                elif 'PA' in pre and 'PA' in suf:
                    # Tipical flow that was reported in the middle
                    """
                    Examples:
                    PA_PA
                    FPA_FPA
                    """
                    return 'Established'
                elif 'ECO' in pre:
                    return 'ICMP Echo'
                elif 'ECR' in pre:
                    return 'ICMP Reply'
                elif 'URH' in pre:
                    return 'ICMP Host Unreachable'
                elif 'URP' in pre:
                    return 'ICMP Port Unreachable'
                else:
                    """
                    Examples:
                    S_RA
                    S_R
                    A_R
                    S_SA
                    SR_SA
                    FA_FA
                    SR_RA
                    SEC_RA
                    """
                    return 'Not Established'
            except IndexError:
                # suf does not exist, which means that this is some ICMP or no response was sent for UDP or TCP
                if 'ECO' in pre:
                    # ICMP
                    return 'Established'
                elif 'UNK' in pre:
                    # ICMP6 unknown upper layer
                    return 'Established'
                elif 'CON' in pre:
                    # UDP
                    return 'Established'
                elif 'INT' in pre:
                    # UDP trying to connect, NOT preciselly not established but also NOT 'Established'. So we considered not established because there
                    # is no confirmation of what happened.
                    return 'Not Established'
                elif 'EST' in pre:
                    # TCP
                    return 'Established'
                elif 'RST' in pre:
                    # TCP. When -z B is not used in argus, states are single words. Most connections are reseted when finished and therefore are established
                    # It can happen that is reseted being not established, but we can't tell without -z b.
                    # So we use as heuristic the amount of packets. If <=3, then is not established because the OS retries 3 times.
                    return 'Not Established' if int(pkts) <= 3 else 'Established'
                elif 'FIN' in pre:
                    # TCP. When -z B is not used in argus, states are single words. Most connections are finished with FIN when finished and therefore are established
                    # It can happen that is finished being not established, but we can't tell without -z b.
                    # So we use as heuristic the amount of packets. If <=3, then is not established because the OS retries 3 times.
                    return 'Not Established' if int(pkts) <= 3 else 'Established'
                else:
                    """
                    Examples:
                    S_
                    FA_
                    PA_
                    FSA_
                    SEC_
                    SRPA_
                    """
                    return 'Not Established'
            return None
        except Exception:
            exception_line = sys.exc_info()[2].tb_lineno
            self.outputqueue.put(
                f'01|database|[DB] Error in getFinalStateFromFlags() in database.py line {exception_line}'
            )
            self.outputqueue.put(f'01|database|[DB] Inst: {traceback.print_exc()}')

    def getDataFromProfileTW(
        self,
        profileid: str,
        twid: str,
        direction: str,
        state: str,
        protocol: str,
        role: str,
        type_data: str,
    ) -> dict:
        """
        Get the info about a certain role (Client or Server),
        for a particular protocol (TCP, UDP, ICMP, etc.) for a
        particular State (Established, etc.)
        direction: 'Dst' or 'Src'. This is used to know if you
        want the data of the src ip or ports, or the data from
        the dst ips or ports
        state: can be 'Established' or 'NotEstablished'
        protocol: can be 'TCP', 'UDP', 'ICMP' or 'IPV6ICMP'
        role: can be 'Client' or 'Server'
        type_data: can be 'Ports' or 'IPs'
        """
        if not profileid:
            # profileid is None if we're dealing with a profile
            # outside of home_network when this param is given
            return False
        try:
            key = direction + type_data + role + protocol + state
            # self.print('Asked Key: {}'.format(key))
            data = self.r.hget(self.prefix + self.separator + f'{profileid}{self.separator}{twid}', key)
            value = {}
            if data:
                portdata = json.loads(data)
                value = portdata
            else:
                self.print(
                    f'There is no data for Key: {key}. Profile {profileid} TW {twid}',
                    3,
                    0,
                )
            return value
        except Exception:
            exception_line = sys.exc_info()[2].tb_lineno
            self.outputqueue.put(
                f'01|database|[DB] Error in getDataFromProfileTW database.py line {exception_line}'
            )
            self.outputqueue.put(f'01|database|[DB] Inst: {traceback.print_exc()}')

    def add_ips(self, profileid, twid, flow, role):
        """
        Function to add information about an IP address
        The flow can go out of the IP (we are acting as Client) or into the IP
        (we are acting as Server)
        ip_as_obj: IP to add. It can be a dstIP or srcIP depending on the role
        role: 'Client' or 'Server'
        This function does two things:
            1- Add the ip to this tw in this profile, counting how many times
            it was contacted, and storing it in the key 'DstIPs' or 'SrcIPs'
            in the hash of the profile
            2- Use the ip as a key to count how many times that IP was
            contacted on each port. We store it like this because its the
               pefect structure to detect vertical port scans later on
            3- Check if this IP has any detection in the threat intelligence
            module. The information is added by the module directly in the DB.
        """

        uid = flow.uid
        starttime = str(flow.starttime)
        ip = flow.daddr if role=='Client' else flow.saddr

        """
        Depending if the traffic is going out or not, we are Client or Server
        Client role means:
            The profile corresponds to the src ip that received this flow
            The dstip is here the one receiving data from your profile
            So check the dst ip
        Server role means:
            The profile corresponds to the dst ip that received this flow
            The srcip is here the one sending data to your profile
            So check the src ip
        """
        direction = 'Dst' if role == 'Client' else 'Src'

        #############
        # Store the Dst as IP address and notify in the channel
        # We send the obj but when accessed as str, it is automatically
        # converted to str
        self.setNewIP(ip)

        #############

        # OTH means that we didnt see the true src ip and dst ip
        if flow.state != 'OTH':
            self.ask_for_ip_info(flow.saddr,
                                 profileid,
                                 twid,
                                 flow.proto.upper(),
                                 flow.starttime,
                                 flow.uid,
                                 'srcip',
                                 daddr=flow.daddr)
            self.ask_for_ip_info(flow.daddr,
                                 profileid,
                                 twid,
                                 flow.proto.upper(),
                                 flow.starttime,
                                 flow.uid,
                                 'dstip')


        self.update_times_contacted(ip, direction, profileid, twid)

        # Get the state. Established, NotEstablished
        summaryState = self.getFinalStateFromFlags(flow.state, flow.pkts)

        # Get the previous data about this key
        old_profileid_twid_data = self.getDataFromProfileTW(
            profileid,
            twid,
            direction,
            summaryState,
            flow.proto,
            role,
            'IPs',
        )

        profileid_twid_data = self.update_ip_info(
            old_profileid_twid_data,
            flow.pkts,
            flow.dport,
            flow.spkts,
            flow.bytes,
            ip,
            starttime,
            uid
        )


        key_name = (
            f'{direction}IPs{role}{flow.proto.upper()}{summaryState}'
        )
        # Store this data in the profile hash
        self.r.hset(
            self.prefix + self.separator + f'{profileid}{self.separator}{twid}',
            key_name,
            json.dumps(profileid_twid_data)
        )
        return True

    def update_ip_info(
        self,
        old_profileid_twid_data,
        pkts,
        dport,
        spkts,
        totbytes,
        ip,
        starttime,
        uid
    ):
        """
        #  Updates how many times each individual DstPort was contacted,
        the total flows sent by this ip and their uids,
        the total packets sent by this ip,
        total bytes sent by this ip
        """
        dport = str(dport)
        spkts = int(spkts)
        pkts = int(pkts)
        totbytes = int(totbytes)

        try:
            # update info about an existing ip
            ip_data = old_profileid_twid_data[ip]
            ip_data['totalflows'] += 1
            ip_data['totalpkt'] += pkts
            ip_data['totalbytes'] += totbytes
            ip_data['uid'].append(uid)
            if dport in ip_data['dstports']:
                ip_data['dstports'][dport] += spkts
            else:
                ip_data['dstports'][dport] = spkts

        except KeyError:
            # First time seeing this ip
            ip_data = {
                'totalflows': 1,
                'totalpkt': pkts,
                'totalbytes': totbytes,
                'stime': starttime,
                'uid': [uid],
                'dstports': {dport: spkts}

            }

        old_profileid_twid_data[ip] = ip_data
        return old_profileid_twid_data

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
        try:
            self.outputqueue.put(f'{levels}|{self.name}|{text}')
        except AttributeError:
            pass

    def add_tuple(
        self, profileid, twid, tupleid, data_tuple, role, starttime, uid
    ):
        """
        Add the tuple going in or out for this profile
        :param tupleid: daddr:dport:proto
        role: 'Client' or 'Server'
        """
        # If the traffic is going out it is part of our outtuples, if not, part of our intuples
        if role == 'Client':
            direction = 'OutTuples'
        elif role == 'Server':
            direction = 'InTuples'

        try:
            self.print(
                f'Add_tuple called with profileid {profileid}, '
                f'twid {twid}, '
                f'tupleid {tupleid}, '
                f'data {data_tuple}',
                3, 0
            )
            # Get all the InTuples or OutTuples for this profileid in this TW
            profileid_twid = f'{profileid}{self.separator}{twid}'
            tuples = self.r.hget(self.prefix + self.separator + profileid_twid, direction)
            # Separate the symbold to add and the previous data
            (symbol_to_add, previous_two_timestamps) = data_tuple
            if not tuples:
                # Must be str so we can convert later
                tuples = '{}'
            # Convert the json str to a dictionary
            tuples = json.loads(tuples)
            try:
                tuples[tupleid]
                # Disasemble the input
                self.print(
                    f'Not the first time for tuple {tupleid} as an {direction} for '
                    f'{profileid} in TW {twid}. Add the symbol: {symbol_to_add}. '
                    f'Store previous_times: {previous_two_timestamps}. Prev Data: {tuples}',
                    3, 0,
                )
                # Get the last symbols of letters in the DB
                prev_symbols = tuples[tupleid][0]
                # Add it to form the string of letters
                new_symbol = f'{prev_symbols}{symbol_to_add}'
                # analyze behavioral model with lstm model if the length is divided by 3 -
                # so we send when there is 3 more characters added
                if len(new_symbol) % 3 == 0:
                    to_send = {
                        'new_symbol': new_symbol,
                        'profileid': profileid,
                        'twid': twid,
                        'tupleid': str(tupleid),
                        'uid': uid,
                        'stime': starttime,
                    }
                    to_send = json.dumps(to_send)
                    self.publish('new_letters', to_send)

                tuples[tupleid] = (new_symbol, previous_two_timestamps)
                self.print(f'\tLetters so far for tuple {tupleid}: {new_symbol}', 3, 0)
                tuples = json.dumps(tuples)
            except (TypeError, KeyError):
                # TODO check that this condition is triggered correctly
                #  only for the first case and not the rest after...
                # There was no previous data stored in the DB
                self.print(
                    f'First time for tuple {tupleid} as an {direction} for {profileid} in TW {twid}',
                    3, 0,
                )
                # Here get the info from the ipinfo key
                tuples[tupleid] = (symbol_to_add, previous_two_timestamps)
                # Convet the dictionary to json
                tuples = json.dumps(tuples)
            # Store the new data on the db
            self.r.hset(self.prefix + self.separator + profileid_twid, direction, str(tuples))
            # Mark the tw as modified
            self.markProfileTWAsModified(profileid, twid, starttime)

        except Exception:
            exception_line = sys.exc_info()[2].tb_lineno
            self.outputqueue.put(
                f'01|database|[DB] Error in add_tuple in database.py line {exception_line}'
            )
            self.outputqueue.put(f'01|database|[DB] {traceback.format_exc()}')

    def getSlipsInternalTime(self):
        return self.r.get(self.prefix + self.separator + 'slips_internal_time')

    def search_tws_for_flow(self, profileid, twid, uid, go_back=False):
        """
        Search for the given uid in the given twid, or the tws before
        :param go_back: how many hours back to search?
        """
        tws_to_search = float('inf')

        if go_back:
            hrs_to_search = float(go_back)
            tws_to_search = self.get_equivalent_tws(hrs_to_search)

        twid_number: int = int(twid.split('timewindow')[-1])
        while twid_number > -1 and tws_to_search > 0:
            flow = self.get_flow(profileid, f'timewindow{twid_number}', uid)

            uid = next(iter(flow))
            if flow[uid]:
                return flow

            twid_number -= 1
            # this reaches 0 when go_back is set to a number
            tws_to_search -= 1

        # uid isn't in this twid or any of the previous ones
        return {uid: None}

    def get_equivalent_tws(self, hrs: float):
        """
        How many tws correspond to the given hours?
        for example if the tw width is 1h, and hrs is 24, this function returns 24
        """
        return int(hrs*3600/self.width)

    def check_TW_to_close(self, close_all=False):
        """
        Check if we should close some TW
        Search in the modifed tw list and compare when they
        were modified with the slips internal time
        """

        sit = self.getSlipsInternalTime()

        # for each modified profile
        modification_time = float(sit) - self.width
        if close_all:
            # close all tws no matter when they were last modified
            modification_time = float('inf')

        profiles_tws_to_close = self.r.zrangebyscore(
            self.prefix + self.separator + 'ModifiedTW', 0, modification_time, withscores=True
        )

        for profile_tw_to_close in profiles_tws_to_close:
            profile_tw_to_close_id = profile_tw_to_close[0]
            profile_tw_to_close_time = profile_tw_to_close[1]
            self.print(
                f'The profile id {profile_tw_to_close_id} has to be closed because it was'
                f' last modifed on {profile_tw_to_close_time} and we are closing everything older '
                f'than {modification_time}.'
                f' Current time {sit}. '
                f'Difference: {modification_time - profile_tw_to_close_time}',
                3,
                0,
            )
            self.markProfileTWAsClosed(profile_tw_to_close_id)

    def markProfileTWAsClosed(self, profileid_tw):
        """
        Mark the TW as closed so tools can work on its data
        """
        self.r.sadd(self.prefix + self.separator + 'ClosedTW', profileid_tw)
        self.r.zrem(self.prefix + self.separator + 'ModifiedTW', profileid_tw)
        self.publish('tw_closed', profileid_tw)

    def markProfileTWAsModified(self, profileid, twid, timestamp):
        """
        Mark a TW in a profile as modified
        This means:
        1- To add it to the list of ModifiedTW
        2- Add the timestamp received to the time_of_last_modification
           in the TW itself
        3- To update the internal time of slips
        4- To check if we should 'close' some TW
        """
        timestamp = time.time()
        data = {
            f'{profileid}{self.separator}{twid}': float(timestamp)
        }
        self.r.zadd(self.prefix + self.separator + 'ModifiedTW', data)
        self.publish(
            'tw_modified',
            f'{profileid}:{twid}'
            )
        # Check if we should close some TW
        self.check_TW_to_close()

    def add_port(
            self, profileid: str, twid: str, ip_address: str, flow: dict, role: str, port_type: str
    ):
        """
        Store info learned from ports for this flow
        The flow can go out of the IP (we are acting as Client) or into the IP (we are acting as Server)
        role: 'Client' or 'Server'. Client also defines that the flow is going out, Server that is going in
        port_type: 'Dst' or 'Src'.
        Depending if this port was a destination port or a source port
        """
        # Extract variables from columns
        dport = flow.dport
        sport = flow.sport
        totbytes = int(flow.bytes)
        pkts = int(flow.pkts)
        state = flow.state
        proto = flow.proto.upper()
        starttime = str(flow.starttime)
        uid = flow.uid
        ip = str(ip_address)
        spkts = flow.spkts
        state_hist = flow.state_hist if hasattr(flow, 'state_hist') else ''
        # dpkts = columns['dpkts']
        # daddr = columns['daddr']
        # saddr = columns['saddr']
        # sbytes = columns['sbytes']

        if '^' in state_hist:
            # The majority of the FP with horizontal port scan detection happen because a
            # benign computer changes wifi, and many not established conns are redone,
            # which look like a port scan to 10 webpages. To avoid this, we IGNORE all
            # the flows that have in the history of flags (field history in zeek), the ^,
            # that means that the flow was swapped/flipped.
            # The below key_name is only used by the portscan module to check for horizontal
            # portscan, which means we can safely ignore it here and it won't affect the rest
            # of slips
            return False


        # Choose which port to use based if we were asked Dst or Src
        port = str(sport) if port_type == 'Src' else str(dport)

        # If we are the Client, we want to store the dstips only
        # If we are the Server, we want to store the srcips only
        ip_key = 'srcips' if role == 'Server' else 'dstips'

        # Get the state. Established, NotEstablished
        summaryState = self.getFinalStateFromFlags(state, pkts)

        old_profileid_twid_data = self.getDataFromProfileTW(
            profileid,
            twid,
            port_type,
            summaryState,
            proto,
            role,
            'Ports'
        )

        try:
            # we already have info about this dport, update it
            port_data = old_profileid_twid_data[port]
            port_data['totalflows'] += 1
            port_data['totalpkt'] += pkts
            port_data['totalbytes'] += totbytes

            # if there's a conn from this ip on this port, add the pkts
            if ip in port_data[ip_key]:
                port_data[ip_key][ip]['pkts'] += pkts
                port_data[ip_key][ip]['spkts'] += spkts
                port_data[ip_key][ip]['uid'].append(uid)
            else:
                port_data[ip_key][ip] = {
                    'pkts': pkts,
                    'spkts': spkts,
                    'stime': starttime,
                    'uid': [uid]
                }

        except KeyError:
            # First time for this dport
            port_data = {
                'totalflows': 1,
                'totalpkt': pkts,
                'totalbytes': totbytes,
                ip_key: {
                    ip: {
                        'pkts': pkts,
                        'spkts': spkts,
                        'stime': starttime,
                        'uid': [uid]
                    }
                }
            }

        old_profileid_twid_data[port] = port_data
        data = json.dumps(old_profileid_twid_data)
        hash_key = f'{profileid}{self.separator}{twid}'
        key_name = f'{port_type}Ports{role}{proto}{summaryState}'
        self.r.hset(self.prefix + self.separator + hash_key, key_name, str(data))
        self.markProfileTWAsModified(profileid, twid, starttime)

    def add_flow(
        self,
        flow,
        profileid='',
        twid='',
        label='',
    ):
        """
        Function to add a flow by interpreting the data. The flow is added to the correct TW for this profile.
        The profileid is the main profile that this flow is related too.
        : param new_profile_added : is set to True for everytime we see a new srcaddr
        """
        summaryState = self.getFinalStateFromFlags(flow.state, flow.pkts)
        flow_dict = {
            'ts': flow.starttime,
            'dur': flow.dur,
            'saddr': flow.saddr,
            'sport': flow.sport,
            'daddr': flow.daddr,
            'dport': flow.dport,
            'proto': flow.proto,
            'origstate': flow.state,
            'state': summaryState,
            'pkts': flow.pkts,
            'allbytes': flow.bytes,
            'spkts': flow.spkts,
            'sbytes': flow.sbytes,
            'appproto': flow.appproto,
            'smac': flow.smac,
            'dmac': flow.dmac,
            'label': label,
            'flow_type': flow.type_,
            'module_labels': {},
        }

        # Convert to json string
        flow_dict = json.dumps(flow_dict)
        # Store in the hash x.x.x.x_timewindowx_flows
        value = self.r.hset(
            self.prefix + self.separator + f'{profileid}{self.separator}{twid}{self.separator}flows',
            flow.uid,
            flow_dict,
        )
        if not value:
            # duplicate flow
            return False

        # The key was not there before. So this flow is not repeated
        # Store the label in our uniq set, and increment it by 1
        if label:
            self.r.zincrby(self.prefix + self.separator + 'labels', 1, label)

        flow_dict = {flow.uid: flow_dict}

        # Get the dictionary and convert to json string
        flow_dict = json.dumps(flow_dict)
        # Prepare the data to publish.
        to_send = {
            'profileid': profileid,
            'twid': twid,
            'flow': flow_dict,
            'stime': flow.starttime,
        }
        to_send = json.dumps(to_send)

        # set the pcap/file stime in the analysis key
        if self.first_flow:
            self.set_input_metadata({'file_start': flow.starttime})
            self.first_flow = False

        self.set_local_network(flow.saddr)

        # dont send arp flows in this channel, they have their own new_arp channel
        if flow.type_ != 'arp':
            self.publish('new_flow', to_send)
        return True
    def set_local_network(self, saddr):
        # set the local network used in the db
        if self.is_localnet_set:
            return

        if saddr in ('0.0.0.0', '255.255.255.255'):
            return

        if not (
                validators.ipv4(saddr)
                and ipaddress.ip_address(saddr).is_private
        ):
            return
        # get the local network of this saddr
        if network_range := utils.get_cidr_of_ip(saddr):
            self.r.set(self.prefix + self.separator + "local_network", network_range)
            self.is_localnet_set = True
    def get_local_network(self):
         return self.r.get(self.prefix + self.separator + "local_network")

    def get_label_count(self, label):
        """
        :param label: malicious or normal
        """
        return self.r.zscore(self.prefix + self.separator + 'labels', label)

    def get_disabled_modules(self) -> list:
        return json.loads(self.r.hget(self.prefix + self.separator + 'analysis', 'disabled_modules'))

    def set_input_metadata(self, info:dict):
        """
        sets name, size, analysis dates, and zeek_dir in the db
        """
        for info, val in info.items():
            self.r.hset(self.prefix + self.separator + 'analysis', info, val)

    def get_zeek_output_dir(self):
        """
        gets zeek output dir from the db
        """
        return self.r.hget(self.prefix + self.separator + 'analysis', 'zeek_dir')


    def get_total_flows(self):
        """
        gets total flows to process from the db
        """
        return self.r.hget(self.prefix + self.separator + 'analysis', 'total_flows')

    def get_input_type(self):
        """
        gets input type from the db
        """
        return self.r.hget(self.prefix + self.separator + 'analysis', 'input_type')

    def get_output_dir(self, info:dict):
        """
        returns the currently used output dir
        """
        return self.r.hget(self.prefix + self.separator + 'analysis', 'output_dir')


    def get_flow(self, profileid, twid, uid):
        """
        Returns the flow in the specific time
        The format is a dictionary
        """
        if not profileid:
            # profileid is None if we're dealing with a profile
            # outside of home_network when this param is given
            return {}
        temp = self.r.hget(
            self.prefix + self.separator +  f'{profileid}{self.separator}{twid}{self.separator}flows', uid
        )
        return {uid: temp}

    def add_out_ssl(
        self,
        profileid,
        twid,
        flow
    ):
        """
        Store in the DB an ssl request
        All the type of flows that are not netflows are stored in a separate hash ordered by uid.
        The idea is that from the uid of a netflow, you can access which other type of info is related to that uid
        """
        ssl_flow = {
            'uid': flow.uid,
            'type': flow.type_,
            'version': flow.version,
            'cipher': flow.cipher,
            'resumed': flow.resumed,
            'established': flow.established,
            'cert_chain_fuids': flow.cert_chain_fuids,
            'client_cert_chain_fuids': flow.client_cert_chain_fuids,
            'subject': flow.subject,
            'issuer': flow.issuer,
            'validation_status': flow.validation_status,
            'curve': flow.curve,
            'server_name': flow.server_name,
            'daddr': flow.daddr,
            'dport': flow.dport,
            'stime': flow.starttime,
            'ja3': flow.ja3,
            'ja3s': flow.ja3s,
            'is_DoH': flow.is_DoH,
        }
        # TODO do something with is_doh
        # Convert to json string
        ssl_flow = json.dumps(ssl_flow)
        self.r.hset(
            self.prefix + self.separator +  f'{profileid}{self.separator}{twid}{self.separator}altflows',
            flow.uid,
            ssl_flow,
        )
        to_send = {
            'profileid': profileid,
            'twid': twid,
            'flow': ssl_flow,
            'stime': flow.starttime,
        }
        to_send = json.dumps(to_send)
        self.publish('new_ssl', to_send)
        self.print(f'Adding SSL flow to DB: {ssl_flow}', 3, 0)
        # Check if the server_name (SNI) is detected by the threat intelligence.
        # Empty field in the end, cause we have extrafield for the IP.
        # If server_name is not empty, set in the IPsInfo and send to TI
        if not flow.server_name:
            return False

        # We are giving only new server_name to the threat_intelligence module.
        self.give_threat_intelligence(profileid, twid, 'dstip', flow.starttime,
                                      flow.uid, flow.daddr, lookup=flow.server_name)

        # Save new server name in the IPInfo. There might be several server_name per IP.
        if ipdata := self.getIPData(flow.daddr):
            sni_ipdata = ipdata.get('SNI', [])
        else:
            sni_ipdata = []

        SNI_port = {
            'server_name': flow.server_name,
            'dport': flow.dport
        }
        # We do not want any duplicates.
        if SNI_port not in sni_ipdata:
            # Verify that the SNI is equal to any of the domains in the DNS resolution
            # only add this SNI to our db if it has a DNS resolution
            if dns_resolutions := self.r.hgetall(self.prefix + self.separator +  'DNSresolution'):
                # dns_resolutions is a dict with {ip:{'ts'..,'domains':..., 'uid':..}}
                for ip, resolution in dns_resolutions.items():
                    resolution = json.loads(resolution)
                    if SNI_port['server_name'] in resolution['domains']:
                        # add SNI to our db as it has a DNS resolution
                        sni_ipdata.append(SNI_port)
                        self.setInfoForIPs(
                            flow.daddr, {'SNI': sni_ipdata}
                        )
                        break

    def setInfoForIPs(self, ip: str, ipdata: dict):
        """
        Store information for this IP
        We receive a dictionary, such as {'geocountry': 'rumania'} that we are
        going to store for this IP.
        If it was not there before we store it. If it was there before, we
        overwrite it
        """
        # Get the previous info already stored
        data = self.getIPData(ip)
        if data is False:
            # This IP is not in the dictionary, add it first:
            self.setNewIP(ip)
            # Now get the data, which should be empty, but just in case
            data = self.getIPData(ip)

        new_key = False
        for key, val in ipdata.items():
            # If the key is new, we will notify publish notification about that
            if key not in data:
                new_key = True

            data[key] = val

        self.rcache.hset('IPsInfo', ip, json.dumps(data))
        if new_key:
            self.r.publish(self.prefix + self.separator + 'ip_info_change', ip)

    def get_p2p_reports_about_ip(self, ip) -> dict:
        """
        returns a dict of all p2p past reports about the given ip
        """
        #p2p_reports key is basically { ip:  { reporter1: [report1, report2, report3]} }
        if reports := self.rcache.hget('p2p_reports', ip):
            return json.loads(reports)
        return {}

    def store_p2p_report(self, ip: str, report_data: dict):
        """
        stores answers about IPs slips asked other peers for.
        """
        # reports in the db are sorted by reporter bydefault
        reporter = report_data['reporter']
        del report_data['reporter']

        # if we have old reports about this ip, append this one to them
        # cached_p2p_reports is a dict
        if cached_p2p_reports := self.get_p2p_reports_about_ip(ip):
            # was this ip reported by the same peer before?
            if reporter in cached_p2p_reports:
                # ip was reported before, by the same peer
                # did the same peer report the same score and confidence about the same ip twice in a row?
                last_report_about_this_ip = cached_p2p_reports[reporter][-1]
                score = report_data['score']
                confidence = report_data['confidence']
                if (
                        last_report_about_this_ip['score'] == score
                        and last_report_about_this_ip['confidence'] == confidence
                ):
                    report_time = report_data['report_time']
                    # score and confidence are the same as the last report, only update the time
                    last_report_about_this_ip['report_time'] = report_time
                else:
                    # score and confidence are the different from the last report, add report to the list
                    cached_p2p_reports[reporter].append(report_data)
            else:
                # ip was reported before, but not by the same peer
                cached_p2p_reports[reporter] = [report_data]
            report_data = cached_p2p_reports
        else:
            # no old reports about this ip
            report_data = {reporter: [report_data]}

        self.rcache.hset('p2p_reports', ip, json.dumps(report_data))


    def add_out_http(
        self,
        profileid,
        twid,
        flow,
    ):
        """
        Store in the DB a http request
        All the type of flows that are not netflows are stored in a separate hash ordered by uid.
        The idea is that from the uid of a netflow, you can access which other type of info is related to that uid
        """
        http_flow_dict = {
            'uid': flow.uid,
            'type': flow.type_,
            'method': flow.method,
            'host': flow.host,
            'uri': flow.uri,
            'version': flow.version,
            'user_agent': flow.user_agent,
            'request_body_len': flow.request_body_len,
            'response_body_len': flow.response_body_len,
            'status_code': flow.status_code,
            'status_msg': flow.status_msg,
            'resp_mime_types': flow.resp_mime_types,
            'resp_fuids': flow.resp_fuids,
            'stime': flow.starttime,
            'daddr': flow.daddr,
        }
        # Convert to json string
        http_flow_dict = json.dumps(http_flow_dict)

        self.r.hset(
            self.prefix + self.separator + f'{profileid}{ self.separator }{twid}{ self.separator }altflows',
            flow.uid,
            http_flow_dict,
        )

        http_flow = {
            'profileid': profileid,
            'twid': twid,
            'flow': http_flow_dict,
            'stime': flow.starttime,
        }
        to_send = json.dumps(http_flow)
        self.publish('new_http', to_send)
        self.publish('new_url', to_send)

        self.print(f'Adding HTTP flow to DB: {http_flow_dict}', 3, 0)

        http_flow.pop('flow', None)
        http_flow['uid'] = flow.uid

        # Check if the host domain AND the url is detected by the threat intelligence.
        # not all flows have a host value so don't send empty hosts to ti module.
        if len(flow.host) > 2:
            self.give_threat_intelligence(profileid,
                                          twid,
                                          'dst',
                                          flow.starttime,
                                          flow.uid,
                                          flow.daddr,
                                          lookup=flow.host)
            self.give_threat_intelligence(profileid,
                                          twid,
                                          'dst',
                                          flow.starttime,
                                          flow.uid,
                                          flow.daddr,
                                          lookup=f'http://{flow.host}{flow.uri}')
        else:
            # use the daddr since there's no host
            self.give_threat_intelligence(profileid,
                                          twid,
                                          'dstip',
                                          flow.starttime,
                                          flow.uid,
                                          flow.daddr,
                                          lookup=f'http://{flow.daddr}{flow.uri}')


    def add_out_ssh(
        self,
        profileid,
        twid,
        flow,
    ):
        """
        Store in the DB a SSH request
        All the type of flows that are not netflows are stored in a
        separate hash ordered by uid.
        The idea is that from the uid of a netflow, you can access which
        other type of info is related to that uid
        """
        ssh_flow_dict = {
            'uid': flow.uid,
            'type': flow.type_,
            'version': flow.version,
            'auth_attempts': flow.auth_attempts,
            'auth_success': flow.auth_success,
            'client': flow.client,
            'server': flow.server,
            'cipher_alg': flow.cipher_alg,
            'mac_alg': flow.mac_alg,
            'compression_alg': flow.compression_alg,
            'kex_alg': flow.kex_alg,
            'host_key_alg': flow.host_key_alg,
            'host_key': flow.host_key,
            'stime': flow.starttime,
            'daddr': flow.daddr
        }
        # Convert to json string
        ssh_flow_dict = json.dumps(ssh_flow_dict)
        # Set the dns as alternative flow
        self.r.hset(
            self.prefix + self.separator + f'{profileid}{self.separator}{twid}{self.separator}altflows',
            flow.uid,
            ssh_flow_dict,
        )
        # Publish the new dns received
        to_send = {
            'profileid': profileid,
            'twid': twid,
            'flow': ssh_flow_dict,
            'stime': flow.starttime,
            'uid': flow.uid,
        }
        to_send = json.dumps(to_send)
        # publish a dns with its flow
        self.publish('new_ssh', to_send)
        self.print(f'Adding SSH flow to DB: {ssh_flow_dict}', 3, 0)
        # Check if the dns is detected by the threat intelligence. Empty field in the end, cause we have extrafield for the IP.
        self.give_threat_intelligence(profileid, twid, 'dstip', flow.starttime,
                                      flow.uid,
                                      flow.daddr, lookup=flow.daddr)


    def add_out_notice(
        self,
        profileid,
        twid,
        flow,
    ):
        """ " Send notice.log data to new_notice channel to look for self-signed certificates"""
        notice_flow = {
            'type': 'notice',
            'daddr': flow.daddr,
            'sport': flow.sport,
            'dport': flow.dport,
            'note': flow.note,
            'msg': flow.msg,
            'scanned_port': flow.scanned_port,
            'scanning_ip': flow.scanning_ip,
            'stime': flow.starttime,
        }
        notice_flow = json.dumps(
            notice_flow
        )   # this is going to be sent insidethe to_send dict
        to_send = {
            'profileid': profileid,
            'twid': twid,
            'flow': notice_flow,
            'stime': flow.starttime,
            'uid': flow.uid,
        }
        to_send = json.dumps(to_send)
        self.r.hset(
            self.prefix + self.separator + f'{profileid}{self.separator}{twid}{self.separator}altflows',
            flow.uid,
            notice_flow,
        )
        self.publish('new_notice', to_send)
        self.print(f'Adding notice flow to DB: {notice_flow}', 3, 0)
        self.give_threat_intelligence(profileid, twid,
                                      'dstip', flow.starttime,
                                      flow.uid, flow.daddr,
                                      lookup=flow.daddr)

    def get_dns_resolution(self, ip):
        """
        IF this IP was resolved by slips
        returns a dict with {ts: .. ,
                            'domains': .. ,
                            'uid':...,
                            'resolved-by':.. }
        If not resolved, returns {}
        this function is called for every IP in the timeline of kalipso
        """
        if ip_info := self.r.hget(self.prefix + self.separator + 'DNSresolution', ip):
            ip_info = json.loads(ip_info)
            # return a dict with 'ts' 'uid' 'domains' about this IP
            return ip_info
        return {}

    def is_ip_resolved(self, ip, hrs):
        """
        :param hrs: float, how many hours to look back for resolutions
        """
        ip_info = self.get_dns_resolution(ip)
        if ip_info == {}:
            return False

        # these are the tws this ip was resolved in
        tws = ip_info['timewindows']

        # IP is resolved, was it resolved in the past x hrs?
        tws_to_search = self.get_equivalent_tws(hrs)

        current_twid = 0   # number of the tw we're looking for
        while tws_to_search != current_twid:
            matching_tws = [i for i in tws if f'timewindow{current_twid}' in i]

            if not matching_tws:
                current_twid += 1
            else:
                return True

    def set_dns_resolution(
        self,
        query: str,
        answers: list,
        ts: float,
        uid: str,
        qtype_name: str,
        srcip: str,
        twid: str,
    ):
        """
        Cache DNS answers
        1- For each ip in the answer, store the domain
           in DNSresolution as {ip: {ts: .. , 'domains': .. , 'uid':... }}
        2- For each CNAME, store the ip

        :param srcip: ip that performed the dns query
        """
        # don't store queries ending with arpa as dns resolutions, they're reverse dns
        # type A: for ipv4
        # type AAAA: for ipv6
        if (
            qtype_name not in ['AAAA', 'A']
            or answers == '-'
            or query.endswith('arpa')
        ):
            return
        # ATENTION: the IP can be also a domain, since the dns answer can be CNAME.

        # Also store these IPs inside the domain
        ips_to_add = []
        CNAMEs = []
        profileid_twid = f'profile_{srcip}_{twid}'

        for answer in answers:
            # Make sure it's an ip not a CNAME
            if not validators.ipv6(answer) and not validators.ipv4(answer):
                if 'TXT' in answer:
                    continue
                # now this is not an ip, it's a CNAME or a TXT
                # it's a CNAME
                CNAMEs.append(answer)
                continue


            # get stored DNS resolution from our db
            ip_info_from_db = self.get_dns_resolution(answer)
            if ip_info_from_db == {}:
                # if the domain(query) we have isn't already in DNSresolution in the db
                resolved_by = [srcip]
                domains = []
                timewindows = [profileid_twid]
            else:
                # we have info about this domain in DNSresolution in the db
                # keep track of all srcips that resolved this domain
                resolved_by = ip_info_from_db.get('resolved-by', [])
                if srcip not in resolved_by:
                    resolved_by.append(srcip)

                # timewindows in which this odmain was resolved
                timewindows = ip_info_from_db.get('timewindows', [])
                if profileid_twid not in timewindows:
                    timewindows.append(profileid_twid)

                # we'll be appending the current answer to these cached domains
                domains = ip_info_from_db.get('domains', [])

            # if the domain(query) we have isn't already in DNSresolution in the db, add it
            if query not in domains:
                domains.append(query)

            # domains should be a list, not a string!, so don't use json.dumps here
            ip_info = {
                'ts': ts,
                'uid': uid,
                'domains': domains,
                'resolved-by': resolved_by,
                'timewindows': timewindows,
            }
            ip_info = json.dumps(ip_info)
            # we store ALL dns resolutions seen since starting slips
            # store with the IP as the key
            self.r.hset(self.prefix + self.separator + 'DNSresolution', answer, ip_info)
            # store with the domain as the key:
            self.r.hset(self.prefix + self.separator + 'ResolvedDomains', domains[0], answer)
            # these ips will be associated with the query in our db
            ips_to_add.append(answer)

            #  For each CNAME in the answer
            # store it in DomainsInfo in the cache db (used for kalipso)
            # and in CNAMEsInfo in the maion db  (used for detecting dns without resolution)
        if ips_to_add:
            domaindata = {'IPs': ips_to_add}
            # if an ip came in the DNS answer along with the last seen CNAME
            try:
                # store this CNAME in the db
                domaindata['CNAME'] = CNAMEs
            except NameError:
                # no CNAME came with this query
                pass

            self.setInfoForDomains(query, domaindata, mode='add')
            self.set_domain_resolution(query, ips_to_add)

    def set_domain_resolution(self, domain, ips):
        """
        stores all the resolved domains with their ips in the db
        """
        self.r.hset(self.prefix + self.separator + "DomainsResolved", domain, json.dumps(ips))

    def getDomainData(self, domain):
        """
        Return information about this domain
        Returns a dictionary or False if there is no domain in the database
        We need to separate these three cases:
        1- Domain is in the DB without data. Return empty dict.
        2- Domain is in the DB with data. Return dict.
        3- Domain is not in the DB. Return False
        """
        data = self.rcache.hget('DomainsInfo', domain)
        data = json.loads(data) if data or data == {} else False
        return data

    def setNewDomain(self, domain: str):
        """
        1- Stores this new domain in the Domains hash
        2- Publishes in the channels that there is a new domain, and that we want
            data from the Threat Intelligence modules
        """
        data = self.getDomainData(domain)
        if data is False:
            # If there is no data about this domain
            # Set this domain for the first time in the DomainsInfo
            # Its VERY important that the data of the first time we see a domain
            # must be '{}', an empty dictionary! if not the logic breaks.
            # We use the empty dictionary to find if a domain exists or not
            self.rcache.hset('DomainsInfo', domain, '{}')
            # Publish that there is a new domain ready in the channel
            self.publish('new_dns', domain)

    def setInfoForDomains(self, domain: str, info_to_set: dict, mode='leave'):
        """
        Store information for this domain
        :param info_to_set: a dictionary, such as {'geocountry': 'rumania'} that we are
        going to store for this domain
        :param mode: defines how to deal with the new data
        - to 'overwrite' the data with the new data
        - to 'add' the data to the new data
        - to 'leave' the past data untouched
        """

        # Get the previous info already stored
        domain_data = self.getDomainData(domain)
        if not domain_data:
            # This domain is not in the dictionary, add it first:
            self.setNewDomain(domain)
            # Now get the data, which should be empty, but just in case
            domain_data = self.getDomainData(domain)

        # Let's check each key stored for this domain
        for key in iter(info_to_set):
            # info_to_set can be {'VirusTotal': [1,2,3,4], 'Malicious': ""}
            # info_to_set can be {'VirusTotal': [1,2,3,4]}

            # I think we dont need this anymore of the conversion
            if type(domain_data) == str:
                # Convert the str to a dict
                domain_data = json.loads(domain_data)

            # this can be a str or a list
            data_to_store = info_to_set[key]
            # If there is data previously stored, check if we have
            # this key already
            try:
                # Do we have the key alredy?
                _ = domain_data[key]

                # convert incoming data to list
                if type(data_to_store) != list:
                    # data_to_store and prev_info Should both be lists, so we can extend
                    data_to_store = [data_to_store]

                if mode == 'overwrite':
                    domain_data[key] = data_to_store
                elif mode == 'add':
                    prev_info = domain_data[key]

                    if type(prev_info) == list:
                        # for example, list of IPs
                        prev_info.extend(data_to_store)
                        domain_data[key] = list(set(prev_info))
                    elif type(prev_info) == str:
                        # previous info about this domain is a str, we should make it a list and extend
                        prev_info = [prev_info]
                        # add the new data_to_store to our prev_info
                        domain_data[key] = prev_info.extend(data_to_store)
                    elif prev_info is None:
                        # no previous info about this domain
                        domain_data[key] = data_to_store

                elif mode == 'leave':
                    return

            except KeyError:
                # There is no data for the key so far. Add it
                if type(data_to_store) == list:
                    domain_data[key] = list(set(data_to_store))
                else:
                    domain_data[key] = data_to_store
            # Store
            domain_data = json.dumps(domain_data)
            self.rcache.hset('DomainsInfo', domain, domain_data)
            # Publish the changes
            self.r.publish(self.prefix + self.separator + 'dns_info_change', domain)

    def add_out_dns(
        self,
        profileid,
        twid,
        flow
    ):
        """
        Store in the DB a DNS request
        All the type of flows that are not netflows are stored in a separate hash ordered by flow.uid.
        The idea is that from the flow.uid of a netflow, you can access which other type of info is related to that flow.uid
        """
        dns_flow = {
            'flow.uid': flow.uid,
            'type': flow.type_,
            'query': flow.query,
            'qclass_name': flow.qclass_name,
            'flow.qtype_name': flow.qtype_name,
            'rcode_name': flow.rcode_name,
            'answers': flow.answers,
            'ttls': flow.TTLs,
            'stime': flow.starttime,
        }

        # Convert to json string
        dns_flow = json.dumps(dns_flow)
        # Set the dns as alternative flow
        self.r.hset(
            self.prefix + self.separator + f'{profileid}{self.separator}{twid}{self.separator}altflows',
            flow.uid,
            dns_flow,
        )
        # Publish the new dns received
        # TODO we should just send the DNS obj!
        to_send = {
            'profileid': profileid,
            'twid': twid,
            'flow': dns_flow,
            'stime': flow.starttime,
            'uid': flow.uid,
            'rcode_name': flow.rcode_name,
            'daddr': flow.daddr,
            'answers': flow.answers
        }

        to_send = json.dumps(to_send)
        # publish a dns with its flow
        self.publish('new_dns_flow', to_send)
        # Check if the dns query is detected by the threat intelligence.
        self.give_threat_intelligence(
            profileid,
            twid,
            'dstip',
            flow.starttime,
            flow.uid,
            flow.daddr,
            lookup=flow.query
        )


        # Add DNS resolution to the db if there are answers for the query
        if flow.answers and flow.answers !=  ['-'] :
            srcip = profileid.split('_')[1]
            self.set_dns_resolution(
                flow.query, flow.answers, flow.starttime, flow.uid, flow.qtype_name, srcip, twid
            )
            # send each dns answer to TI module
            for answer in flow.answers:
                if 'TXT' in answer:
                    continue

                extra_info = {
                    'is_dns_response': True,
                    'dns_query': flow.query,
                    'domain': answer,
                }
                self.give_threat_intelligence(
                    profileid,
                    twid,
                    'dstip',
                    flow.starttime,
                    flow.uid,
                    flow.daddr,
                    lookup=answer,
                    extra_info=extra_info
                )

