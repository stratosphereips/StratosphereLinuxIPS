from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database.database import __database__
from slips_files.common.slips_utils import utils
import sys
import traceback
import time
import ipaddress
import json
import threading


class PortScanProcess(Module, multiprocessing.Process):
    """
    A class process to find port scans
    This should be converted into a module that wakesup alone when a new alert arrives
    """

    name = 'Network Discovery'
    description = 'Detect Horizonal, Vertical Port scans, ICMP, and DHCP scans'
    authors = ['Sebastian Garcia', 'Alya Gomaa']

    def __init__(self, outputqueue, redis_port):
        multiprocessing.Process.__init__(self)
        self.outputqueue = outputqueue
        __database__.start(redis_port)
        # Set the output queue of our database instance
        __database__.setOutputQueue(self.outputqueue)
        # Get from the database the separator used to separate the IP and the word profile
        self.fieldseparator = __database__.getFieldSeparator()
        # To which channels do you wnat to subscribe? When a message arrives on the channel the module will wakeup
        self.c1 = __database__.subscribe('tw_modified')
        self.c2 = __database__.subscribe('new_notice')
        self.c3 = __database__.subscribe('new_dhcp')
        # We need to know that after a detection, if we receive another flow
        # that does not modify the count for the detection, we are not
        # re-detecting again only because the threshold was overcomed last time.
        self.cache_det_thresholds = {}
        # Retrieve malicious/benigh labels
        self.normal_label = __database__.normal_label
        self.malicious_label = __database__.malicious_label
        self.separator = '_'
        # The minimum amount of ips to scan horizontal scan
        self.port_scan_minimum_dips = 5
        # The minimum amount of ports to scan in vertical scan
        self.port_scan_minimum_dports = 5
        self.pingscan_minimum_flows = 5
        self.pingscan_minimum_scanned_ips = 5
        # time in seconds to wait before alerting port scan
        self.time_to_wait_before_generating_new_alert = 25
        # list of tuples, each tuple is the args to setevidence
        self.pending_vertical_ps_evidence = {}
        self.pending_horizontal_ps_evidence = {}
        # this flag will be true after the first portscan alert
        self.alerted_once_vertical_ps = False
        self.alerted_once_horizontal_ps = False
        # the threads are responsible for combining all evidence each 10 seconds to
        # avoid many alerts
        self.timer_thread_vertical_ps = threading.Thread(
                                target=self.wait_for_vertical_scans,
                                daemon=True
        )
        self.timer_thread_horizontal_ps = threading.Thread(
                                target=self.wait_for_horizontal_scans,
                                daemon=True
        )
        # when a client is seen requesting this minimum addresses in 1 tw,
        # slips sets dhcp scan evidence
        self.minimum_requested_addrs = 4

    def shutdown_gracefully(self):
        # Confirm that the module is done processing
        __database__.publish('finished_modules', self.name)

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

    def check_horizontal_portscan(self, profileid, twid):

        def get_uids():
            """
            returns all the uids of flows to this port
            """
            uids = []
            for dip in dstips:
                for uid in dstips[dip]['uid']:
                     uids.append(uid)
            return uids

        saddr = profileid.split(self.fieldseparator)[1]
        try:
            saddr_obj = ipaddress.ip_address(saddr)
            if saddr == '255.255.255.255' or saddr_obj.is_multicast:
                # don't report port scans on the broadcast or multicast addresses
                return False
        except ValueError:
            # it's a mac
            pass

        # Get the list of dports that we connected as client using TCP not established
        direction = 'Dst'
        role = 'Client'
        type_data = 'Ports'
        for state in ('Established', 'Not Established'):
            for protocol in ('TCP', 'UDP'):
                dports = __database__.getDataFromProfileTW(
                    profileid, twid, direction, state, protocol, role, type_data
                )

                # For each port, see if the amount is over the threshold
                for dport in dports.keys():
                    # PortScan Type 2. Direction OUT
                    dstips = dports[dport]['dstips']
                    # this is the list of dstips that have dns resolution, we will remove them from the dstips
                    dstips_to_discard = []
                    # Remove dstips that have DNS resolution already
                    for dip in dstips:
                        dns_resolution = __database__.get_dns_resolution(dip)
                        dns_resolution = dns_resolution.get('domains', [])
                        if dns_resolution:
                            dstips_to_discard.append(dip)
                    # remove the resolved dstips from dstips dict
                    for ip in dstips_to_discard:
                        dstips.pop(ip)

                    amount_of_dips = len(dstips)
                    # If we contacted more than 3 dst IPs on this port with not established
                    # connections, we have evidence.

                    cache_key = f'{profileid}:{twid}:dstip:{dport}:HorizontalPortscan'
                    prev_amount_dips = self.cache_det_thresholds.get(cache_key, 0)

                    # self.print('Key: {}. Prev dips: {}, Current: {}'.format(cache_key,
                    # prev_amount_dips, amount_of_dips))

                    # We detect a scan every Threshold. So, if threshold is 3,
                    # we detect when there are 3, 6, 9, 12, etc. dips per port.
                    # The idea is that after X dips we detect a connection. And then
                    # we 'reset' the counter until we see again X more.
                    if (
                        amount_of_dips % self.port_scan_minimum_dips == 0
                        and prev_amount_dips < amount_of_dips
                    ):
                        # Get the total amount of pkts sent to the same port from all IPs
                        pkts_sent = 0
                        for dip in dstips:
                            if 'spkts' not in dstips[dip]:
                                # In argus files there are no src pkts, only pkts.
                                # So it is better to have the total pkts than to have no packets count
                                pkts_sent += dstips[dip]["pkts"]
                            else:
                                pkts_sent += dstips[dip]["spkts"]

                        uids: list = get_uids()
                        timestamp = next(iter(dstips.values()))['stime']

                        self.cache_det_thresholds[cache_key] = amount_of_dips
                        if not self.alerted_once_horizontal_ps:
                            self.alerted_once_horizontal_ps = True
                            self.set_evidence_horizontal_portscan(
                                timestamp,
                                pkts_sent,
                                protocol,
                                profileid,
                                twid,
                                uids,
                                dport,
                                amount_of_dips
                            )
                        else:
                            # we will be combining further alerts to avoid alerting many times every portscan
                            # for all the combined alerts, the following params should be equal
                            key = f'{profileid}-{twid}-{state}-{protocol}-{dport}'

                            evidence_details = (timestamp, pkts_sent, uids, amount_of_dips)
                            try:
                                self.pending_horizontal_ps_evidence[key].append(evidence_details)
                            except KeyError:
                                # first time seeing this key
                                self.pending_horizontal_ps_evidence[key] = [evidence_details]

    def wait_for_vertical_scans(self):
        while True:
            # wait 10s for new evidence to arrive so we can combine them
            time.sleep(self.time_to_wait_before_generating_new_alert)
            # to make sure the network_discovery process isn't adding evidence of another ps while this thread is
            # calling set_evidence
            lock = threading.Lock()
            lock.acquire()
            for key, evidence_list in self.pending_vertical_ps_evidence.items():
                # each key here is  {profileid}-{twid}-{state}-{protocol}-{dport}
                # each value here is a list of evidence that should be combined
                profileid, twid, state, protocol, dstip = key.split('-')
                final_evidence_uids = []
                final_pkts_sent = 0

                # combine all evidence that share the above key
                for evidence in evidence_list:
                    # each evidence is a tuple of (timestamp, pkts_sent, uids, amount_of_dips)
                    # in the final evidence, we'll be using the ts of the last evidence
                    timestamp, pkts_sent, evidence_uids, amount_of_dports = evidence
                    # since we're combining evidence, we want the uids of the final evidence
                    # to be the sum of all the evidence we combined
                    final_evidence_uids += evidence_uids
                    final_pkts_sent += pkts_sent

                self.set_evidence_vertical_portscan(
                    timestamp,
                    final_pkts_sent,
                    protocol,
                    profileid,
                    twid,
                    final_evidence_uids,
                    amount_of_dports,
                    dstip
                )
            # reset the dict sinse we already combiner
            self.pending_vertical_ps_evidence = {}
            lock.release()

    def wait_for_horizontal_scans(self):
        """
        This thread waits for 10s then checks if more horizontal scans happened
         to combine evidence
        """
        while True:
            # wait 10s for new evidence to arrive so we can combine them
            time.sleep(self.time_to_wait_before_generating_new_alert)
            # to make sure the network_discovery process isn't adding evidence of another ps while this thread is
            # calling set_evidence
            lock = threading.Lock()
            lock.acquire()
            for key, evidence_list in self.pending_horizontal_ps_evidence.items():
                # each key here is {profileid}-{twid}-{state}-{protocol}-{dport}
                # each value here is a list of evidence that should be combined
                profileid, twid, state, protocol, dport = key.split('-')
                final_evidence_uids = []
                final_pkts_sent = 0
                # combine all evidence that share the above key
                for evidence in evidence_list:
                    # each evidence is a tuple of (timestamp, pkts_sent, uids, amount_of_dips)
                    # in the final evidence, we'll be using the ts of the last evidence
                    timestamp, pkts_sent, evidence_uids, amount_of_dips = evidence
                    # since we're combining evidence, we want the uids of the final evidence
                    # to be the sum of all the evidence we combined
                    final_evidence_uids += evidence_uids
                    final_pkts_sent += pkts_sent

                self.set_evidence_horizontal_portscan(
                    timestamp,
                    final_pkts_sent,
                    protocol,
                    profileid,
                    twid,
                    final_evidence_uids,
                    dport,
                    amount_of_dips
                )
            # reset the dict sinse we already combiner
            self.pending_horizontal_ps_evidence = {}
            lock.release()


    def set_evidence_horizontal_portscan(
            self,
            timestamp,
            pkts_sent,
            protocol,
            profileid,
            twid,
            uid,
            dport,
            amount_of_dips
    ):
        evidence_type = 'HorizontalPortscan'
        attacker_direction = 'srcip'
        source_target_tag = 'Recon'
        srcip = profileid.split('_')[-1]
        attacker = srcip
        threat_level = 'medium'
        category = 'Recon.Scanning'
        portproto = f'{dport}/{protocol}'
        port_info = __database__.get_port_info(portproto)
        port_info = port_info if port_info else ""
        confidence = self.calculate_confidence(pkts_sent)
        description = (
            f'horizontal port scan to port {port_info} {portproto}. '
            f'From {srcip} to {amount_of_dips} unique dst IPs. '
            f'Tot pkts sent: {pkts_sent}. '
            f'Threat Level: {threat_level}. '
            f'Confidence: {confidence}. by Slips'
        )

        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag, conn_count=pkts_sent,
                                 port=dport, proto=protocol, profileid=profileid, twid=twid, uid=uid)
        # Set 'malicious' label in the detected profile
        __database__.set_profile_module_label(
            profileid, evidence_type, self.malicious_label
        )
        self.print(description, 3, 0)

    def set_evidence_vertical_portscan(
            self,
            timestamp,
            pkts_sent,
            protocol,
            profileid,
            twid,
            uid,
            amount_of_dports,
            dstip
    ):
        attacker_direction = 'srcip'
        evidence_type = 'VerticalPortscan'
        source_target_tag = 'Recon'
        threat_level = 'medium'
        category = 'Recon.Scanning'
        srcip = profileid.split('_')[-1]
        attacker = srcip
        confidence = self.calculate_confidence(pkts_sent)
        description = (
                        f'new vertical port scan to IP {dstip} from {srcip}. '
                        f'Total {amount_of_dports} dst {protocol} ports were scanned. '
                        f'Tot pkts sent to all ports: {pkts_sent}. '
                        f'Confidence: {confidence}. by Slips'
                    )
        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag, conn_count=pkts_sent,
                                 proto=protocol, profileid=profileid, twid=twid, uid=uid)
        # Set 'malicious' label in the detected profile
        __database__.set_profile_module_label(
            profileid, evidence_type, self.malicious_label
        )


    def calculate_confidence(self, pkts_sent):
        if pkts_sent > 10:
            confidence = 1
        elif pkts_sent == 0:
            return 0.3
        else:
            # Between threshold and 10 pkts compute a kind of linear grow
            confidence = pkts_sent / 10.0
        return confidence

    def check_vertical_portscan(self, profileid, twid):
        # Get the list of dstips that we connected as client using TCP not
        # established, and their ports
        direction = 'Dst'
        role = 'Client'
        type_data = 'IPs'
        # self.print('Vertical Portscan check. Amount of dports: {}.
        # Threshold=3'.format(amount_of_dports), 3, 0)
        evidence_type = 'VerticalPortscan'
        for state in ('Not Established', 'Established'):
            for protocol in ('TCP', 'UDP'):
                dstips = __database__.getDataFromProfileTW(
                    profileid, twid, direction, state, protocol, role, type_data
                )
                # For each dstip, see if the amount of ports connections is over the threshold
                for dstip in dstips.keys():
                    ### PortScan Type 1. Direction OUT
                    dstports: dict = dstips[dstip]['dstports']
                    amount_of_dports = len(dstports)
                    cache_key = f'{profileid}:{twid}:dstip:{dstip}:{evidence_type}'
                    prev_amount_dports = self.cache_det_thresholds.get(cache_key, 0)
                    # self.print('Key: {}, Prev dports: {}, Current: {}'.format(cache_key,
                    # prev_amount_dports, amount_of_dports))

                    # We detect a scan every Threshold. So we detect when there
                    # is 6, 9, 12, etc. dports per dip.
                    # The idea is that after X dips we detect a connection.
                    # And then we 'reset' the counter
                    # until we see again X more.
                    if (
                            amount_of_dports % self.port_scan_minimum_dports == 0
                            and prev_amount_dports < amount_of_dports
                    ):
                        # Get the total amount of pkts sent different ports on the same host
                        pkts_sent = sum(dstports[dport] for dport in dstports)
                        uid = dstips[dstip]['uid']
                        timestamp = dstips[dstip]['stime']

                        # Store in our local cache how many dips were there:
                        self.cache_det_thresholds[cache_key] = amount_of_dports
                        if not self.alerted_once_vertical_ps:
                            self.alerted_once_vertical_ps = True
                            self.set_evidence_vertical_portscan(
                                timestamp,
                                pkts_sent,
                                protocol,
                                profileid,
                                twid,
                                uid,
                                amount_of_dports,
                                dstip
                            )
                        else:
                             # we will be combining further alerts to avoid alerting
                             # many times every portscan
                            # for all the combined alerts, the following params should be equal
                            key = f'{profileid}-{twid}-{state}-{protocol}-{dstip}'

                            evidence_details = (timestamp, pkts_sent, uid, amount_of_dports)

                            try:
                                self.pending_vertical_ps_evidence[key].append(evidence_details)
                            except KeyError:
                                # first time seeing this key
                                self.pending_vertical_ps_evidence[key] = [evidence_details]

    def check_icmp_sweep(self, msg, note, profileid, uid, twid, timestamp):
        """
        Use our own Zeek scripts to detect ICMP scans. 
        Threshold is on the scrips and it is 25 icmp flows
        """

        if 'TimestampScan' in note:
            evidence_type = 'ICMP-Timestamp-Scan'
        elif 'ICMPAddressScan' in note:
            evidence_type = 'ICMP-AddressScan'
        elif 'AddressMaskScan' in note:
            evidence_type = 'ICMP-AddressMaskScan'
        else:
            # unsupported notice type
            return False

        hosts_scanned = int(msg.split('on ')[1].split(' hosts')[0])
        # get the confidence from 0 to 1 based on the number of hosts scanned
        confidence = 1 / (255 - 5) * (hosts_scanned - 255) + 1
        threat_level = 'medium'
        category = 'Recon.Scanning'
        # attacker_direction is set to dstip even though the srcip is the one performing the scan
        # because setEvidence doesn't alert on the same key twice, so we have to send different keys to be able
        # to generate an alert every 5,10,15,.. scans #todo test this
        attacker_direction = 'srcip'
        # this is the last dip scanned
        attacker = profileid.split('_')[1]
        source_target_tag = 'Recon'
        description = msg
        # this one is detected by zeek so we can't track the uids causing it
        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag, conn_count=hosts_scanned,
                                 profileid=profileid, twid=twid, uid=uid)

    def check_portscan_type3(self):
        """
        ###
        # PortScan Type 3. Direction OUT
        # Considering all the flows in this TW, for all the Dst IP, get the sum of all the pkts send to each dst port TCP No tEstablished
        totalpkts = int(data[dport]['totalpkt'])
        # If for each port, more than X amount of packets were sent, report an evidence
        if totalpkts > 3:
            # Type of evidence
            evidence_type = 'PortScanType3'
            # Key
            key = 'dport' + ':' + dport + ':' + evidence_type
            # Description
            description = 'Too Many Not Estab TCP to same port {} from IP: {}. Amount: {}'.format(dport, profileid.split('_')[1], totalpkts)
            # Threat level
            threat_level = 50
            # Confidence. By counting how much we are over the threshold.
            if totalpkts >= 10:
                # 10 pkts or more, receive the max confidence
                confidence = 1
            else:
                # Between 3 and 10 pkts compute a kind of linear grow
                confidence = totalpkts / 10.0
            __database__.setEvidence(profileid, twid, evidence_type, threat_level, confidence)
            self.print('Too Many Not Estab TCP to same port {} from IP: {}. Amount: {}'.format(dport, profileid.split('_')[1], totalpkts),6,0)
        """

    def check_icmp_scan(self, profileid, twid):
        # Map the ICMP port scanned to it's attack
        port_map = {
            '0x0008': 'AddressScan',
            '0x0013': 'TimestampScan',
            '0x0014': 'TimestampScan',
            '0x0017': 'AddressMaskScan',
            '0x0018': 'AddressMaskScan',
        }

        direction = 'Src'
        role = 'Client'
        type_data = 'Ports'
        protocol = 'ICMP'
        state = 'Established'
        sports = __database__.getDataFromProfileTW(
                    profileid, twid, direction, state, protocol, role, type_data
                )
        for sport, sport_info in sports.items():
            # get the name of this attack
            attack = port_map.get(sport)
            if not attack:
                return

            # get the IPs attacked
            scanned_ips = sport_info['dstips']
            # are we pinging a single IP or ping scanning several IPs?
            amount_of_scanned_ips = len(scanned_ips)

            if amount_of_scanned_ips == 1:
                # how many icmp flows were found?
                for scanned_ip, scan_info in scanned_ips.items():
                    icmp_flows_uids = scan_info['uid']
                    number_of_flows = len(icmp_flows_uids)
                    # how many flows are responsible for this attack
                    # (from this srcip to this dstip on the same port)
                    cache_key = f'{profileid}:{twid}:dstip:{scanned_ip}:{sport}:{attack}'
                    prev_flows = self.cache_det_thresholds.get(cache_key, 0)

                    # We detect a scan every Threshold. So we detect when there
                    # is 5,10,15 etc. scan to the same dstip on the same port
                    # The idea is that after X dips we detect a connection.
                    # And then we 'reset' the counter
                    # until we see again X more.
                    if (
                            number_of_flows % self.pingscan_minimum_flows == 0
                            and prev_flows < number_of_flows
                    ):
                        self.cache_det_thresholds[cache_key] = number_of_flows
                        pkts_sent = scan_info['spkts']
                        timestamp = scan_info['stime']
                        self.set_evidence_icmpscan(
                            amount_of_scanned_ips,
                            timestamp,
                            pkts_sent,
                            protocol,
                            profileid,
                            twid,
                            icmp_flows_uids,
                            attack,
                            scanned_ip=scanned_ip
                        )

            elif amount_of_scanned_ips > 1:
                # this srcip is scanning several IPs (a network maybe)
                # how many dstips scanned by this srcip on this port?
                cache_key = f'{profileid}:{twid}:{attack}'
                prev_scanned_ips = self.cache_det_thresholds.get(cache_key, 0)
                # detect every 5, 10, 15 scanned IPs
                if (
                        amount_of_scanned_ips % self.pingscan_minimum_scanned_ips == 0
                        and prev_scanned_ips < amount_of_scanned_ips
                ):

                    pkts_sent = 0
                    uids = []
                    for scanned_ip, scan_info in scanned_ips.items():
                        # get the total amount of pkts sent to all scanned IP
                        pkts_sent += scan_info['spkts']
                        # get all flows that were part of this scan
                        uids.extend(scan_info['uid'])
                        timestamp = scan_info['stime']

                    self.set_evidence_icmpscan(
                            amount_of_scanned_ips,
                            timestamp,
                            pkts_sent,
                            protocol,
                            profileid,
                            twid,
                            uids,
                            attack
                        )
                    self.cache_det_thresholds[cache_key] = amount_of_scanned_ips


    def set_evidence_icmpscan(
            self,
            number_of_scanned_ips,
            timestamp,
            pkts_sent,
            protocol,
            profileid,
            twid,
            icmp_flows_uids,
            attack,
            scanned_ip=False
    ):
        confidence = self.calculate_confidence(pkts_sent)
        attacker_direction = 'srcip'
        evidence_type = attack
        source_target_tag = 'Recon'
        threat_level = 'medium'
        category = 'Recon.Scanning'
        srcip = profileid.split('_')[-1]
        attacker = srcip

        if number_of_scanned_ips == 1:
            description = (
                            f'ICMP scanning {scanned_ip} ICMP scan type: {attack}. '
                            f'Total packets sent: {pkts_sent} over {len(icmp_flows_uids)} flows. '
                            f'Confidence: {confidence}. by Slips'
                        )
        else:
            description = (
                f'ICMP scanning {number_of_scanned_ips} different IPs. ICMP scan type: {attack}. '
                f'Total packets sent: {pkts_sent} over {len(icmp_flows_uids)} flows. '
                f'Confidence: {confidence}. by Slips'
            )

        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag, conn_count=pkts_sent,
                                 proto=protocol, profileid=profileid, twid=twid, uid=icmp_flows_uids)
        # Set 'malicious' label in the detected profile
        __database__.set_profile_module_label(
            profileid, evidence_type, self.malicious_label
        )


    def set_evidence_dhcp_scan(
            self,
            timestamp,
            profileid,
            twid,
            uids,
            number_of_requested_addrs
    ):
        evidence_type = 'DHCPScan'
        attacker_direction = 'srcip'
        source_target_tag = 'Recon'
        srcip = profileid.split('_')[-1]
        attacker = srcip
        threat_level = 'medium'
        category = 'Recon.Scanning'
        confidence = 0.8
        description = (
            f'Performing a DHCP scan by requesting {number_of_requested_addrs} different IP addresses. '
            f'Threat Level: {threat_level}. '
            f'Confidence: {confidence}. by Slips'
        )

        __database__.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag,
                                 conn_count=number_of_requested_addrs, profileid=profileid, twid=twid, uid=uids)

        # Set 'malicious' label in the detected profile
        __database__.set_profile_module_label(
            profileid, evidence_type, self.malicious_label
        )

    def check_dhcp_scan(self, flow):
        """
        Detects DHCP scans, when a client requests 4+ different IPs in the same tw
        """

        requested_addr = flow['requested_addr']
        if not requested_addr:
            # we are only interested in DHCPREQUEST flows, where a client is requesting an IP
            return

        uid = flow['uid']
        profileid = flow['profileid']
        twid = flow['twid']
        ts = flow['ts']

        # dhcp_flows format is
        #       { requested_addr: uid,
        #         requested_addr2: uid2... }

        dhcp_flows: dict = __database__.get_dhcp_flows(profileid, twid)

        if dhcp_flows:
            # client was seen requesting an addr before in this tw
            # was it requesting the same addr?
            if requested_addr in dhcp_flows:
                # a client requesting the same addr twice isn't a scan
                return

            # it was requesting a different addr, keep track of it and its uid
            __database__.set_dhcp_flow(profileid, twid, requested_addr, uid)
        else:
            # first time for this client to make a dhcp request in this tw
            __database__.set_dhcp_flow(profileid, twid, requested_addr, uid)
            return


        # TODO if we are not going to use the requested addr, no need to store it
        # TODO just store the uids
        dhcp_flows: dict = __database__.get_dhcp_flows(profileid, twid)

        # we alert every 4,8,12, etc. requested IPs
        number_of_requested_addrs = len(dhcp_flows)
        if number_of_requested_addrs % self.minimum_requested_addrs == 0:

            # get the uids of all the flows where this client was requesting an addr in this tw
            uids = []
            for requested_addr, uid in dhcp_flows.items():
                uids.append(uid)

            self.set_evidence_dhcp_scan(
                ts,
                profileid,
                twid,
                uids,
                number_of_requested_addrs
            )


    def run(self):
        utils.drop_root_privs()
        self.timer_thread_vertical_ps.start()
        self.timer_thread_horizontal_ps.start()

        while True:
            try:
                # Wait for a message from the channel that a TW was modified
                message = __database__.get_message(self.c1)
                # print('Message received from channel {} with data {}'.format(message['channel'], message['data']))
                if message and message['data'] == 'stop_process':
                    self.shutdown_gracefully()
                    return True

                if utils.is_msg_intended_for(message, 'tw_modified'):
                    # Get the profileid and twid
                    profileid = message['data'].split(':')[0]
                    twid = message['data'].split(':')[1]
                    # Start of the port scan detection
                    self.print(
                        f'Running the detection of portscans in profile '
                        f'{profileid} TW {twid}', 3, 0
                    )

                    # For port scan detection, we will measure different things:

                    # 1. Vertical port scan:
                    # (single IP being scanned for multiple ports)
                    # - 1 srcip sends not established flows to > 3 dst ports in the same dst ip. Any number of packets
                    # 2. Horizontal port scan:
                    #  (scan against a group of IPs for a single port)
                    # - 1 srcip sends not established flows to the same dst ports in > 3 dst ip.
                    # 3. Too many connections???:
                    # - 1 srcip sends not established flows to the same dst ports, > 3 pkts, to the same dst ip
                    # 4. Slow port scan. Same as the others but distributed in multiple time windows

                    # Remember that in slips all these port scans can happen for traffic going IN to an IP or going OUT from the IP.

                    self.check_horizontal_portscan(profileid, twid)
                    self.check_vertical_portscan(profileid, twid)
                    self.check_icmp_scan(profileid, twid)

                message = __database__.get_message(self.c2)
                # print('Message received from channel {} with data {}'.format(message['channel'], message['data']))
                if message and message['data'] == 'stop_process':
                    self.shutdown_gracefully()
                    return True

                if utils.is_msg_intended_for(message, 'new_notice'):
                    data = message['data']
                    if type(data) != str:
                        continue
                    # Convert from json to dict
                    data = json.loads(data)
                    profileid = data['profileid']
                    twid = data['twid']
                    # Get flow as a json
                    flow = data['flow']
                    # Convert flow to a dict
                    flow = json.loads(flow)
                    timestamp = flow['stime']
                    uid = data['uid']
                    msg = flow['msg']
                    note = flow['note']
                    self.check_icmp_sweep(
                        msg, note, profileid, uid, twid, timestamp
                    )

                message = __database__.get_message(self.c3)
                if message and message['data'] == 'stop_process':
                    self.shutdown_gracefully()
                    return True

                if utils.is_msg_intended_for(message, 'new_dhcp'):
                    flow = json.loads(message['data'])
                    self.check_dhcp_scan(flow)



            except KeyboardInterrupt:
                self.shutdown_gracefully()
                return True
            except Exception as inst:
                exception_line = sys.exc_info()[2].tb_lineno
                self.print(f'Problem on the run() line {exception_line}', 0, 1)
                self.print(traceback.format_exc(), 0, 1)
                return True
