# Must imports
from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database.database import __database__
from slips_files.common.slips_utils import utils
import sys

# Your imports
import time
import ipaddress
import json
import threading
from multiprocessing import Queue


class PortScanProcess(Module, multiprocessing.Process):
    """
    A class process to find port scans
    This should be converted into a module that wakesup alone when a new alert arrives
    """

    name = 'portscandetector-1'
    description = 'Detect Horizonal, Vertical and ICMP scans'
    authors = ['Sebastian Garcia']

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

        # We need to know that after a detection, if we receive another flow
        # that does not modify the count for the detection, we are not
        # re-detecting again only because the threshold was overcomed last time.
        self.cache_det_thresholds = {}
        # Retrieve malicious/benigh labels
        self.normal_label = __database__.normal_label
        self.malicious_label = __database__.malicious_label
        self.timeout = 0.0000001
        self.separator = '_'
        # The minimum amount of ips to scan horizontal scan
        self.port_scan_minimum_dips = 6
        # The minimum amount of ports to scan in vertical scan
        self.port_scan_minimum_dports = 5
        self.pingscan_minimum_flows = 5
        self.pingscan_minimum_scanned_ips = 3
        # time in seconds to wait before alerting port scan
        self.time_to_wait = 10
        # list of tuples, each tuple is the args to setevidence
        self.pending_vertical_ps_evidence = Queue()
        self.pending_horizontal_ps_evidence = Queue()
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

                    # self.print('Key: {}. Prev dips: {}, Current: {}'.format(cache_key, prev_amount_dips, amount_of_dips))

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
                            # after alerting once, wait 10s to see if more packets/flows are coming
                            self.pending_horizontal_ps_evidence.put(
                                (
                                    timestamp,
                                    pkts_sent,
                                    protocol,
                                    profileid,
                                    twid,
                                    uids,
                                    dport,
                                    amount_of_dips
                                )
                            )


    def wait_for_vertical_scans(self):
        """
        This thread waits for 10s then checks if more vertical scans happened to modify the alert
        """
        # after 5 dips that aren't the same as the first one, we alert the first one
        dips_counter = 1

        while True:
            # this evidence is the one that triggered this thread
            try:
                evidence: dict = self.pending_vertical_ps_evidence.get(timeout=0.5)
            except:
                # nothing in queue
                time.sleep(5)
                continue

            # unpack the old evidence (the one triggered the thread)
            timestamp, \
                pkts_sent, \
                protocol, \
                profileid, \
                twid, \
                uid, \
                amount_of_dports, \
                dstip = evidence

            # wait 10s if a new evidence arrived
            time.sleep(self.time_to_wait)
            combined_evidence = 0

            while True:
                try:
                    new_evidence = self.pending_vertical_ps_evidence.get(timeout=0.5)
                except:
                    # queue is empty
                    break

                # These are the variables of the combined evidence we are generating

                timestamp, \
                    pkts_sent2, \
                    protocol2, \
                    profileid2, \
                    twid, \
                    uid, \
                    amount_of_dports2, \
                    dstip2 = new_evidence

                if (
                        dstip == dstip2
                        and profileid == profileid2
                        and protocol == protocol2
                ):

                    # the last evidence contains the sum of all the dports and pkts sent found so far,
                    # we shouldn't accumulate
                    amount_of_dports = amount_of_dports2
                    pkts_sent = pkts_sent2

                    # set evidence if there's no more evidence to combine
                    if self.pending_vertical_ps_evidence.empty():
                        break
                    # max evidence to combine before calling setevidence is 5
                    # if we don't set a max evidence,
                    # this loop will keep going forever for the same dstip without setting evidence
                    combined_evidence += 1
                    if combined_evidence == 5:
                        break
                else:
                    # this is a separate ip performing a portscan, we shouldn't accumulate its evidence
                    # store it back in the queue until we're done with the current one
                    dips_counter += 1
                    self.pending_vertical_ps_evidence.put(new_evidence)
                    if dips_counter == 5:
                        dips_counter = 0
                        break

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
        # todo we are not detecting second port scans

    def wait_for_horizontal_scans(self):
        """
        This thread waits for 10s then checks if more horizontal scans happened to modify the alert
        """
        # after 5 ports that aren't the same as the first one, we alert the first one
        ports_counter = 1
        while True:
            try:
                # this evidence is the one that triggered this thread
                evidence: dict = self.pending_horizontal_ps_evidence.get(timeout=0.5)
            except:
                # nothing in queue
                time.sleep(5)
                continue

            # unpack the old evidence (the one triggered the thread)
            timestamp, \
                pkts_sent, \
                protocol, \
                profileid, \
                twid, \
                uids, \
                dport, \
                amount_of_dips = evidence
            # wait 10s if a new evidence arrived
            time.sleep(self.time_to_wait)
            combined_evidence = 0

            while True:
                try:
                    new_evidence = self.pending_horizontal_ps_evidence.get(timeout=0.5)
                except:
                    # queue is empty
                    break

                # These are the variables of the evidence that we should combine
                # if they match the variable of the evidence above
                timestamp, \
                    pkts_sent2, \
                    protocol2, \
                    profileid2, \
                    twid, \
                    uids2, \
                    dport2, \
                    amount_of_dips2 = new_evidence
                if (
                        dport == dport2
                        and profileid == profileid2
                        and protocol == protocol2
                ):

                    # the last evidence contains the sum of all the dips and pkts sent found so far,
                    # we shouldn't accumulate
                    amount_of_dips = amount_of_dips2
                    pkts_sent = pkts_sent2
                    uids += uids2
                    # set evidence if there's no more evidence to combine
                    if self.pending_horizontal_ps_evidence.empty():
                        break
                    # max evidence to combine before calling setevidence is 5
                    # if we don't set a max evidence,
                    # this loop will keep going forever for the same dport without setting evidence
                    combined_evidence += 1
                    if combined_evidence == 5:
                        break
                else:
                    # this is a separate ip performing a portscan, we shouldn't accumulate its evidence
                    # store it back in the queue until we're done with the current one
                    ports_counter += 1
                    self.pending_horizontal_ps_evidence.put(new_evidence)
                    # after 5 evidence that are not detecting the same port, we alert the ones we already accumulated,
                    # and start accumulating again
                    if ports_counter == 5:
                        ports_counter = 0
                        break

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
        type_evidence = 'HorizontalPortscan'
        type_detection = 'srcip'
        source_target_tag = 'Recon'
        srcip = profileid.split('_')[-1]
        detection_info = srcip
        threat_level = 'medium'
        category = 'Recon.Scanning'
        cache_key = f'{profileid}:{twid}:dstip:{dport}:{type_evidence}'
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

        __database__.setEvidence(
            type_evidence,
            type_detection,
            detection_info,
            threat_level,
            confidence,
            description,
            timestamp,
            category,
            conn_count=pkts_sent,
            source_target_tag=source_target_tag,
            port=dport,
            proto=protocol,
            profileid=profileid,
            twid=twid,
            uid=uid,
        )
        # Set 'malicious' label in the detected profile
        __database__.set_profile_module_label(
            profileid, type_evidence, self.malicious_label
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
        type_detection = 'srcip'
        type_evidence = 'VerticalPortscan'
        source_target_tag = 'Recon'
        threat_level = 'medium'
        category = 'Recon.Scanning'
        srcip = profileid.split('_')[-1]
        detection_info = srcip
        confidence = self.calculate_confidence(pkts_sent)
        description = (
                        f'new vertical port scan to IP {dstip} from {srcip}. '
                        f'Total {amount_of_dports} dst {protocol} ports were scanned. '
                        f'Tot pkts sent to all ports: {pkts_sent}. '
                        f'Confidence: {confidence}. by Slips'
                    )
        __database__.setEvidence(
            type_evidence,
            type_detection,
            detection_info,
            threat_level,
            confidence,
            description,
            timestamp,
            category,
            conn_count=pkts_sent,
            source_target_tag=source_target_tag,
            proto=protocol,
            profileid=profileid,
            twid=twid,
            uid=uid,
        )
        # Set 'malicious' label in the detected profile
        __database__.set_profile_module_label(
            profileid, type_evidence, self.malicious_label
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
        type_evidence = 'VerticalPortscan'
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
                    cache_key = f'{profileid}:{twid}:dstip:{dstip}:{type_evidence}'
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
                            # after alerting once, wait 10s to see if more packets/flows are coming
                            self.pending_vertical_ps_evidence.put(
                                (
                                    timestamp,
                                    pkts_sent,
                                    protocol,
                                    profileid,
                                    twid,
                                    uid,
                                    amount_of_dports,
                                    dstip
                                )
                            )


    def check_icmp_sweep(self, msg, note, profileid, uid, twid, timestamp):
        """
        Use our own Zeek scripts to detect ICMP scans. 
        Threshold is on the scrips and it is 25 icmp flows
        """

        if 'TimestampScan' in note:
            type_evidence = 'ICMP-Timestamp-Scan'
        elif 'ICMPAddressScan' in note:
            type_evidence = 'ICMP-AddressScan'
        elif 'AddressMaskScan' in note:
            type_evidence = 'ICMP-AddressMaskScan'
        else:
            # unsupported notice type
            return False

        hosts_scanned = int(msg.split('on ')[1].split(' hosts')[0])
        # get the confidence from 0 to 1 based on the number of hosts scanned
        confidence = 1 / (255 - 5) * (hosts_scanned - 255) + 1
        threat_level = 'medium'
        category = 'Recon.Scanning'
        # type_detection is set to dstip even though the srcip is the one performing the scan
        # because setEvidence doesn't alert on the same key twice, so we have to send different keys to be able
        # to generate an alert every 5,10,15,.. scans #todo test this
        type_detection = 'srcip'
        # this is the last dip scanned
        detection_info = profileid.split('_')[1]
        source_target_tag = 'Recon'
        description = msg
        # this one is detected by zeek so we can't track the uids causing it
        __database__.setEvidence(
            type_evidence,
            type_detection,
            detection_info,
            threat_level,
            confidence,
            description,
            timestamp,
            category,
            source_target_tag=source_target_tag,
            conn_count=hosts_scanned,
            profileid=profileid,
            twid=twid,
            uid=uid,
        )

    def check_portscan_type3(self):
        """
        ###
        # PortScan Type 3. Direction OUT
        # Considering all the flows in this TW, for all the Dst IP, get the sum of all the pkts send to each dst port TCP No tEstablished
        totalpkts = int(data[dport]['totalpkt'])
        # If for each port, more than X amount of packets were sent, report an evidence
        if totalpkts > 3:
            # Type of evidence
            type_evidence = 'PortScanType3'
            # Key
            key = 'dport' + ':' + dport + ':' + type_evidence
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
            __database__.setEvidence(profileid, twid, type_evidence, threat_level, confidence)
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

                    cache_key = f'{profileid}:{twid}:dstip:{scanned_ip}:{sport}:{attack}'
                    # how many flows were last seen responsible for this attack to this dstip
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
                            timestamp,
                            pkts_sent,
                            protocol,
                            profileid,
                            twid,
                            icmp_flows_uids,
                            scanned_ip,
                            attack
                        )

            elif amount_of_scanned_ips > 1:
                # this srcip is scanning several IPs (a network maybe)

                cache_key = f'{profileid}:{twid}:scanned_ips:{amount_of_scanned_ips}:{attack}'
                # how many flows were last seen responsible for this attack to this dstip
                prev_scanned_ips = self.cache_det_thresholds.get(cache_key, 0)

                # detect every 2, 4, 8 scanned IPs
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

                    # todo set evidence



    def set_evidence_icmpscan(
            self,
            timestamp,
            pkts_sent,
            protocol,
            profileid,
            twid,
            icmp_flows_uids,
            scanned_ip,
            attack
    ):

        type_detection = 'srcip'
        type_evidence = attack
        source_target_tag = 'Recon'
        threat_level = 'medium'
        category = 'Recon.Scanning'
        srcip = profileid.split('_')[-1]
        detection_info = srcip
        confidence = self.calculate_confidence(pkts_sent)
        description = (
                        f'ICMP scanning {scanned_ip} ICMP scan type: {attack}. '
                        f'Total packets sent: {pkts_sent} over {len(icmp_flows_uids)} flows. '
                        f'Confidence: {confidence}. by Slips'
                    )
        __database__.setEvidence(
            type_evidence,
            type_detection,
            detection_info,
            threat_level,
            confidence,
            description,
            timestamp,
            category,
            conn_count=pkts_sent,
            source_target_tag=source_target_tag,
            proto=protocol,
            profileid=profileid,
            twid=twid,
            uid=icmp_flows_uids,
        )
        # Set 'malicious' label in the detected profile
        __database__.set_profile_module_label(
            profileid, type_evidence, self.malicious_label
        )

    def run(self):
        utils.drop_root_privs()
        self.timer_thread_vertical_ps.start()
        self.timer_thread_horizontal_ps.start()

        while True:
            try:
                # Wait for a message from the channel that a TW was modified
                message = self.c1.get_message(timeout=self.timeout)
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

                message = self.c2.get_message(timeout=self.timeout)
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

            except KeyboardInterrupt:
                self.shutdown_gracefully()
                return True
            except Exception as inst:
                exception_line = sys.exc_info()[2].tb_lineno
                self.print(f'Problem on the run() line {exception_line}', 0, 1)
                self.print(str(type(inst)), 0, 1)
                self.print(str(inst.args), 0, 1)
                self.print(str(inst), 0, 1)
                return True
