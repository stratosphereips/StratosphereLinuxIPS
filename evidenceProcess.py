import multiprocessing
import time
from slips.core.database import __database__
import json
from datetime import datetime
from datetime import timedelta
import ast
import configparser
import platform

# Evidence Process
class EvidenceProcess(multiprocessing.Process):
    """ 
    A class to process the evidence from the alerts and update the threat level 
    It only work on evidence for IPs that were profiled
    This should be converted into a module 
    """
    def __init__(self, inputqueue, outputqueue, config):
        self.myname = 'Evidence'
        multiprocessing.Process.__init__(self)
        self.inputqueue = inputqueue
        self.outputqueue = outputqueue
        self.config = config
        # Start the DB
        __database__.start(self.config)
        self.separator = __database__.separator
        # Read the configuration
        self.read_configuration()
        # Subscribe to channel 'tw_modified'
        self.c1 = __database__.subscribe('evidence_added')
        # Set the timeout based on the platform. This is because the pyredis lib does not have officially recognized the timeout=None as it works in only macos and timeout=-1 as it only works in linux
        if platform.system() == 'Darwin':
            # macos
            self.timeout = None
        elif platform.system() == 'Linux':
            # now linux also needs to be non-negative
            self.timeout = None
        else:
            #??
            self.timeout = None

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
        self.outputqueue.put(vd_text + '|' + self.myname + '|[' + self.myname + '] ' + str(text))

    def read_configuration(self):
        """ Read the configuration file for what we need """
        # Get the format of the time in the flows
        try:
            self.timeformat = self.config.get('timestamp', 'format')
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.timeformat = '%Y/%m/%d %H:%M:%S.%f'

        # Read the width of the TW
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
        if self.width < 0:
            self.width = 300.0

        # Get the detection threshold
        try:
            self.detection_threshold = float(self.config.get('detection', 'evidence_detection_threshold'))
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified, by default...
            self.detection_threshold = 2
        self.outputqueue.put('10|evidence|Detection Threshold: {} attacks per minute ({} in the current time window width)'.format(self.detection_threshold, self.detection_threshold * self.width / 60 ))

    def add_maliciousIP(self, ip='', profileid='', twid=''):
        '''
        Add malicious IP to DB 'MaliciousIPs' with a profileid and twid where it was met
        Returns nothing
        '''

        ip_location = __database__.get_malicious_ip(ip)
        # if profileid or twid is None, do not put any value in a dictionary
        if profileid != 'None':
            try:
                profile_tws = ip_location[profileid]
                profile_tws = ast.literal_eval(profile_tws)
                profile_tws.add(twid)
                ip_location[profileid] = str(profile_tws)
            except KeyError:
                ip_location[profileid] = str({twid})
        elif not ip_location:
            ip_location = {}
        data = json.dumps(ip_location)
        __database__.add_malicious_ip(ip, data)

    def add_maliciousDomain(self, domain='', profileid='', twid=''):
        '''
        Add malicious domain to DB 'MaliciousDomainss' with a profileid and twid where domain was met
        Returns nothing
        '''
        domain_location = __database__.get_malicious_domain(domain)
        # if profileid or twid is None, do not put any value in a dictionary
        if profileid != 'None':
            try:
                profile_tws = domain_location[profileid]
                profile_tws = ast.literal_eval(profile_tws)
                profile_tws.add(twid)
                domain_location[profileid] = str(profile_tws)
            except KeyError:
                domain_location[profileid] = str({twid})
        elif not domain_location:
            domain_location = {}
        data = json.dumps(domain_location)
        __database__.add_malicious_domain(domain, data)

    def set_TI_IP_detection(self, ip, ip_description, profileid, twid):
        '''
        Funciton to set malicious IPs in IPsInfo and other db keys.
        :ip: detected IP
        :ip_description: source file of detected IP
        :profileid: profile where IP was detected
        :twid: timewindow where IP was detected
        '''

        ip_data = {}
        # Maybe we should change the key to 'status' or something like that.
        ip_data['Malicious'] = ip_description
        self.add_maliciousIP(ip, profileid, twid)
        __database__.setInfoForIPs(ip, ip_data)  # Set in the IP info that IP is blacklisted

    def set_TI_Domain_detection(self, domain, domain_description, profileid, twid):
        '''
        Funciton to set malicious domains in DomainsInfo and other db keys.
        :domain: detected domain
        :domain_description: source file of detected domain
        :profileid: profile where domain was detected
        :twid: timewindow where domain was detected
        '''

        domain_data = {}
        # Maybe we should change the key to 'status' or something like that.
        domain_data['Malicious'] = domain_description
        self.add_maliciousDomain(domain, profileid, twid)
        __database__.setInfoForDomains(domain, domain_data)  # Set in the DomainsInfo info that Domain is blacklisted

    def run(self):
        try:
            # Adapt this process to process evidence from only IPs and not profileid or twid
            while True:
                # Wait for a message from the channel that a TW was modified
                message = self.c1.get_message(timeout=self.timeout)
                # if timewindows are not updated for a long time (see at logsProcess.py), we will stop slips automatically.The 'stop_process' line is sent from logsProcess.py.
                if message['data'] == 'stop_process':
                    return True
                elif message['channel'] == 'evidence_added':
                    # Get the profileid and twid
                    try:
                        profileid = message['data'].split(':')[0]
                        twid = message['data'].split(':')[1]
                    except AttributeError:
                        # When the channel is created the data '1' is sent
                        continue
                    evidence = __database__.getEvidenceForTW(profileid, twid)
                    # Important! It may happen that the evidence is not related to a profileid and twid.
                    # For example when the evidence is on some src IP attacking our home net, and we are not creating
                    # profiles for attackers
                    if evidence:
                        evidence = json.loads(evidence)
                        #self.print(f'Evidence: {evidence}. Profileid {profileid}, twid {twid}')
                        # The accumulated threat level is for all the types of evidence for this profile
                        accumulated_threat_level = 0.0
                        # CONTINUE HERE
                        ip = profileid.split(self.separator)[1]
                        for key in evidence:
                            key_split = key.split(':')
                            detection_type = key_split[0]
                            detection_module = key_split[-1]
                            detection_info = key[len(detection_type)+1:-len(detection_module)-1] # In case of TI, this info is IP, in case of LSTM this is a tuple
                            data = evidence[key]
                            self.print('\tEvidence for key {}'.format(key), 5, 0)
                            confidence = float(data[0])
                            threat_level = float(data[1])
                            description = data[2]
                            # Compute the moving average of evidence
                            new_threat_level = threat_level * confidence
                            self.print('\t\tWeighted Threat Level: {}'.format(new_threat_level), 5, 0)
                            accumulated_threat_level += new_threat_level
                            self.print('\t\tAccumulated Threat Level: {}'.format(accumulated_threat_level), 5, 0)


                        # This is the part to detect if the accumulated evidence was enough for generating a detection
                        # The detection should be done in attacks per minute. The parameter in the configuration is attacks per minute
                        # So find out how many attacks corresponds to the width we are using
                        # 60 because the width is specified in seconds
                        detection_threshold_in_this_width = self.detection_threshold * self.width / 60
                        if accumulated_threat_level >= detection_threshold_in_this_width:
                            # if this profile was not already blocked in this TW
                            if not __database__.checkBlockedProfTW(profileid, twid):
                                # Differentiate the type of evidence for different detections

                                if detection_module == 'ThreatIntelligenceBlacklistIP':
                                    if detection_type == 'dstip':
                                        self.print('\tInfected IP {} connected to blacklisted IP {} due to {}. Accumulated evidence: {}'.format(ip, detection_info, description, accumulated_threat_level), 1, 0)
                                    elif detection_type == 'srcip':
                                        self.print('\tDetected blacklisted IP {} due to {}. Accumulated evidence: {}'.format(detection_info, description, accumulated_threat_level), 1, 0)
                                    self.set_TI_IP_detection(detection_info, description, profileid, twid)

                                elif detection_module == 'ThreatIntelligenceBlacklistDomain':
                                    self.print('\tDETECTED DOMAIN: {} due to {}. Accumulated evidence: {}'.format(detection_info, description,accumulated_threat_level), 1, 0)
                                    self.set_TI_Domain_detection(detection_info, description, profileid, twid)

                                elif detection_module == 'LongConnection':
                                    self.print('\tDETECTED IP {} due to {}. Accumulated evidence: {}'.format(detection_info, description, accumulated_threat_level), 1, 0)
                                else:
                                    self.print('\tDETECTED IP: {} due to {}. Accumulated evidence: {}'.format(ip, description,accumulated_threat_level), 1, 0)

                                __database__.publish('new_blocking', ip)
                                __database__.markProfileTWAsBlocked(profileid, twid)
                            
        except KeyboardInterrupt:
            self.outputqueue.put('01|evidence|[Evidence] Stopping the Evidence Process')
            return True
        except Exception as inst:
            self.outputqueue.put('01|evidence|[Evidence] Error in the Evidence Process')
            self.outputqueue.put('01|evidence|[Evidence] {}'.format(type(inst)))
            self.outputqueue.put('01|evidence|[Evidence] {}'.format(inst))
            return True
