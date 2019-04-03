import multiprocessing
import time
from slips.core.database import __database__
import json
from datetime import datetime
from datetime import timedelta
import configparser

# Evidence Process
class EvidenceProcess(multiprocessing.Process):
    """ 
    A class process to process the evidence from the alerts and update the threat level 
    This should be converted into a module that wakesup alone when a new alert arrives
    """
    def __init__(self, inputqueue, outputqueue, config):
        multiprocessing.Process.__init__(self)
        self.inputqueue = inputqueue
        self.outputqueue = outputqueue
        self.config = config
        self.separator = __database__.separator
        # Read the configuration
        self.read_configuration()
        # Subscribe to channel 'tw_modified'
        self.c1 = __database__.subscribe('tw_modified')

    def read_configuration(self):
        """ Read the configuration file for what we need """
        # Get the format of the time in the flows
        try:
            self.timeformat = config.get('timestamp', 'format')
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


    def run(self):
        try:
            while True:
                # Wait for a message from the channel that a TW was modified
                message = self.c1.get_message(timeout=None)
                #self.print('Message received from channel {} with data {}'.format(message['channel'], message['data']), 0, 1)
                if message['channel'] == 'tw_modified':
                    # Get the profileid and twid
                    try:
                        profileid = message['data'].split(':')[0]
                        twid = message['data'].split(':')[1]
                    except AttributeError:
                        # When the channel is created the data '1' is sent
                        continue
                    self.outputqueue.put('50|evidence|[Evidence] Processing the Evidence')
                    ip = profileid.split(self.separator)[1]
                    evidence = __database__.getEvidenceForTW(profileid, twid)
                    if evidence:
                        evidence = json.loads(evidence)
                        self.outputqueue.put('40|evidence|[Evidence] Evidence for IP: {}. TW: {}. Evidence: {}'.format(ip, twid, evidence))
                        accumulated_threat_level = 0.0
                        for pieceEvid in evidence:
                            self.outputqueue.put('50|evidence|[Evidence] \tPiece of Evidence: {}'.format(pieceEvid))
                            type_of_alert = pieceEvid[0]
                            threat_level = float(pieceEvid[1])
                            confidence = float(pieceEvid[2])
                            # Compute the moving average of evidence
                            new_threat_level = threat_level * confidence
                            self.outputqueue.put('50|evidence|[Evidence] \tPiece Threat Level: {}'.format(new_threat_level))
                            accumulated_threat_level += new_threat_level
                            self.outputqueue.put('50|evidence|[Evidence] \tAccumulated Threat Level: {}'.format(accumulated_threat_level))
                        self.outputqueue.put('30|evidence|[Evidence] IP: {}. TW: {}. Accumulated Threat Level: {}'.format(ip, twid, accumulated_threat_level))

                        # This is the part to detect if the accumulated evidence was enough for generating a detection
                        # The detection should be done in attacks per minute. The paramater in the configuration is attacks per minute
                        # So find out how many attacks corresponds to the width we are using
                        # 60 because the width is specified in seconds
                        detection_threshold_in_this_width = self.detection_threshold * self.width / 60
                        if accumulated_threat_level >= detection_threshold_in_this_width:
                            self.outputqueue.put('10|evidence|[Evidence] DETECTED IP: {}. Accumulated evidence: {}'.format(ip, accumulated_threat_level))
                            __database__.setBlockingRequest(profileid, twid)
                            
        except KeyboardInterrupt:
            self.outputqueue.put('01|evidence|[Evidence] Stopping the Evidence Process')
            return True
        except Exception as inst:
            self.outputqueue.put('01|evidence|[Evidence] Error in the Evidence Process')
            self.outputqueue.put('01|evidence|[Evidence] {}'.format(type(inst)))
            self.outputqueue.put('01|evidence|[Evidence] {}'.format(inst))
            return True
