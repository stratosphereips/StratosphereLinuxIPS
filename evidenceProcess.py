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
                if self.inputqueue.empty():
                    # Do stuff
                    self.outputqueue.put('50|evidence|[Evidence] Processing the Evidence')
                    try:
                        profiles = __database__.getProfiles()
                        for profileid in profiles:
                            ip = profileid.split(self.separator)[1]
                            lasttw = __database__.getLastTWforProfile(profileid)
                            lasttw_id, lasttw_time = lasttw[0]
                            # Is the end time of this TW still current? If the fake now time is out of this TW we do not evaluate it.
                            fake_now = __database__.getFakeNow()
                            # For some weird reason the time from the fake now uses another format!!! not sure why
                            #fake_now = datetime.strptime(fake_now, self.timeformat)
                            try:
                                fake_now = datetime.strptime(fake_now, '%Y-%m-%d %H:%M:%S')
                            except ValueError:
                                # Sometimes there are nanoseconds and some unconverted data remains
                                fake_now = datetime.strptime(fake_now, '%Y-%m-%d %H:%M:%S.%f')
                            lasttw_time = datetime.fromtimestamp(lasttw_time)
                            time_diff = (fake_now - lasttw_time) 
                            width_as_delta = timedelta(seconds=self.width)
                            if time_diff >= width_as_delta:
                                # This TW is already too old. Do not process it
                                self.outputqueue.put('60|evidence|[Evidence] This TW is too old. Discard. Fake Now: {}, Current: {}. Diff: {}'.format(fake_now, lasttw_time, time_diff))
                                continue
                            #self.outputqueue.put('40|evidence|[Evidence] This TW is NOT too old. Use. Fake Now: {}, Current: {}. Diff: {}'.format(fake_now, lasttw_time, time_diff))
                            # Since the analysis of evidence should be done 
                            evidence = __database__.getEvidenceForTW(profileid, lasttw_id)
                            if evidence:
                                evidence = json.loads(evidence)
                                self.outputqueue.put('40|evidence|[Evidence] Evidence for IP: {}. TW: {}. Evidence: {}'.format(ip, lasttw_id, evidence))
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
                                    self.outputqueue.put('50|evidence|[Evidence] \tAcc Threat Level: {}'.format(accumulated_threat_level))
                                self.outputqueue.put('30|evidence|[Evidence] IP: {}. TW: {}. Accumulated Threat Level: {}'.format(ip, lasttw_id, accumulated_threat_level))
                                #self.outputqueue.put('10|evidence|[Evidence] Accumulated evidence: {}, threshold: {}'.format(accumulated_threat_level, self.detected))
                                # This is the part to detect if the accumulated evidence was enough for generating a detection
                                # The detection should be done in attacks per minute. The paramater in the configuration is attacks per minute
                                # So find out how many attacks corresponds to the width we are using
                                # 60 because the width is specified in seconds
                                detection_threshold_in_this_width = self.detection_threshold * self.width / 60
                                if accumulated_threat_level >= detection_threshold_in_this_width:
                                    self.outputqueue.put('10|evidence|[Evidence] DETECTED IP: {}. Accumulated evidence: {}'.format(ip, accumulated_threat_level))
                                    __database__.setBlockingRequest(profileid, lasttw_id)
                                    # We also need to mark the TW as processed, because when the stdin does not receive any more traffic, we just keep thinking
                                    # that the last TW is the last tw....... and the fake time does not advance
                            
                    except Exception as inst:
                        self.outputqueue.put('01|evidence|[Evidence] Error in run() of EvidenceProcess')
                        self.outputqueue.put('01|evidence|[Evidence] {}'.format(type(inst)))
                        self.outputqueue.put('01|evidence|[Evidence] {}'.format(inst))
                        #self.outputqueue.put('01|evidence|[Evidence] After Error Evidence {}'.format(evidence))

                    time.sleep(60)

                else:
                    line = self.queue.get()
                    if 'stop' != line:
                        self.outputqueue.put('01|evidence|[Evidence] Stopping the Evidence Process')
                        return True
        except KeyboardInterrupt:
            self.outputqueue.put('01|evidence|[Evidence] Stopping the Evidence Process')
            return True
        except Exception as inst:
            self.outputqueue.put('01|evidence|[Evidence] Error in the Evidence Process')
            self.outputqueue.put('01|evidence|[Evidence] {}'.format(type(inst)))
            self.outputqueue.put('01|evidence|[Evidence] {}'.format(inst))
            return True
