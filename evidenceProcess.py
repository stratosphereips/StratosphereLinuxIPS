import multiprocessing
import time
from slips.core.database import __database__
import json

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

    def run(self):
        try:
            while True:
                if self.inputqueue.empty():
                    # Do stuff
                    self.outputqueue.put('30|evidence|[Evidence] Processing the Evidence')
                    try:
                        profiles = __database__.getProfiles()
                        for profileid in profiles:
                            ip = profileid.split(self.separator)[1]
                            lasttw = __database__.getLastTWforProfile(profileid)
                            lasttw_id, lasttw_time = lasttw[0]
                            # Is the end time of this TW still current? If the fake now time is out of this TW we do not evaluate it.
                            # Since the analysis of evidence should be done 
                            evidence = __database__.getEvidenceForTW(profileid, lasttw_id)
                            if evidence:
                                evidence = json.loads(evidence)
                                self.outputqueue.put('20|evidence|[Evidence] IP: {}. TW: {}. Evidence: {}'.format(ip, lasttw_id, evidence))
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
                            
                    except Exception as inst:
                        self.outputqueue.put('01|evidence|[Evidence] Error in run() of EvidenceProcess')
                        self.outputqueue.put('01|evidence|[Evidence] {}'.format(type(inst)))
                        self.outputqueue.put('01|evidence|[Evidence] {}'.format(inst))
                        #self.outputqueue.put('01|evidence|[Evidence] After Error Evidence {}'.format(evidence))

                    time.sleep(2)

                elif not self.inputqueue.empty():
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
