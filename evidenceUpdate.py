import multiprocessing
import time
from slips.core.database import __database__

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

    def run(self):
        try:
            while True:
                if self.inputqueue.empty():
                    # Do stuff
                    self.outputqueue.put('10|evidence|[Evidence] Processing the Evidence')
                    try:
                        profiles = __database__.getProfiles()
                        for profileid in profiles:
                            self.outputqueue.put('10|evidence|[Evidence] Profile: {}'.format(profileid))
                            lasttw = __database__.getLastTWforProfile(profileid)
                            lasttw_id, lasttw_time = lasttw[0]
                            evidence = __database__.getEvidenceForTW(profileid, lasttw_id)
                            self.outputqueue.put('10|evidence|[Evidence] TW: {}. Evidence: {}'.format(lasttw_id, evidence))
                            
                    except Exception as inst:
                        self.outputqueue.put('01|evidence|[Evidence] Error in run() of EvidenceProcess')
                        self.outputqueue.put('01|evidence|[Evidence] {}'.format(type(inst)))
                        self.outputqueue.put('01|evidence|[Evidence] {}'.format(inst))

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
