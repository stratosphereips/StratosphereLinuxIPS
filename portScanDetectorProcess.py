import multiprocessing
import time
from slips.core.database import __database__
import json

# Port Scan Detector Process
class PortScanProcess(multiprocessing.Process):
    """ 
    A class process to find port scans
    This should be converted into a module that wakesup alone when a new alert arrives
    """
    def __init__(self, inputqueue, outputqueue, config):
        multiprocessing.Process.__init__(self)
        self.inputqueue = inputqueue
        self.outputqueue = outputqueue
        self.config = config
        self.processname = 'portscan'

    def run(self):
        try:
            while True:
                if self.inputqueue.empty():
                    # Do stuff
                    try:
                        # Start of the port scan detection
                        self.outputqueue.put('50|'+self.processname+'|['+self.processname+'] ' + 'Detecting port scans')
                        # Get all the profiles
                        profiles = __database__.getProfiles()
                        for profileid in profiles:
                            # For each profile
                            self.outputqueue.put('02|'+self.processname+'|['+self.processname+'] ' + 'Profile: {}'.format(profileid))
                            # Get the last tw for this profile
                            lasttw = __database__.getLastTWforProfile(profileid)
                            lasttw_id, lasttw_time = lasttw[0]
                            # For port scan detection, we will measure different things:
                            # Vertical port scan:
                            # - When 1 srcip contacts (established or not) > 3 ports in the same dstip (any number of packets)
                            # Horizontal port scan:
                            # - When 1 srcip contacts (established or not) the same port in > 3 different dstip (any number of packets)
                            # Other things to detect may be
                            # - If a dstip is port scanned by a src ip
                            # - The same srcip connecting to the same dst port in the same ip > 3 packets as not established
                            # - Slow port scan. Same as the others but distributed in multiple time windows
                            # 
                            # Get the dstips statistics for this profile
                            dstips = __database__.getDstIPsfromProfileTW(profileid, lasttw_id)
                            if dstips:
                                # Convert to python data
                                try:
                                    dstips = json.loads(dstips)
                                except TypeError:
                                    # The dstips is empty
                                    pass
                                self.outputqueue.put('03|'+self.processname+'|['+self.processname+'] ' + 'DstIps: {}'.format(dstips))
                                # Search for portscans... 
                                for dstip in dstips:
                                    amount = dstips[dstip]
                                    if amount >= 3:
                                        if amount >= 10:
                                            confidence = 1
                                        else:
                                            confidence = amount / 10.0
                                        # very stupid port scan
                                        type_detection = 'Port Scan from this Profile'
                                        threat_level = 0.5
                                        __database__.setEvidenceForTW(profileid, lasttw_id, type_detection, threat_level, confidence)
                                        self.outputqueue.put('40|'+self.processname+'|['+self.processname+'] ' + 'Port scan detected for IP: {}. Amount: {}'.format(dstip, amount))
                                # We need to do the same but for the srcips comming to this profile
                                
                    except Exception as inst:
                        self.outputqueue.put('01|'+self.processname+'|['+self.processname+'] ' + 'Error in run() of '+self.processname)
                        self.outputqueue.put('01|'+self.processname+'|['+self.processname+'] ' + '{}'.format(type(inst)))
                        self.outputqueue.put('01|'+self.processname+'|['+self.processname+'] ' + '{}'.format(inst))

                    time.sleep(60)

                elif not self.inputqueue.empty():
                    line = self.queue.get()
                    if 'stop' != line:
                        self.outputqueue.put('01|'+self.processname+'|['+self.processname+'] ' + 'Stopping the '+self.processname+ 'process')
                        return True
        except KeyboardInterrupt:
            self.outputqueue.put('01|'+self.processname+'|['+self.processname+'] ' + 'Stopping the '+self.processname+ 'process')
            return True
        except Exception as inst:
            self.outputqueue.put('01|'+self.processname+'|['+self.processname+'] ' + 'Error in '+self.processname)
            self.outputqueue.put('01|'+self.processname+'|['+self.processname+'] ' + '{}'.format(type(inst)))
            self.outputqueue.put('01|'+self.processname+'|['+self.processname+'] ' + '{}'.format(inst))
            return True
