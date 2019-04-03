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
        # Get from the database the separator used to separate the IP and the word profile
        self.fieldseparator = __database__.getFieldSeparator()

    def run(self):
        try:
            while True:
                if self.inputqueue.empty():
                    # Do stuff
                    try:
                        # Start of the port scan detection
                        self.outputqueue.put('50|'+self.processname+'|['+self.processname+'] ' + 'Running the detection of portscans in all modified TW')
                        # Get the list of all the modifed TW for all the profiles for PortScan
                        TWforProfile = __database__.getModifiedTWPortScan()
                        for profileTW in TWforProfile:
                            # Get the profileid and twid
                            profileid = profileTW.split(self.fieldseparator)[0] + self.fieldseparator + profileTW.split(self.fieldseparator)[1]
                            twid = profileTW.split(self.fieldseparator)[2]
                            # For each profile
                            #self.outputqueue.put('02|'+self.processname+'|['+self.processname+'] ' + 'Profile: {}'.format(profileid))
                            # For port scan detection, we will measure different things:
                            # 1. Vertical port scan:
                            #  - When 1 srcip contacts (established or not) > 3 ports in the same dstip (any number of packets)
                            # 2. Horizontal port scan:
                            #  - When 1 srcip contacts (established or not) the same port in > 3 different dstip (any number of packets)
                            # Other things to detect may be
                            # 4. If a dstip is port scanned by a src ip
                            # 3. The same srcip connecting to the same dst port in the same ip > 3 packets as not established
                            # 5. Slow port scan. Same as the others but distributed in multiple time windows
                            
                            ###
                            # To detect 2. and 3. togethe we can use the ClientDstPortTCPNotEstablished
                            # Get the ClientDstPortTCPNotEstablished
                            data = __database__.getSrcDstPortTCPNotEstablishedFromProfileTW(profileid, twid, 'Client')
                            for dport in data.keys():
                                totalpkts = int(data[dport]['totalpkt'])
                                # Fixed threshold for now.
                                #self.outputqueue.put('04|'+self.processname+'|['+self.processname+'] ' + 'Checking profile {}, TW {}. Dport {}. Packets {}'.format(profileid, twid, dport, totalpkts))
                                if totalpkts > 3:
                                    if totalpkts >= 10:
                                        confidence = 1
                                    else:
                                        confidence = totalpkts / 10.0
                                    # very stupid port scan
                                    type_detection = 'Too many not established TCP conn to the same port'
                                    threat_level = 50
                                    __database__.setEvidenceForTW(profileid, twid, type_detection, threat_level, confidence)
                                    
                                    self.outputqueue.put('40|'+self.processname+'|['+self.processname+'] ' + 'Too Many Not Estab TCP to same port {} from IP: {}. Amount: {}'.format(dport, profileid.split('_')[1], totalpkts))

                            # Mark the TW as not modified for port scan
                            __database__.markProfileTWAsNotModifiedPortScan(profileid, twid)

                                
                    except Exception as inst:
                        self.outputqueue.put('01|'+self.processname+'|['+self.processname+'] ' + 'Error in run() of '+self.processname)
                        self.outputqueue.put('01|'+self.processname+'|['+self.processname+'] ' + '{}'.format(type(inst)))
                        self.outputqueue.put('01|'+self.processname+'|['+self.processname+'] ' + '{}'.format(inst))

                    time.sleep(60)

                else:
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
