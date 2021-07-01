# Module to load and find the ASN of each IP

# Must imports
from slips.common.abstracts import Module
import multiprocessing
from slips.core.database import __database__
import platform

# Your imports
import time
import maxminddb
import ipaddress

class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'asn'
    description = 'Module to find the ASN of an IP address'
    authors = ['Sebastian Garcia']

    def __init__(self, outputqueue, config):
        multiprocessing.Process.__init__(self)
        # All the printing output should be sent to the outputqueue. The outputqueue is connected to another process called OutputProcess
        self.outputqueue = outputqueue
        # In case you need to read the slips.conf configuration file for your own configurations
        self.config = config
        # Start the DB
        __database__.start(self.config)
        # Set the output queue of our database instance
        __database__.setOutputQueue(self.outputqueue)
        # Open the maminddb offline db
        try:
            self.reader = maxminddb.open_database('modules/asn/GeoLite2-ASN.mmdb')
        except:
            self.print('Error opening the geolite2 db in ./GeoLite2-Country_20190402/GeoLite2-Country.mmdb. Please download it from https://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.tar.gz. Please note it must be the MaxMind DB version.')
        # To which channels do you wnat to subscribe? When a message arrives on the channel the module will wakeup
        self.c1 = __database__.subscribe('new_ip')
        # Set the timeout based on the platform. This is because the pyredis lib does not have officially recognized the timeout=None as it works in only macos and timeout=-1 as it only works in linux
        if platform.system() == 'Darwin':
            # macos
            self.timeout = None
        elif platform.system() == 'Linux':
            # linux
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
        self.outputqueue.put(vd_text + '|' + self.name + '|[' + self.name + '] ' + str(text))

    def run(self):
        # Main loop function
        while True:
            try:
                message = self.c1.get_message(timeout=self.timeout)
                # if timewindows are not updated for a long time (see at logsProcess.py), we will stop slips automatically.The 'stop_process' line is sent from logsProcess.py.
                if message['data'] == 'stop_process':
                    if self.reader:
                        self.reader.close()
                    # confirm that the module is done processing
                    __database__.publish('finished_modules', self.name)
                    return True
                elif message['channel'] == 'new_ip':
                    # Not all the ips!! only the new one coming in the data
                    ip = message['data']
                    # The first message comes with data=1
                    if type(ip) == str:
                        data = __database__.getIPData(ip)
                        ip_addr = ipaddress.ip_address(ip)
                        # Check whether asn data is in the DB, and that the data is not empty
                        if (not data or 'asn' not in data) and not ip_addr.is_multicast:
                            asninfo = self.reader.get(ip)
                            if asninfo:
                                try:
                                    asnorg = asninfo['autonomous_system_organization']
                                    data = {}
                                    data['asn'] = asnorg
                                except KeyError:
                                    data = {}
                                    data['asn'] = 'Unknown'
                            else:
                                data = {}
                                data['asn'] = 'Unknown'
                            __database__.setInfoForIPs(ip, data)

            except KeyboardInterrupt:
                # On KeyboardInterrupt, slips.py sends a stop_process msg to all modules, so continue to receive it
                continue
            except Exception as inst:
                if self.reader:
                    self.reader.close()
                self.print('Problem on run()', 0, 1)
                self.print(str(type(inst)), 0, 1)
                self.print(str(inst.args), 0, 1)
                self.print(str(inst), 0, 1)
                return True
