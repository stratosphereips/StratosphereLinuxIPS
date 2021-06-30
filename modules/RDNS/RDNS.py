# Ths is a template module for you to copy and create your own slips module
# Instructions
# 1. Create a new folder on ./modules with the name of your template. Example:
#    mkdir modules/anomaly_detector
# 2. Copy this template file in that folder.
#    cp modules/template/template.py modules/anomaly_detector/anomaly_detector.py
# 3. Make it a module
#    touch modules/template/__init__.py
# 4. Change the name of the module, description and author in the variables
# 5. The file name of the python module (template.py) MUST be the same as the name of the folder (template)
# 6. The variable 'name' MUST have the public name of this module. This is used to ignore the module
# 7. The name of the class MUST be 'Module', do not change it.

# Must imports
from slips.common.abstracts import Module
import multiprocessing
from slips.core.database import __database__
import platform

# Your imports
import socket


class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'RDNS'
    description = 'Module to get and store the reverse DNS info about IPs'
    authors = ['Alya Gomaa']

    def __init__(self, outputqueue, config):
        multiprocessing.Process.__init__(self)
        # All the printing output should be sent to the outputqueue.
        # The outputqueue is connected to another process called OutputProcess
        self.outputqueue = outputqueue
        # In case you need to read the slips.conf configuration file for
        # your own configurations
        self.config = config
        # Start the DB
        __database__.start(self.config)
        # Remember to subscribe to this channel in database.py
        self.c1 = __database__.subscribe('new_ip')
        # Set the timeout based on the platform. This is because the
        # pyredis lib does not have officially recognized the
        # timeout=None as it works in only macos and timeout=-1 as it only works in linux
        if platform.system() == 'Darwin':
            # macos
            self.timeout = None
        elif platform.system() == 'Linux':
            # linux
            self.timeout = None
        else:
            # Other systems
            self.timeout = None

    def print(self, text, verbose=1, debug=0):
        """
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by
        taking all the prcocesses into account

        Input
         verbose: is the minimum verbosity level required for this text to
         be printed
         debug: is the minimum debugging level required for this text to be
         printed
         text: text to print. Can include format like 'Test {}'.format('here')

        If not specified, the minimum verbosity level required is 1, and the
        minimum debugging level is 0
        """

        vd_text = str(int(verbose) * 10 + int(debug))
        self.outputqueue.put(vd_text + '|' + self.name + '|[' + self.name + '] ' + str(text))

    def get_ip_family(self, ip):
        """
        returns the family of the IP, AF_INET or AF_INET6
        :param ip: str
        """
        if ':' in ip:
            return socket.AF_INET6
        return socket.AF_INET

    def run(self):
        # Main loop function
        while True:
            try:
                message = self.c1.get_message(timeout=self.timeout)
                # Check that the message is for you. Probably unnecessary...
                if message['data'] == 'stop_process':
                    # confirm that the module is done processing
                    __database__.publish('finished_modules', self.name)
                    return True
                if (message and message['channel'] == 'new_ip'
                            and message['type'] == "message"
                            and type(message['data']) == str):
                    ip = message['data']
                    data = {}
                    try:
                        # works with both ipv4 and ipv6
                        reverse_dns = socket.gethostbyaddr(ip)[0]
                        # if there's no reverse dns record for this ip, reverse_dns will be an ip.
                        try:
                            # reverse_dns is an ip and there's no reverse dns, don't store
                            socket.inet_pton(self.get_ip_family(reverse_dns), reverse_dns)
                            continue
                        except socket.error:
                            # all good, store it
                            data['reverse_dns'] = reverse_dns
                    except (socket.gaierror, socket.herror, OSError):
                        # not an ip or multicast, can't get the reverse dns record of it
                        continue
                    # Store in the db
                    __database__.setInfoForIPs(ip, data)
            except KeyboardInterrupt:
                # On KeyboardInterrupt, slips.py sends a stop_process msg to all modules, so continue to receive it
                continue
            except Exception as inst:
                self.print('Problem on the run()', 0, 1)
                self.print(str(type(inst)), 0, 1)
                self.print(str(inst.args), 0, 1)
                self.print(str(inst), 0, 1)
                return True
