# Must imports
from slips.common.abstracts import Module
import multiprocessing
from slips.core.database import __database__

# Your imports
import ipwhois
import ipaddress
import json



class WhoisIP(Module, multiprocessing.Process):
    name = 'WhoisIP'
    description = 'Get whois info for each IP unique address'
    authors = ['Dita']

    def __init__(self, outputqueue, config, testing=False):
        if testing:
            self.print = self.testing_print
        else:
            multiprocessing.Process.__init__(self)

        # All the printing output should be sent to the outputqueue, which is connected to OutputProcess
        self.outputqueue = outputqueue
        # In case you need to read the slips.conf configuration file for your own configurations
        self.config = config
        # Start the DB
        __database__.start(self.config)
        # To which channels do you want to subscribe? When a message arrives on the channel the module will wake up
        # The options change, so the last list is on the slips/core/database.py file. However common options are:
        # - new_ip
        # - tw_modified
        # - evidence_added
        self.c1 = __database__.subscribe('new_ip')

        self.db_hashset_ipv4 = "whois-module-ipv4subnet-cache"

    def print(self, text, verbose=1, debug=0):
        """ 
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by taking all the processes into account

        Input
         verbose: is the minimum verbosity level required for this text to be printed
         debug: is the minimum debugging level required for this text to be printed
         text: text to print. Can include format like 'Test {}'.format('here')

        If not specified, the minimum verbosity level required is 1, and the minimum debugging level is 0
        """

        vd_text = str(int(verbose) * 10 + int(debug))
        self.outputqueue.put(vd_text + '|' + self.name + '|[' + self.name + '] ' + str(text))

    def testing_print(self, text, verbose=1, debug=0):
        """
        Printing function that will be used automatically by the module, in case it is run in testing mode
        (without SLIPS and outputprocess). 
        :param text: String to print
        :param verbose: ignored parameter
        :param debug: ignored parameter
        :return: None
        """

        print(text)

    def check_ip(self, ip):
        print("--- Checking ip " + ip)
        try:
            ip_object = ipwhois.IPWhois(ip)
        except Exception as e:
            self.print(e)
            return

        if ip_object.version == 4:
            load_subnet = self.load_ipv4_subnet
            save_subnet = self.save_ipv4_subnet
            Interface = ipaddress.IPv4Interface
        else:
            load_subnet = self.load_ipv6_subnet
            save_subnet = self.save_ipv6_subnet
            Interface = ipaddress.IPv6Interface

        cached_data = load_subnet(ipaddress.ip_address(ip))

        if cached_data is not None:
            self.print("Data found in cache!")
            return cached_data  # TODO

        try:
            message = ip_object.lookup_rdap(depth=1)
        except ipwhois.ASNRegistryError as e:
            self.print(e)
            return

        asn = message["asn"]
        ctr_code = message["asn_country_code"]
        cidr = message["network"]["cidr"]
        name = message["network"]["name"]
        print("ASN:", asn)
        print("Country:", ctr_code)
        print("CIDR:", cidr)
        print("Name:", name)

        if "," in cidr:
            cidrs = cidr.split(", ")
        else:
            cidrs = [cidr]

        for cidr in cidrs:
            mask = int(Interface(cidr).netmask)
            save_subnet(mask, asn, ctr_code, cidr, name)

    def save_ipv4_subnet(self, mask: int, asn: str, ctr_code: str, cidr: str, name: str):
        data = {"asn": asn,
                  "country": ctr_code,
                  "cidr": cidr,
                  "name": name}
        str_data = json.dumps(data)
        __database__.r.hset(self.db_hashset_ipv4, mask, str_data)

    def save_ipv6_subnet(self, mask, asn, ctr_code, cidr, name):
        pass

    def load_ipv4_subnet(self, ip):
        mask = 4294967295
        ip_value = int(ip)
        for i in range(0, 16):
            mask -= pow(2, i)
            masked_ip = mask & ip_value
            data = __database__.r.hget(self.db_hashset_ipv4, masked_ip)
            if data:
                return data
        return None

    def load_ipv6_subnet(self, ip):
        pass

    def run(self):
        try:
            # Main loop function
            while True:
                message = self.c1.get_message(timeout=-1)
                # Check that the message is for you. Probably unnecessary...
                if message['channel'] == 'new_ip' and message["type"] == "message":
                    ip = message["data"]
                    self.check_ip(ip)

        except KeyboardInterrupt:
            return True
        except Exception as inst:
            self.print('Problem on the run()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            return True
