# Must imports
from slips.common.abstracts import Module
import multiprocessing
from slips.core.database import __database__

# Your imports
import socket
from modules.whoisip.whois_parser import get_data_from_response
import ipaddress
import json
from cymruwhois import Client
import subprocess


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

        self.client = Client()

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

    def is_checkable(self, address):
        if not address.is_global:
            self.print("Address is not global")
            return False

        if address.is_private:
            self.print("Address is private")
            return False

        if address.is_multicast:
            self.print("Address is multicast")
            return False

        if address.is_link_local:
            self.print("Address is link local")
            return False

        if address.is_loopback:
            self.print("Address is loopback")
            return False

        return True

    def check_ip(self, ip):
        print("--- Checking ip " + ip)

        address = ipaddress.ip_address(ip)

        if not self.is_checkable(address):
            return

        if address.version == 4:
            load_subnet = self.load_ipv4_subnet
            save_subnet = self.save_ipv4_subnet
            Interface = ipaddress.IPv4Interface
        else:
            load_subnet = self.load_ipv6_subnet
            save_subnet = self.save_ipv6_subnet
            Interface = ipaddress.IPv6Interface

        cached_data = load_subnet(address)

        if cached_data is not None:
            self.print("Data found in cache!")
            self.show_results(cached_data["asn"], cached_data["country"], cached_data["cidr"], cached_data["name"])
            return cached_data

        self.print("Data not found in cache!")

        try:
            check_manually = False
            message = self.client.lookup(ip)
            asn = message.asn
            ctr_code = message.cc
            cidr = message.prefix
            name = message.owner
            if asn == "NA":
                asn = "None"
                check_manually = True
            if ctr_code == "" or ctr_code == "NA":
                # unfortunately, IP addresses from Namibia (NA) will have to be checked again
                ctr_code = "None"
                check_manually = True
            if cidr == "NA":
                cidr = "None"
                check_manually = True
            if name == "NA":
                name = "None"
                check_manually = True
        except socket.gaierror as e:
            self.print(e)
            return
        except BrokenPipeError as e:
            self.print(e)
            return
        except TypeError:
            # error in cymruwhois when querying IP 76.42.110.168
            # __init__() missing 2 required positional arguments: 'cc' and 'owner'
            print("### CymruWhois crashed")
            check_manually = True
            asn = "None"
            ctr_code = "None"
            cidr = "None"
            name = "None"

        if check_manually:
            print("### Running manual check")
            asn, ctr_code, cidr, name = self.check_whois_manually(address, asn, ctr_code, cidr, name)

        self.show_results(asn, ctr_code, cidr, name)

        if asn == "None" or ctr_code == "None" or cidr == "None" or name == "None":
            print("Results are incomplete")

        if "," in cidr:
            cidrs = cidr.split(", ")
        else:
            cidrs = [cidr]

        for cidr in cidrs:
            try:
                mask = int(Interface(cidr))
                save_subnet(mask, asn, ctr_code, cidr, name)
            except:
                pass

    def check_whois_manually(self, ip, asn, ctr_code, cidr, name):
        try:
            # timeout: interrupt process after time in seconds
            # stdout: save output in response object
            # stderr: save error output in response object
            # universal newlines: output is string instead of byte array (this cannot be used due to encoding issues
            #    with foreign characters, eg French: 86.255.141.19)
            response = subprocess.run(["whois", str(ip)], timeout=3, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.TimeoutExpired as e:
            # -r stops whois from following links to other databases
            # but also some outputs are different, so it cannot be used by default
            response = subprocess.run(["whois", "-r", str(ip)], stdout=subprocess.PIPE)

        if response.returncode != 0:
            print(response.stderr)
            # TODO: handle incorrect requests (don't cache them)
            return None

        # decode as iso-8859-1, this fixes errors in French requests
        output = response.stdout.decode("iso-8859-1")
        data = get_data_from_response(output, asn, ctr_code, cidr, name)
        return data["asn"], data["country"], data["cidr"], data["name"]

    def show_results(self, asn, ctr_code, cidr, name):
        self.print("ASN: " + asn)
        self.print("Country: " + ctr_code)
        self.print("CIDR: " + cidr)
        self.print("Name: " + name)

    def save_ipv4_subnet(self, mask: int, asn: str, ctr_code: str, cidr: str, name: str):
        data = {"asn": asn, "country": ctr_code, "cidr": cidr, "name": name}
        str_data = json.dumps(data)
        __database__.r.hset(self.db_hashset_ipv4, mask, str_data)

    def save_ipv6_subnet(self, mask, asn, ctr_code, cidr, name):
        pass

    def load_ipv4_subnet(self, ip):
        mask = 4294967295
        ip_value = int(ip)
        for i in range(0, 32):
            mask -= pow(2, i)
            masked_ip = mask & ip_value
            data = __database__.r.hget(self.db_hashset_ipv4, masked_ip)
            if data:
                return json.loads(data)
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
