# Must imports
from slips.common.abstracts import Module
import multiprocessing
from slips.core.database import __database__

# Your imports
import ipaddress
import json
from modules.whoisip.whois_parser import WhoisQuery


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
        self.db_hashset_ipv6 = "whois-module-ipv6subnet-cache"

        # a queue to store all the ips that will have to be retried, as ipaddress objects
        self.ip_queue = []

    def print(self, text, verbose=2, debug=0):
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

    def testing_print(self, text, verbose=0, debug=0):
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
            self.print("Address " + str(address) + " is not global", verbose=9, debug=1)
            return False

        if address.is_private:
            self.print("Address " + str(address) + " is private", verbose=9, debug=1)
            return False

        if address.is_multicast:
            self.print("Address " + str(address) + " is multicast", verbose=9, debug=1)
            return False

        if address.is_link_local:
            self.print("Address " + str(address) + " is link local", verbose=9, debug=1)
            return False

        if address.is_loopback:
            self.print("Address " + str(address) + " is loopback", verbose=9, debug=1)
            return False

        return True

    def check_ip(self, ip: str):
        """
        Look if IP is already cached. If a specific network cache is ready, save it to IP data. If a general cached
        network is found, a query is attempted and depending on the result, either cached data or new results are saved
        to IP data (and the new results are cached).
        If there is nothing in the cache, a query is run, and either the result is saved and cached, or the IP is added
        to the retry queue.
        :param ip: IP address to work with
        :return: True if the query was successful (meaning network is ok), False if no query was run or if it failed.
        """
        self.print("Checking ip " + ip, verbose=5, debug=1)

        address = ipaddress.ip_address(ip)

        if not self.is_checkable(address):
            return False

        cached_data = self.load_subnet(address)

        cidr_prefix_len = None
        if cached_data is not None:
            cidr_prefix_len = cached_data["cidr_prefix_len"]
            if cidr_prefix_len > 8:
                self.print("Data found in cache!", verbose=9, debug=1)
                self.print(cached_data, verbose=9, debug=1)
                self.save_ip_data(ip, cached_data)
                return False
            else:
                self.print("Data found in cache with mask /"+str(cidr_prefix_len), verbose=9, debug=1)
        else:
            self.print("Data not found in cache!", verbose=9, debug=1)

        query = WhoisQuery(address)
        query.run(self.print)

        result = query.get_result_dictionary()

        self.print(result, verbose=9, debug=1)

        # in case of unsuccessful query, if something was found in the cache, use it. If not, save the ip for later
        if str(result["status"]) != "0":
            # if there is nothing about the ip in cache, add it to the queue so it will be retried later
            if cidr_prefix_len is None:
                self.ip_queue.append(address)
                self.print("Query failed, appending to queue!", verbose=9, debug=1)
            # if at least something is present in cache about the ip, use the generic data
            else:
                self.save_ip_data(ip, cached_data)
            # the query didn't run, so return False
            return False

        # otherwise, the query found something
        else:
            # in case of a new ip that has nothing in cache, check if it should be cached, cache it and save it
            if cidr_prefix_len is None:
                self.check_and_cache(address.version, result)
                # save it
                self.save_ip_data(ip, result)
            # if there is something cached already, compare the two responses and choose the more detailed one
            else:
                # if the new result is more specific, cache it
                if result["cidr_prefix_len"] is not None and cidr_prefix_len < result["cidr_prefix_len"]:
                    self.check_and_cache(address.version, result)
                # save the newly found result
                self.save_ip_data(ip, result)
            return True

    def retry_queue(self):
        """
        Read IP addresses from retry_queue and try to check them for a second time.
        :return: None
        """
        if len(self.ip_queue) == 0:
            return
        self.print("Loading unsuccessful queries from the queue", verbose=5, debug=1)

        while len(self.ip_queue) > 0:
            address = self.ip_queue.pop(0)
            ip = str(address)
            self.print("Retrying unsuccessful query for " + ip, verbose=5, debug=1)

            # if the network was found while the ip was waiting in queue, use the cached value
            cached_data = self.load_subnet(address)
            if cached_data is not None:
                self.print("Data found in cache", verbose=9, debug=1)
                self.save_ip_data(ip, cached_data)
                # go to next ip in queue
                continue

            # if no cache entry is present, run query again
            # TODO: maybe run the query first with small timeout (4s) and retry later with bigger timeout (20s)
            query = WhoisQuery(address)
            query.run(self.print)

            result = query.get_result_dictionary()

            self.print(result, verbose=9, debug=1)

            # in case the query fails (again), then maybe there is an issue with it, and we should give up trying
            if str(result["status"]) != "0":
                self.print("Retry query failed, dropping!", verbose=9, debug=1)
                # however, this might also be a sign of network failure (unfortunately for that ip), in that case,
                # pause retrying until a successful query is run for a new ip
                break

            # getting here means that the query was successful, cache it and save it
            self.print("Retry query successful, saving!", verbose=9, debug=1)
            self.check_and_cache(address.version, result)
            self.save_ip_data(ip, result)

    def save_ip_data(self, ip, data):
        """
        Save whois data about an IP to the database
        :param ip: ip address
        :param data: dictionary with the response
        :return: None
        """
        pass

    def should_data_be_cached(self, prefix_len, cidr, version):
        # Do not cache if the mask is zero, or 32 (ipv4) or 128 (ipv6)
        if prefix_len == 0:
            return False
        if prefix_len == 32 and version == 4:
            return False
        if prefix_len == 128 and version == 6:
            return False
        if cidr is None:
            return False
        return True

    def check_and_cache(self, version, result):
        if version == 4:
            Interface = ipaddress.IPv4Interface
            save_subnet = self.save_ipv4_subnet
        else:
            Interface = ipaddress.IPv6Interface
            save_subnet = self.save_ipv6_subnet

        # check if data should be cached
        if self.should_data_be_cached(result["cidr_prefix_len"], result["cidr"], version):
            mask = int(Interface(result["cidr"]))
            save_subnet(mask, result)
        else:
            self.print("Not suitable for caching", verbose=5, debug=1)

    def save_ipv4_subnet(self, mask: int, result: dict):
        str_data = json.dumps(result)
        __database__.r.hset(self.db_hashset_ipv4, mask, str_data)

    def save_ipv6_subnet(self, mask, result):
        str_data = json.dumps(result)
        __database__.r.hset(self.db_hashset_ipv6, mask, str_data)

    def load_subnet(self, ip):
        if ip.version == 4:
            mask = 4294967295
            ip_value = int(ip)
            for i in range(0, 32):
                mask -= pow(2, i)
                masked_ip = mask & ip_value
                data = __database__.r.hget(self.db_hashset_ipv4, masked_ip)
                if data:
                    return json.loads(data)
            return None
        else:
            mask = 340282366920938463463374607431768211455
            ip_value = int(ip)
            for i in range(0, 128):
                mask -= pow(2, i)
                masked_ip = mask & ip_value
                data = __database__.r.hget(self.db_hashset_ipv6, masked_ip)
                if data:
                    return json.loads(data)
            return None

    def run(self):
        try:
            # Main loop function
            while True:
                message = self.c1.get_message(timeout=-1)
                # Check that the message is for you. Probably unnecessary...
                if message['channel'] == 'new_ip' and message["type"] == "message":
                    ip = message["data"]
                    if self.check_ip(ip):
                        self.retry_queue()

        except KeyboardInterrupt:
            return True
        except Exception as inst:
            self.print('Problem on the run()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            return True
