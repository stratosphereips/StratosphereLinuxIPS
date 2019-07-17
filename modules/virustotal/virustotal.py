# Must imports
import configparser

from slips.common.abstracts import Module
import multiprocessing
from slips.core.database import __database__

# Your imports
import json
import re
import requests
import time
import ipaddress


class VirusTotalModule(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'VirusTotal'
    description = 'IP address lookup on VirusTotal'
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
        # This line might not be needed when running SLIPS, but when VT module is run standalone, it still uses the
        # database and this line is necessary. Do not delete it, instead move it to line 21.
        __database__.start(self.config)  # TODO: What does this line do? It changes nothing.

        self.db_hashset_name = "virustotal-module-ipv4subnet-cache"
        self.db_ip_hashset_name = "virustotal-module-ip-cache"
        # To which channels do you want to subscribe? When a message arrives on the channel the module will wake up
        # The options change, so the last list is on the slips/core/database.py file. However common options are:
        # - new_ip
        # - tw_modified
        # - evidence_added
        self.c1 = __database__.subscribe('new_ip')

        # VT api URL for querying IPs
        self.url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'

        key_file = self.__read_configuration("virustotal", "api_key_file")
        self.key = None
        try:
            with open(key_file, "r") as f:
                self.key = f.read(64)
        except FileNotFoundError:
            self.print("The file with API key (" + key_file + ") could not be loaded. VT module is stopping.")

        # regex to check IP version (only IPv4 can be saved at the moment)
        self.ipv4_reg = re.compile("^([0-9]{1,3}\.){3}[0-9]{1,3}$")

        # self.print("Starting VirusTotal module at " + str(time.time()))
        self.counter = 0

    def __read_configuration(self, section: str, name: str) -> str:
        """ Read the configuration file for what we need """
        # Get the time of log report
        try:
             conf_variable = self.config.get(section, name)
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            conf_variable = None
        return conf_variable

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

    def run(self):
        if self.key is None:
            return

        try:
            # Main loop function
            while True:
                message = self.c1.get_message(timeout=-1)
                # Check that the message is for you. Probably unnecessary...
                # Ignore the first message
                if message['channel'] == 'new_ip' and message["type"] == "message":
                    ip = message["data"]
                    ip_score = self.check_ip(ip)
                    save_score_to_db(ip, ip_score)
                    self.print("[" + ip + "] has score " + str(ip_score), verbose=5, debug=1)

        except KeyboardInterrupt:
            return True
        except Exception as inst:
            self.print('Problem on the run()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            return True

    def check_ip(self, ip: str):
        """
        Look if this IP was already processed. If not, perform API call to VirusTotal and return scores for each of
        the four processed categories. Response is cached in a dictionary. Private IPs always return (0, 0, 0, 0).
        :param ip: IP address to check
        :return: 4-tuple of floats: URL ratio, downloaded file ratio, referrer file ratio, communicating file ratio 
        """

        addr = ipaddress.ip_address(ip)
        if addr.is_private:
            self.print("[" + ip + "] is private, skipping", verbose=5, debug=1)
            return 0, 0, 0, 0

        # check if the address is in the cache (probably not, since all IPs are unique)
        cached_data = self.is_ip_in_db(ip)
        if cached_data:
            return cached_data

        # for unknown address, do the query
        response = self.api_query_(ip)

        scores = interpret_response(response.json())
        self.put_ip_to_db(ip, scores)
        self.counter += 1
        return scores

    def check_ip_with_subnet_cache_(self, ip: str):
        """
        Unused.
        Look if similar IP was already processed. If not, perform API call to VirusTotal and return scores for each of
        the four processed categories. Response is cached in a dictionary.
        IPv6 addresses are not cached, they will always be queried.
        :param ip: IP address to check
        :return: 4-tuple of floats: URL ratio, downloaded file ratio, referrer file ratio, communicating file ratio 
        """

        # first, look if an address from the same network was already resolved
        if re.match(self.ipv4_reg, ip):
            # get first three bytes of address
            ip_split = ip.split(".")
            ip_subnet = ip_split[0] + "." + ip_split[1] + "." + ip_split[2]

            if not is_ipv4_public(ip_split):
                self.print("[" + ip + "] is private, skipping", verbose=5, debug=1)
                return 0, 0, 0, 0

            # compare if the first three bytes of address match
            cached_data = self.is_subnet_in_db(ip_subnet)
            if cached_data:
                self.print("[" + ip + "] This IP was already processed", verbose=5, debug=1)
                return cached_data

            # for unknown ipv4 address, do the query
            response = self.api_query_(ip)

            # save query results
            scores = interpret_response(response.json())
            self.put_subnet_to_db(ip_subnet, scores)
            self.counter += 1
            return scores

        # ipv6 addresses
        response = self.api_query_(ip)
        self.counter += 1

        return interpret_response(response.json())

    def api_query_(self, ip, save_data=False):
        """
        Create request and perform API call
        :param ip: IP address to check
        :param save_data: False by default. Set to True to save each request json in a file named ip.txt
        :return: Response object
        """

        params = {'apikey': self.key, 'ip': ip}
        response = requests.get(self.url, params=params)

        sleep_attempts = 0

        # repeat query if API limit was reached (code 204)
        while response.status_code != 200:

            # requests per minute limit reached
            if response.status_code == 204:
                # usually sleeping for 40 seconds is enough, if not, try adding 20 more
                if sleep_attempts == 0:
                    sleep_time = 40
                else:
                    sleep_time = 20
                sleep_attempts += 1

            # requests per hour limit reached
            elif response.status_code == 403:
                # 10 minutes
                sleep_time = 600
                self.print("Please check that your API key is correct. Code 403 means timeout but also wrong API key.")

            else:
                # if the query was unsuccessful but it is not caused by API limit, abort (this is some unknown error)
                # X-Api-Message is a comprehensive error description, but it is not always present
                if "X-Api-Message" in response.headers:
                    message = response.headers["X-Api-Message"]
                # Reason is a much shorter description ("Forbidden"), but it is always there
                else:
                    message = response.reason
                raise Exception("VT API returned unexpected code: " + str(response.status_code) + " - " + message)

            # report that API limit is reached, wait one minute and try again
            self.print("Status code is " + str(response.status_code) + " at " + str(time.asctime()) + ", query id: " + str(
                self.counter), verbose=5, debug=1)

            self.print("API limit reached, going to sleep for " + str(sleep_time) + " seconds", verbose=1, debug=0)
            time.sleep(sleep_time)
            response = requests.get(self.url, params=params)

        # optionally, save data to file
        if save_data:
            data = response.json()
            filename = ip + ".txt"
            if filename:
                with open(filename, 'w') as f:
                    json.dump(data, f)

        return response

    def is_subnet_in_db(self, subnet):
        """ Check if subnet ip is in db. Unused """
        data = __database__.r.hget(self.db_hashset_name, subnet)
        if data:
            return list(map(float, data.split(" ")))
        else:
            return data  # None, the key wasn't found

    def put_subnet_to_db(self, subnet, score):
        """ Add new subnet with score to db. Unused """
        data = str(score[0]) + " " + str(score[1]) + " " + str(score[2]) + " " + str(score[3])
        __database__.r.hset(self.db_hashset_name, subnet, data)

    def is_ip_in_db(self, ip):
        data = __database__.r.hget(self.db_ip_hashset_name, ip)
        if data:
            return list(map(float, data.split(" ")))
        else:
            return data  # None, the key wasn't found

    def put_ip_to_db(self, ip, score):
        data = str(score[0]) + " " + str(score[1]) + " " + str(score[2]) + " " + str(score[3])
        __database__.r.hset(self.db_ip_hashset_name, ip, data)


def save_score_to_db(ip, scores):
    vtdata = {"URL": scores[0],
              "down_file": scores[1],
              "ref_file": scores[2],
              "com_file": scores[3]}

    data = {"VirusTotal": vtdata}
    __database__.setInfoForIPs(ip, data)


def is_ipv4_public(ip: list):
    # Reserved addresses: https://en.wikipedia.org/wiki/Reserved_IP_addresses
    ip = list(map(int, ip))

    # private addresses
    # 10.*
    if ip[0] == 10:
        return False
    # 192.168.*
    if ip[0] == 192 and ip[1] == 168:
        return False
    # 172.16.* - 172.32.*
    if ip[0] == 172 and 16 <= ip[1] <= 32:
        return False

    # Used for link-local addresses between two hosts on a single link when no IP address is otherwise specified,
    # such as would have normally been retrieved from a DHCP server.
    # 169.254.*
    if ip[0] == 169 and ip[1] == 254:
        return False

    # IETF Protocol Assignments
    # 192.0.0.*
    if ip[0] == 192 and ip[1] == 0 and ip[2] == 0:
        return False

    # In use for IP multicast. (Former Class D network) 224.* - 239.*
    # Reserved for future use. (Former Class E network) 240.0.0.0 – 255.255.255.254
    # Reserved for the "limited broadcast" destination address 255.255.255.255
    if ip[0] >= 224:
        return False

    return True


def interpret_response(response: dict):
    """
    Read the dictionary and compute ratio for each category
    :param response: dictionary (json data from the response)
    :return: four floats: url_ratio, down_file_ratio, ref_file_ratio, com_file_ratio
    """
    # get score [positives, total] for the URL samples that weren't detected
    # this is the only section where samples are lists and not dicts, that's why integers are passed as keys
    undetected_url_score = count_positives(response, "undetected_urls", 2, 3)
    detected_url_score = count_positives(response, "detected_urls", "positives", "total")
    url_detections = undetected_url_score[0] + detected_url_score[0]
    url_total = undetected_url_score[1] + detected_url_score[1]

    if url_total:
        url_ratio = url_detections/url_total
    else:
        url_ratio = 0

    undetected_download_score = count_positives(response, "undetected_downloaded_samples", "positives", "total")
    detected_download_score = count_positives(response, "detected_downloaded_samples", "positives", "total")
    down_file_detections = undetected_download_score[0] + detected_download_score[0]
    down_file_total = undetected_download_score[1] + detected_download_score[1]

    if down_file_total:
        down_file_ratio = down_file_detections/down_file_total
    else:
        down_file_ratio = 0

    undetected_ref_score = count_positives(response, "undetected_referrer_samples", "positives", "total")
    detected_ref_score = count_positives(response, "detected_referrer_samples", "positives", "total")
    ref_file_detections = undetected_ref_score[0] + detected_ref_score[0]
    ref_file_total = undetected_ref_score[1] + detected_ref_score[1]

    if ref_file_total:
        ref_file_ratio = ref_file_detections/ref_file_total
    else:
        ref_file_ratio = 0

    undetected_com_score = count_positives(response, "undetected_communicating_samples", "positives", "total")
    detected_com_score = count_positives(response, "detected_communicating_samples", "positives", "total")
    com_file_detections = undetected_com_score[0] + detected_com_score[0]
    com_file_total = undetected_com_score[1] + detected_com_score[1]

    if com_file_total:
        com_file_ratio = com_file_detections/com_file_total
    else:
        com_file_ratio = 0

    return url_ratio, down_file_ratio, ref_file_ratio, com_file_ratio


def count_positives(response: dict, response_key: str, positive_key, total_key):
    """
    Count positive checks and total checks in the response, for the given category. To compute ratio of downloaded
    samples, sum results for both detected and undetected dicts: "undetected_downloaded_samples" and
    "detected_downloaded_samples".
    :param response: json dictionary with response data
    :param response_key: category to count, eg "undetected_downloaded_samples"
    :param positive_key: key to use inside of the category for successful detections (usually its "positives")
    :param total_key: key to use inside of the category to sum all checks (usually its "total")
    :return: number of positive tests, number of total tests run
    """
    detections = 0
    total = 0
    if response_key in response.keys():
        for item in response[response_key]:
            detections += item[positive_key]
            total += item[total_key]
    return detections, total
