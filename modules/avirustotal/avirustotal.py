# Must imports


from slips.common.abstracts import Module
import multiprocessing
from slips.core.database import __database__

# Your imports
import json
import re
import requests
import time


class VirusTotalModule(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'aVirusTotal'
    description = 'IP address lookup on VirusTotal'
    authors = ['Dita']

    def __init__(self, outputqueue, config, testing=False, keyfile="modules/avirustotal/api_key"):
        if testing:
            self.print = print
        else:
            multiprocessing.Process.__init__(self)
            # All the printing output should be sent to the outputqueue, which is connected to OutputProcess
            self.outputqueue = outputqueue
            # In case you need to read the slips.conf configuration file for your own configurations
            self.config = config
            # Start the DB
            __database__.start(self.config)  # TODO: What does this line do? It changes nothing.
            # To which channels do you want to subscribe? When a message arrives on the channel the module will wake up
            # The options change, so the last list is on the slips/core/database.py file. However common options are:
            # - new_ip
            # - tw_modified
            # - evidence_added
            self.c1 = __database__.subscribe('new_ip')
            print("VT", self.c1)

        # VT api URL for querying IPs
        self.url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'

        key_file = open(keyfile, "r")
        self.key = key_file.read(64)
        key_file.close()

        # dictionary of already processed subnets
        # TODO: use redis instead
        self.known_ipv4_subnets = {}

        # regex to check IP version (only IPv4 can be saved at the moment)
        self.ipv4_reg = re.compile("^([0-9]{1,3}\.){3}[0-9]{1,3}$")

        # self.print("Starting VirusTotal module at " + str(time.time()))
        self.counter = 0

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

    def run(self):
        try:
            # Main loop function
            while True:
                message = self.c1.get_message(timeout=-1)
                # Check that the message is for you. Probably unnecessary...
                # Ignore the first message
                if message['channel'] == 'new_ip' and message["type"] == "message":
                    ip = message["data"]
                    ip_score = self.check_ip(ip)
                    if is_dangerous(ip_score):
                        print("IP address " + ip + " is suspicious (URL score " + str(ip_score[0]) + ")")
                    # self.print("Score of IP " + ip + " is " + str(ip_score))

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
        Look if similar IP was already processed. If not, perform API call to VirusTotal and return scores for each of
        the four processed categories. Response is cached in a dictionary.
        IPv6 addresses are not cached, they will always be queried.
        :param ip: IP address to check
        :return: 4-tuple of floats: URL ratio, downloaded file ratio, referrer file ratio, communicating file ratio 
        """

        # TODO whitelist
        # TODO should private IPs be excluded?

        # first, look if an address from the same network was already resolved - TODO: add ipv6
        if re.match(self.ipv4_reg, ip):
            # get first three bytes of address
            ip_split = ip.split(".")
            ip_subnet = ip_split[0] + "." + ip_split[1] + "." + ip_split[2]

            # compare if the first three bytes of address match
            if ip_subnet in self.known_ipv4_subnets:
                # TODO: check API limit and consider doing the query anyway
                self.print("[" + ip + "] This IP was already processed")
                return self.known_ipv4_subnets[ip_subnet]

            # for unknown ipv4 address, do the query
            response = self.api_query_(ip)

            # save query results
            scores = interpret_response(response.json())
            self.known_ipv4_subnets[ip_subnet] = scores
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

        # repeat query if API limit was reached (code 204)
        while response.status_code != 200:
            # if the query was unsuccessful but it is not caused by API limit, abort (this is some unknown error)
            if response.status_code != 204:
                # X-Api-Message is a comprehensive error description, but it is not always present
                if "X-Api-Message" in response.headers:
                    message = response.headers["X-Api-Message"]
                # Reason is a much shorter desctiption ("Forbidden"), but it is always there
                else:
                    message = response.reason
                raise Exception("VT API returned unexpected code: " + str(response.status_code) + " - " + message)

            # report that API limit is reached, wait one minute and try again
            self.print("Status code is " + str(response.status_code) + " at " + str(time.time()) + ", query id: " + str(
                self.counter))
            time.sleep(60)
            response = requests.get(self.url, params=params)

        # optionally, save data to file
        if save_data:
            data = response.json()
            filename = ip + ".txt"
            if filename:
                with open(filename, 'w') as f:
                    json.dump(data, f)

        return response


def is_dangerous(score):
    if score[0] > 0.025:
        return True
    return False


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
