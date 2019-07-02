import requests
import json
import re
import socket
import time
import os
import numpy as np
from api_key import key
from matplotlib import pyplot as plt


class VTTest:

    def __init__(self):
        self.url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        self.known_ipv4_subnets = {}
        self.ipv4_reg = re.compile("^([0-9]{1,3}\.){3}[0-9]{1,3}$")
        print("Starting VT module at ", time.time())
        self.counter = 0

    def check_ip(self, ip: str):
        """
        Look if similar IP was already processed. If not, perform API call to VirusTotal and return scores for each of
        the four processed categories. Response is cached in a dictionary.
        IPv6 addresses are not cached, they will always be queried.
        :param ip: IP address to check
        :return: 4-tuple of floats: URL ratio, downloaded file ratio, referrer file ratio, communicating file ratio 
        """

        # TODO whitelist

        # first, look if an address from the same network was already resolved - TODO: add ipv6
        if re.match(self.ipv4_reg, ip):
            # get first three bytes of address
            ip_split = ip.split(".")
            ip_subnet = ip_split[0] + "." + ip_split[1] + "." + ip_split[2]

            # compare if the first three bytes of address match
            if ip_subnet in self.known_ipv4_subnets:
                # TODO: check API limit and consider doing the query anyway
                print("[" + ip + "] This IP was already processed")
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

        params = {'apikey': key, 'ip': ip}
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
            print("Status code is " + str(response.status_code) + " at " + str(time.time()) + ", query id: " + str(
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


def count_positives(response, response_key, positive_key, total_key):
    """
    Count positive checks and total checks in the response, for the given category. To compute ratio of downloaded
    samples, sum results for both detected and undetected dicts: "undetected_downloaded_samples" and
    "detected_downloaded_samples".
    :param response: json dictionary with response data
    :param response_key: category to count, eg "undetected_downloaded_samples"
    :param positive_key: key to use inside of the category for sucessful detections (usually its "positives")
    :param total_key: key to use inside of the category to sum all checks (usualy its "total")
    :return: number of positive tests, number of total tests run
    """
    detections = 0
    total = 0
    if response_key in response.keys():
        for item in response[response_key]:
            detections += item[positive_key]
            total += item[total_key]
    return detections, total


def check_ip_from_file(ip):
    """
    Loads json data from the file ip.txt and computes the score for this ip
    :param ip: IP address to work with
    :return: None
    """
    filename = ip + ".txt"
    if filename:
        with open(filename, 'r') as f:
            data = json.load(f)
            print(interpret_response(data))


def dataset_demo(benign_infile, benign_outfile, b_is_ips, malicious_infile, malicious_outfile, m_is_ips, call_api=True):
    """
    Demo script to visualise the dataset. API will be called on all records in both input files (this can be skipped if
    scores were computed previously). Score data is then loaded and data is visualised in four histograms.
    :param benign_infile: input file with benign addresses
    :param benign_outfile: output file to store scores for benign addresses
    :param b_is_ips: True if benign file contains IPs, False if it contains hostnames
    :param malicious_infile: input file with malicious addresses
    :param malicious_outfile: output file to store scores for malicious addresses
    :param m_is_ips: True if malicious file contains IPs, False if it contains hostnames
    :param call_api: True by default. If the API call was done already, you can set this to False and work with outfiles
    :return: None
    """

    if call_api:
        process_input_file(benign_infile, benign_outfile, b_is_ips)
        process_input_file(malicious_infile, malicious_outfile, m_is_ips)

    benign_data = read_score_from_file(benign_outfile)
    malicious_data = read_score_from_file(malicious_outfile)

    show_histograms(benign_data, malicious_data)


def process_input_file(infile, outfile, is_ips):
    """
    Reads hosts from a file and fetches their score from virustotal.
    :param infile: On each line of the input file, a hostname or IP is expected. These addresses will be read (host
    names are resolved first) and then the IP is checked against VT. A 4-tuple score is returned, as computed by
    VTTest:interpret_response. The query will pause if max. API request rate is reached. Any unresolvable hostnames
    will be skipped (you will be notified in stdout).
    :param outfile: The output file will be deleted if found, and new one will be created. Lines will be appended to
    the end of the file, one line per each ip/resolvable hostname. 
    :param is_ips: True if input file contains IP addresses, False for file with hostnames.
    :return: None
    """

    def get_score_for_ip(vt_test, ip):
        return vt_test.check_ip(ip)

    def get_score_for_hostname(vt_test, hostname):
        ip = socket.gethostbyname(hostname)
        return vt_test.check_ip(ip)

    # use different function to compute the score based on input format
    if is_ips:
        get_score = get_score_for_ip
    else:
        get_score = get_score_for_hostname

    if os.path.exists(outfile):
        os.remove(outfile)
    with open(infile, 'r') as f:
        with open(outfile, 'a') as o:
            lines = f.read().split("\n")
            lines.remove("")
            vt = VTTest()
            for l in lines:
                try:
                    scores = get_score(vt, l)
                    # print("Line", l, "resolved to", scores)
                    o.write(str(scores) + "\n")
                except socket.gaierror:
                    # unresolvable hostnames will throw this error, ignore those
                    print("Service " + l + " not known")


def read_score_from_file(filename, verbose=False):
    """
    Take a human readable file with scores and load the numbers into numpy array.
    :param filename: file with computed scores to read
    :param verbose: if set to true, basic stats will be printed (mean, min and max)
    :return: numpy array, 4 columns, one row for each score line
    """
    with open(filename, 'r') as f:
        lines = f.read().split("\n")
        lines = list(map(lambda s: s.replace("(", ""), lines))
        lines = list(map(lambda s: s.replace(")", ""), lines))
        lines = list(map(lambda s: s.split(","), lines))
        lines = list(map(lambda s: list(map(float, s)), lines[:-1]))

        data = np.array(lines)

        if verbose:
            print("Mean value:", np.mean(data, 0))
            print("Max value:", np.max(data, 0))
            print("Min value:", np.min(data, 0))

        return data


def show_histograms(benign, malicious):
    """
    Visualise four histograms, one for each category of scores. The input arrays must have 4 columns, number of rows
    do not need to match
    :param benign: np.ndarray of benign scores
    :param malicious: np.ndarray of malicious scores
    :return: None
    """
    bins = np.linspace(0, 0.12, 20)
    titles = ["Resolved URLs", "Downloaded files", "Referring files", "Communicating files"]

    for i in range(0, 4):
        b_urls = benign[:, i]
        m_urls = malicious[:, i]

        subplot_id = 221 + i

        plt.subplot(subplot_id)
        plt.hist(b_urls, bins, alpha=0.5, label='Benign', color="blue")
        plt.hist(m_urls, bins, alpha=0.5, label='Malicious', color="red")
        plt.title(titles[i])
        plt.legend(loc='upper right')
    plt.show()


if __name__ == "__main__":
    # filename = "response_lauren.txt"
    # if filename:
    #     with open(filename, 'r') as f:
    #         datastore = json.load(f)
    #         k = 3

    # vt = VTTest()
    # vt.check_ip("216.58.201.78")
    # check_ip_from_file("216.58.201.78")  # google.com
    # check_ip_from_file("47.88.158.115")  # laurengraham.com (malicious)

    # process_ips_in_file("data/malicious-ips2.txt")
    # process_hostnames_in_file("data/hostnames")
    # malicious_data = read_score_from_file("data/scores-malicious.txt")
    # benign_data = read_score_from_file("data/scores-benign.txt")

    # show_histograms(benign_data, malicious_data)

    dataset_demo("data/demo/benign_in", "data/demo/benign_out", False,
                 "data/demo/malicious_in", "data/demo/malicious_out", True,
                 call_api=False)
