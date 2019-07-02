import json
import socket
import os
import numpy as np
from matplotlib import pyplot as plt

from modules.avirustotal.avirustotal import VirusTotalModule


def check_ip_from_file(ip):
    """
    Loads json data from the file ip.txt
    :param ip: IP address to work with
    :return: None
    """
    filename = ip + ".txt"
    if filename:
        with open(filename, 'r') as f:
            data = json.load(f)
            print(data)


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
    VirusTotalModule:interpret_response. The query will pause if max. API request rate is reached. Any unresolvable hostnames
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
            vt = VirusTotalModule()
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

    # vt = VirusTotalModule()
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
