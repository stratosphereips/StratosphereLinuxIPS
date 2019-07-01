import requests
import json
import re
from api_key import key


class VTTest:
    def __init__(self):
        self.url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        self.known_ipv4_subnets = {}
        self.ipv4_reg = re.compile("^([0-9]{1,3}\.){3}[0-9]{1,3}$")

    def check_ip(self, ip: str):
        # TODO whitelist
        # first, we look if an address from the same network was already resolved (TODO: maybe add ipv6?)
        if re.match(self.ipv4_reg, ip):
            # compare if the first three bytes of address match
            ip_split = ip.split(".")
            ip_subnet = ip_split[0] + "." + ip_split[1] + "." + ip_split[2]

            if ip_subnet in self.known_ipv4_subnets:
                return interpret_response(self.known_ipv4_subnets[ip_subnet])

            # for unknown ipv4 address, do the query and save it
            # TODO handle refused API calls
            response = self.api_query(ip)
            self.known_ipv4_subnets[ip_subnet] = response.json()

        else:
            # TODO handle refused API calls
            response = self.api_query(ip)

        return interpret_response(response.json())

    def api_query(self, ip):

        params = {'apikey': key, 'ip': ip}
        response = requests.get(self.url, params=params)

        data = response.json()
        filename = ip + ".txt"
        if filename:
            # Writing JSON data
            with open(filename, 'w') as f:
                json.dump(data, f)

        return response


def interpret_response(response: dict):
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
    detections = 0
    total = 0
    if response_key in response.keys():
        for item in response[response_key]:
            detections += item[positive_key]
            total += item[total_key]
    return detections, total


def check_ip_from_file(ip):
    filename = ip + ".txt"
    if filename:
        with open(filename, 'r') as f:
            datastore = json.load(f)
            print(interpret_response(datastore))


if __name__ == "__main__":
    # filename = "response_lauren.txt"
    # if filename:
    #     with open(filename, 'r') as f:
    #         datastore = json.load(f)
    #         k = 3

    # vt = VTTest()
    # vt.api_query("216.58.201.78")
    check_ip_from_file("216.58.201.78")  # google.com
    check_ip_from_file("47.88.158.115")  # laurengraham.com (malicious)
