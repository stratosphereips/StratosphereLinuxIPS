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
    url_detections = 0
    url_total = 0
    if "undetected_urls" in response.keys():
        for url in response["undetected_urls"]:
            url_detections += url[2]
            url_total += url[3]
    if "detected_urls" in response.keys():
        for url in response["detected_urls"]:
            url_detections += url["positives"]
            url_total += url["total"]

    if url_total:
        url_ratio = url_detections/url_total
    else:
        url_ratio = 0

    down_file_detections = 0
    down_file_total = 0
    if "undetected_downloaded_samples" in response.keys():
        for down_file in response["undetected_downloaded_samples"]:
            down_file_detections += down_file["positives"]
            down_file_total += down_file["total"]
    if "detected_downloaded_samples" in response.keys():
        for down_file in response["detected_downloaded_samples"]:
            down_file_detections += down_file["positives"]
            down_file_total += down_file["total"]

    if down_file_total:
        down_file_ratio = down_file_detections/down_file_total
    else:
        down_file_ratio = 0

if __name__ == "__main__":
    # filename = "response_lauren.txt"
    # if filename:
    #     with open(filename, 'r') as f:
    #         datastore = json.load(f)
    #         k = 3

    vt = VTTest()
    vt.api_query("216.58.201.78")