import configparser

import time
import random

from modules.whoisip.whoisip import WhoisIP


def get_default_config():
    cfg = configparser.ConfigParser()
    cfg.read_file(open("slips.conf"))
    return cfg


def run(infile, outfile):
    wi = WhoisIP(None, get_default_config(), testing=True)
    with open(infile, 'r') as f:
        with open(outfile, 'a') as o:
            lines = f.read().split("\n")
            for l in lines:
                wi.check_ip(l)


def try_random_addresses(limit=500):
    wi = WhoisIP(None, get_default_config(), testing=True)
    for i in range(0, limit):
        ip = str(random.randint(0, 255)) + "." + str(random.randint(0, 255)) + "."\
             + str(random.randint(0, 255)) + "." + str(random.randint(0, 255))
        wi.check_ip(ip)


def test_tricky_ips():
    ips = []
    ips.append("206.60.214.219")  # referring to other servers, unregistered segment, wrong country code
    ips.append("43.131.21.80")
    ips.append("245.51.167.150")  # manual check returns None
    ips.append("8.218.236.191")  # cymruwhois correctly says its SG, but whois insists on AU
    ips.append("107.78.26.116")  # broken pipe in cymruwhois (didn't happen for the second time..)
    ips.append("163.194.132.190")  # ASN lookup failed
    ips.append("162.253.210.64")  # 404 error for rdap, however whois works
    ips.append("71.163.76.208")  # there is a list of cidrs
    ips.append("223.43.28.222")  # Korean whois with encoding errs
    ips.append("76.42.110.168")  # cymruwhois crashes (it crashed last week with TypeError, now it works ¯\_(ツ)_/¯)
    ips.append("86.255.141.19")  # wrong encoding
    ips.append("71.163.76.208")  # no line "Information related to ..."
    ips.append("148.37.198.241")  # no line "Information related to ..."
    ips.append("47.216.133.94")  # Referred whois server rejected connection
    ips.append("185.0.192.82")  # Type error
    ips.append("211.42.167.245")  # response in both english and Korean from local Korean whois
    ips.append("169.251.240.44")  # double parentheses in orgname

    wi = WhoisIP(None, get_default_config(), testing=True)
    for ip in ips:
        print("-------------------------------------------")
        print(wi.check_ip_manual_only(ip, verbose=True))


def compare_methods(limit=500):
    cymru = WhoisIP(None, get_default_config(), testing=True)
    manual = WhoisIP(None, get_default_config(), testing=True)

    cymru_results = []
    manual_results = []

    random_addresses = []

    for i in range(0, limit):
        ip = str(random.randint(0, 255)) + "." + str(random.randint(0, 255)) + "."\
             + str(random.randint(0, 255)) + "." + str(random.randint(0, 255))
        random_addresses.append(ip)

    tmp_time = time.time()
    for ip in random_addresses:
        cymru_results.append(cymru.check_ip(ip))
    cymru_time = time.time() - tmp_time

    tmp_time = time.time()
    for ip in random_addresses:
        manual_results.append(manual.check_ip_manual_only(ip))
    manual_time = time.time() - tmp_time

    print("Cymru took", cymru_time)
    print("Manual took", manual_time)

    for ip, cr, mr in zip(random_addresses, cymru_results, manual_results):
        if cr[0] != mr[0] or cr[1] != mr[1] or cr[2] != mr[2] or cr[3] != mr[3]:
            print("IP:", ip, "has different results")
            if cr[0] != mr[0]:
                print("ASN - cumru:", cr[0] + ", manual:", mr[0])
            if cr[1] != mr[1]:
                print("Country - cumru:", cr[1] + ", manual:", mr[1])
            if cr[2] != mr[2]:
                print("CIDR - cumru:", cr[2] + ", manual:", mr[2])
            if cr[3] != mr[3]:
                print("Name - cumru:", cr[3] + ", manual:", mr[3])

if __name__ == "__main__":
    t = time.time()
    test_tricky_ips()
    # run("modules/whoisip/data/errs_out_of_erx.txt", "modules/whoisip/data/tmp.txt")
    # run("modules/whoisip/data/asn_lookup_err_ips.txt", "modules/whoisip/data/tmp.txt")
    # try_random_addresses()
    # TODO: check ip ranges in file
    # TODO: run query manually if the query doesn't return enough data
    print(time.time() - t)

    # compare_methods(limit=50)
