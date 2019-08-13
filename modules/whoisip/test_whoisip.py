import configparser

import time

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
    import random
    wi = WhoisIP(None, get_default_config(), testing=True)
    for i in range(0, limit):
        ip = str(random.randint(0, 255)) + "." + str(random.randint(0, 255)) + "."\
             + str(random.randint(0, 255)) + "." + str(random.randint(0, 255))
        wi.check_ip(ip)


def test_tricky_ips():
    ips = []
    ips.append("8.218.236.191")  # cymruwhois correctly says its SG, but whois insists on AU
    ips.append("206.60.214.219")  # referring to other servers, unregistered segment, wrong country code
    ips.append("107.78.26.116")  # broken pipe in cymruwhois (didn't happen for the second time..)
    ips.append("163.194.132.190")  # ASN lookup failed
    ips.append("162.253.210.64")  # 404 error for rdap, however whois works
    ips.append("71.163.76.208")  # there is a list of cidrs
    ips.append("223.43.28.222")  # Korean whois with encoding errs
    ips.append("76.42.110.168")  # cymruwhois crashes (it crashed last week with TypeError, now it works ¯\_(ツ)_/¯)
    ips.append("86.255.141.19")  # wrong encoding
    ips.append("71.163.76.208")  # no line "Information related to ..."
    ips.append("148.37.198.241")  # no line "Information related to ..."

    wi = WhoisIP(None, get_default_config(), testing=True)
    for ip in ips:
        wi.check_ip(ip)

if __name__ == "__main__":
    t = time.time()
    test_tricky_ips()
    # run("modules/whoisip/data/errs_out_of_erx.txt", "modules/whoisip/data/tmp.txt")
    # run("modules/whoisip/data/asn_lookup_err_ips.txt", "modules/whoisip/data/tmp.txt")
    try_random_addresses()
    # TODO: check ip ranges in file
    # TODO: run query manually if the query doesn't return enough data
    print(time.time() - t)
