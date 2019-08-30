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


def test_ipv6():
    ips = []
    ips.append("2400:3200:2000:57::1")
    ips.append("2600:1404:18:380::6395")
    ips.append("2600:1403:1:58c::6395")
    ips.append("2001:718:2:1611:0:1:0:90")
    ips.append("2600:3c00::f03c:91ff:fe73:6ac0")
    ips.append("2604:4000:4000::64:98:151:2")
    ips.append("2604:4000:4000::64:98:151:1")
    ips.append("2001:19f0:6401:18f1:5400:1ff:febc:864a")
    ips.append("2400:3200:2000:56::1")
    ips.append("2001:1398:276::200:7:5:7")
    ips.append("2400:3200:2000:29::1")
    ips.append("2400:3200:2000:28::1")
    ips.append("2a02:750:5::538")
    ips.append("2001:19f0:5001:1caf:5400:1ff:fec5:8d50")
    ips.append("2a00:1a28:2010:1::89")
    ips.append("2001:19f0:6801:474:5400:1ff:fec5:8efb")
    ips.append("2a02:750:8::32")
    ips.append("2001:8d8:fe:53::d9a0:5251:100")
    ips.append("2001:8d8:fe:53::d9a0:5151:100")
    ips.append("2001:8d8:fe:53::d9a0:5051:100")
    ips.append("2001:8d8:fe:53::d9a0:5351:100")
    ips.append("2a00:1ed0:2::1:5bef:c8f3:1")
    ips.append("2001:4de8:fa22::1:5264:602:1")
    ips.append("2a02:2b88:1:4::ac")
    ips.append("2a00:f940:4::47")
    ips.append("2a00:f940:5::190")
    ips.append("2607:f798:140:202::2091:4813:2165")
    ips.append("2607:f798:140:302::2091:4812:8212")
    ips.append("2400:3200:2000:26::1")
    ips.append("2400:3200:2000:27::1")
    ips.append("2400:3200:2000:21::1")
    ips.append("2400:3200:2000:20::1")
    ips.append("2001:8d8:fe:53::d9a0:5274:100")
    ips.append("2001:8d8:fe:53::d9a0:533c:100")
    ips.append("2001:8d8:fe:53::d9a0:512d:100")
    ips.append("2001:8d8:fe:53::d9a0:507b:100")
    ips.append("2400:3200:2000:30::1")
    ips.append("2001:8d8:fe:53::d9a0:5327:100")
    ips.append("2001:8d8:fe:53::d9a0:5112:100")
    ips.append("2001:8d8:fe:53::d9a0:525d:100")
    ips.append("2001:8d8:fe:53::d9a0:505d:100")
    ips.append("2a00:fa8:3::100:0:4:1")
    ips.append("2001:19f0:5001:eed:5400:ff:fe1d:d24f")
    ips.append("2001:19f0:5c01:bb0:5400:ff:fe1d:d1cc")
    ips.append("240e:ff:9000:1100::19a")
    ips.append("2607:a400:1:19::19a")
    ips.append("2001:8d8:fe:53::d9a0:506e:100")
    ips.append("2001:8d8:fe:53::d9a0:5166:100")
    ips.append("2001:8d8:fe:53::d9a0:522b:100")
    ips.append("2001:8d8:fe:53::d9a0:5329:100")
    ips.append("2400:3200:2000:40::1")
    wi = WhoisIP(None, get_default_config(), testing=True)
    for ip in ips:
        result = wi.check_ip(ip)


def test_tricky_ips():
    ips = []
    ips.append("50.64.231.112")  # rejected by server
    ips.append("8.218.236.191")  # cymruwhois correctly says its SG, but whois insists on AU
    ips.append("194.54.110.205")  # NoneType is not iterable (likely empty cidr)
    ips.append("206.60.214.219")  # referring to other servers, unregistered segment, wrong country code
    ips.append("43.131.21.80")  # japan
    ips.append("245.51.167.150")  # manual check returns None
    ips.append("107.78.26.116")  # broken pipe in cymruwhois (didn't happen for the second time..)
    ips.append("163.194.132.190")  # ASN lookup failed
    ips.append("162.253.210.64")  # empty result for both arin and ripe
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
    ips.append("52.88.0.1")  # multiple as in one result AS16509, AS14618

    wi = WhoisIP(None, get_default_config(), testing=True)
    for ip in ips:
        print("-------------------------------------------")
        print(wi.check_ip(ip, verbose=False))


if __name__ == "__main__":
    t = time.time()
    # test_tricky_ips()
    # run("modules/whoisip/data/errs_out_of_erx.txt", "modules/whoisip/data/tmp.txt")
    # run("modules/whoisip/data/asn_lookup_err_ips.txt", "modules/whoisip/data/tmp.txt")
    # try_random_addresses(limit=10)
    test_ipv6()
    # TODO: test on malware data
    # TODO: test if caching a large network will hide a smaller network
    # TODO: fix verbosity and debug
    # TODO: should I cache an error? What should I do with an error? (whois.py line 126)
    # TODO: justify the wait delay (whois_parser.py line 137)
    # TODO: make sure no relevant info is skipped (a regex to match line with url.*[-a-zA-Z0-9.]+\.[a-z]{2,}.*)
    # TODO:      whois_utils.py line 266
    # TODO: Save the whois authority that gave this response (whois_parser.py 46)

    print(time.time() - t)

    # compare_methods(limit=50)
