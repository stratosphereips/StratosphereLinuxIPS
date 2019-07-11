import configparser

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


def try_random_addresses():
    import random
    wi = WhoisIP(None, get_default_config(), testing=True)
    while True:
        ip = str(random.randint(0, 255)) + "." + str(random.randint(0, 255)) + "."\
             + str(random.randint(0, 255)) + "." + str(random.randint(0, 255))
        wi.check_ip(ip)


def test_tricky_ips():
    ips = []
    ips.append("162.253.210.64")  # 404 error for rdap, however whois works
    ips.append("71.163.76.208")  # there is a list of cidrs
    ips.append("223.43.28.222")  # Korean whois with encoding errs

    wi = WhoisIP(None, get_default_config(), testing=True)
    for ip in ips:
        wi.check_ip(ip)
    for ip in ips:
        wi.check_ip(ip)


if __name__ == "__main__":
    # run("modules/whoisip/data/malicious_ips.txt", "modules/whoisip/data/malicious_ips_out.txt")
    # try_random_addresses()
    test_tricky_ips()
