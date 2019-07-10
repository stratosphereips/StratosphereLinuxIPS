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


def test_tricky(ips):
    ips = []
    ips.append("71.163.76.208")  # there is a list of cidrs
    ips.append("223.43.28.222")  # Korean whois with encoding errs

     # TODO: Tomorrow check this:
     # 21) "4294959104"
     # 22) "{\"asn\": \"17964\", \"country\": \"CN\", \"cidr\": \"101.246.0.0/19\", \"name\": \"GHSX_NET\"}"
     # 23) "4294966784"
     # 24) "{\"asn\": \"8517\", \"country\": \"TR\", \"cidr\": \"193.140.124.0/23\", \"name\": \"OGU-NET\"}"
     # 25) "4294966272"
     # 26) "{\"asn\": \"8517\", \"country\": \"TR\", \"cidr\": \"193.140.120.0/22\", \"name\": \"OGU-NET\"}"


if __name__ == "__main__":
    # run("modules/whoisip/data/malicious_ips.txt", "modules/whoisip/data/malicious_ips_out.txt")
    try_random_addresses()
