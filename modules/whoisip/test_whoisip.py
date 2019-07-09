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


if __name__ == "__main__":
    run("modules/whoisip/data/malicious_ips.txt", "modules/whoisip/data/malicious_ips_out.txt")
