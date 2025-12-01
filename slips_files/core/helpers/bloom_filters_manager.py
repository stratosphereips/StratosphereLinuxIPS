# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from typing import List, Dict

from pybloom_live import BloomFilter

from slips_files.common.slips_utils import utils
from slips_files.core.database.database_manager import DBManager
from slips_files.core.output import Output


class BFManager:
    def __init__(
        self,
        logger: Output,
        output_dir,
        redis_port,
        conf,
        ppid: int,
    ):
        self.redis_port = redis_port
        self.output_dir = output_dir
        self.logger = logger
        self.conf = conf
        # the parent pid of this module, used for strating the db
        self.ppid = ppid
        self.db = DBManager(
            self.logger, self.output_dir, self.redis_port, self.conf, self.ppid
        )
        self.org_filters = {}

    def initialize_filter(self):
        self._init_whitelisted_iocs_bf()
        self._init_whitelisted_orgs_bf()

    def _init_whitelisted_iocs_bf(self):
        self.domains = BloomFilter(capacity=10000, error_rate=0.001)
        self.ips = BloomFilter(capacity=10000, error_rate=0.001)
        self.mac_addrs = BloomFilter(capacity=10000, error_rate=0.001)
        self.orgs = BloomFilter(capacity=100, error_rate=0.001)

        for ip in self.db.get_whitelist("IPs"):
            self.ips.add(ip)

        for domain in self.db.get_whitelist("domains"):
            self.domains.add(domain)

        for org in self.db.get_whitelist("organizations"):
            self.orgs.add(org)

        for mac in self.db.get_whitelist("macs"):
            self.mac_addrs.add(mac)

    def _init_whitelisted_orgs_bf(self):
        """
        Updates the bloom filters with the whitelisted organization
        domains, asns, and ips
        fills the self.org_filters dict
        is called from update_manager whether slips did update its local
        org files or not.
        this goal of calling this is to make sure slips has the bloom
        filters in mem at all times.
        """
        err_rate = 0.01
        for org in utils.supported_orgs:
            domains_bloom = BloomFilter(capacity=10000, error_rate=err_rate)
            asns_bloom = BloomFilter(capacity=10000, error_rate=err_rate)
            cidrs_bloom = BloomFilter(capacity=100, error_rate=err_rate)

            domains: List[str] = self.db.get_org_info(org, "domains")
            _ = [domains_bloom.add(domain) for domain in domains]

            asns: List[str] = self.db.get_org_info(org, "asn")
            _ = [asns_bloom.add(asn) for asn in asns]

            org_subnets: Dict[str, str] = self.db.get_org_ips(org)
            _ = [
                cidrs_bloom.add(first_octet)
                for first_octet in org_subnets.keys()
            ]

            self.org_filters[org] = {
                "domains": domains_bloom,
                "asns": asns_bloom,
                "first_octets": cidrs_bloom,
            }
