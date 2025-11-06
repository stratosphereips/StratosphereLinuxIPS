# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
from typing import List

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
        is called from update_manager whether slips did update its local
        org files or not.
        this goal of calling this is to make sure slips has the bloom
        filters in mem at all times.
        """
        for org in utils.supported_orgs:
            domains_bloom = BloomFilter(capacity=10000, error_rate=0.001)
            asns_bloom = BloomFilter(capacity=10000, error_rate=0.001)
            cidrs_bloom = BloomFilter(capacity=100, error_rate=0.001)

            domains: List[str] = json.loads(
                self.db.get_org_info(org, "domains")
            )
            for domain in domains:
                domains_bloom.add(domain)

            asns: List[str] = json.loads(self.db.get_org_info(org, "asn"))
            for asn in asns:
                asns_bloom.add(asn)

            org_subnets: dict = self.db.get_org_ips(org)
            for first_octet in org_subnets:
                cidrs_bloom.add(first_octet)

            self.org_filters[org] = {
                "domains": domains_bloom,
                "asns": asns_bloom,
                "first_octets": cidrs_bloom,
            }
