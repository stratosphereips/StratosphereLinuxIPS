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
            self.logger,
            self.output_dir,
            self.redis_port,
            self.conf,
            self.ppid,
        )
        self.org_filters = {}

    def initialize_filter(self):
        self._init_whitelisted_iocs_bf()
        self._init_whitelisted_orgs_bf()

    def _create_bloom_filter(self, items, error_rate: float) -> BloomFilter:
        """
        Create a bloom filter sized for the provided items.

        Parameters:
            items: Iterable of values to store in the bloom filter.
            error_rate: Desired bloom filter false-positive rate.

        Returns:
            BloomFilter populated with the given items.
        """
        unique_items = tuple(dict.fromkeys(items))
        bloom = BloomFilter(
            capacity=max(len(unique_items), 1), error_rate=error_rate
        )
        for item in unique_items:
            bloom.add(item)
        return bloom

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
        is called from feeds_update_manager whether slips did update its local
        org files or not.
        this goal of calling this is to make sure slips has the bloom
        filters in mem at all times.
        """
        err_rate = 0.01
        for org in utils.supported_orgs:
            domains: List[str] = self.db.get_org_info(org, "domains")
            asns: List[str] = self.db.get_org_info(org, "asn")
            org_subnets: Dict[str, str] = self.db.get_org_ips(org)

            self.org_filters[org] = {
                "domains": self._create_bloom_filter(domains, err_rate),
                "asns": self._create_bloom_filter(asns, err_rate),
                "first_octets": self._create_bloom_filter(
                    org_subnets.keys(), err_rate
                ),
            }
