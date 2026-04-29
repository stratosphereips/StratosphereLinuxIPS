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

    @staticmethod
    def _create_bloom_filter(
        values, minimum_capacity: int, error_rate: float
    ) -> BloomFilter:
        """
        Create and populate a bloom filter sized for the given values.

        :param values: Iterable of values that will be inserted.
        :param minimum_capacity: Lower bound used for small datasets.
        :param error_rate: Bloom filter false-positive rate.
        :return: A populated BloomFilter.
        """
        items = tuple(values)
        capacity = max(minimum_capacity, len(items) + 1)
        bloom_filter = BloomFilter(capacity=capacity, error_rate=error_rate)
        for item in items:
            bloom_filter.add(item)
        return bloom_filter

    def initialize_filter(self):
        self._init_whitelisted_iocs_bf()
        self._init_whitelisted_orgs_bf()

    def _init_whitelisted_iocs_bf(self):
        err_rate = 0.001
        self.ips = self._create_bloom_filter(
            self.db.get_whitelist("IPs"), 10000, err_rate
        )
        self.domains = self._create_bloom_filter(
            self.db.get_whitelist("domains"), 10000, err_rate
        )
        self.orgs = self._create_bloom_filter(
            self.db.get_whitelist("organizations"), 100, err_rate
        )
        self.mac_addrs = self._create_bloom_filter(
            self.db.get_whitelist("macs"), 10000, err_rate
        )

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
            domains_bloom = self._create_bloom_filter(
                domains, 10000, err_rate
            )

            asns: List[str] = self.db.get_org_info(org, "asn")
            asns_bloom = self._create_bloom_filter(asns, 10000, err_rate)

            org_subnets: Dict[str, str] = self.db.get_org_ips(org)
            cidrs_bloom = self._create_bloom_filter(
                org_subnets.keys(), 100, err_rate
            )

            self.org_filters[org] = {
                "domains": domains_bloom,
                "asns": asns_bloom,
                "first_octets": cidrs_bloom,
            }
