# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
from typing import (
    Dict,
    List,
    Tuple,
    Union,
    Optional,
)

from slips_files.common.data_structures.trie import Trie

# for future developers, remember to invalidate_trie_cache() on every
# change to the self.constants.IOC_DOMAINS key or slips will keep using an
# invalid cache to lookup malicious domains


class IoCHandler:
    """
    Helper class for the Redis class in database.py
    Contains all the logic related to setting and retrieving evidence and
    alerts in the db
    """

    name = "DB"

    def __init__(self):
        # used for faster domain lookups
        self.trie = None
        self.is_trie_cached = False

    def _build_trie(self):
        """Retrieve domains from Redis and construct the trie."""
        self.trie = Trie()
        ioc_domains: Dict[str, str] = self.rcache.hgetall(
            self.constants.IOC_DOMAINS
        )
        for domain, domain_info in ioc_domains.items():
            domain: str
            domain_info: str
            # domain_info is something like this
            # {"description": "['hack''malware''phishing']",
            # "source": "OCD-Datalake-russia-ukraine_IOCs-ALL.csv",
            # "threat_level": "medium",
            # "tags": ["Russia-UkraineIoCs"]}

            # store parsed domain info
            self.trie.insert(domain, json.loads(domain_info))
        self.is_trie_cached = True

    def _invalidate_trie_cache(self):
        """
        Invalidate the trie cache.
        used whenever IOC_DOMAINS key is updated.
        """
        self.trie = None
        self.is_trie_cached = False

    def set_loaded_ti_files(self, number_of_loaded_files: int):
        """
        Stores the number of successfully loaded TI files
        """
        self.r.set(self.constants.LOADED_TI_FILES, number_of_loaded_files)

    def get_loaded_ti_feeds_number(self):
        """
        returns the number of successfully loaded TI files. or 0 if none is loaded
        """
        return self.r.get(self.constants.LOADED_TI_FILES) or 0

    def delete_feed_entries(self, url: str):
        """
        Delete all entries in
         IoC_domains and IoC_ips that contain the given feed as source
        """
        # get the feed name from the given url
        feed_to_delete = url.split("/")[-1]
        # get all domains that are read from TI files in our db
        ioc_domains = self.rcache.hgetall(self.constants.IOC_DOMAINS)
        for domain, domain_description in ioc_domains.items():
            domain_description = json.loads(domain_description)
            if feed_to_delete in domain_description["source"]:
                # this entry has the given feed as source, delete it
                self.rcache.hdel(self.constants.IOC_DOMAINS, domain)
                self._invalidate_trie_cache()

        # get all IPs that are read from TI files in our db
        ioc_ips = self.rcache.hgetall(self.constants.IOC_IPS)
        for ip, ip_description in ioc_ips.items():
            ip_description = json.loads(ip_description)
            if feed_to_delete in ip_description["source"]:
                # this entry has the given feed as source, delete it
                self.rcache.hdel(self.constants.IOC_IPS, ip)

    def delete_ti_feed(self, file):
        self.rcache.hdel(self.constants.TI_FILES_INFO, file)

    def get_loaded_ti_feeds(self):
        """
        returns the successfully loaded/cached TI files.
        """
        return self.rcache.hgetall(self.constants.TI_FILES_INFO)

    def set_feed_last_update_time(self, file: str, time: float):
        """
        sets the 'time' of last update of the given file
        :param file: ti file
        """
        if file_info := self.rcache.hget(self.constants.TI_FILES_INFO, file):
            # update an existin time
            file_info = json.loads(file_info)
            file_info.update({"time": time})
            self.rcache.hset(
                self.constants.TI_FILES_INFO, file, json.dumps(file_info)
            )
            return

        # no cached info about this file
        self.rcache.hset(
            self.constants.TI_FILES_INFO, file, json.dumps({"time": time})
        )

    def get_ti_feed_info(self, file):
        """
        Get TI file info
        :param file: a valid filename not a feed url
        """
        data = self.rcache.hget(self.constants.TI_FILES_INFO, file)
        return json.loads(data) if data else {}

    def give_threat_intelligence(
        self,
        profileid,
        twid,
        ip_state,
        starttime,
        uid,
        daddr,
        proto=False,
        lookup="",
        extra_info: dict = False,
    ):
        data_to_send = {
            "to_lookup": str(lookup),
            "profileid": str(profileid),
            "twid": str(twid),
            "proto": str(proto),
            "ip_state": ip_state,
            "stime": starttime,
            "uid": uid,
            "daddr": daddr,
        }
        if extra_info:
            # sometimes we want to send the dns query/answer to check it for
            # blacklisted ips/domains
            data_to_send.update(extra_info)
        self.publish(self.constants.GIVE_TI, json.dumps(data_to_send))
        return data_to_send

    def set_ti_feed_info(self, file, data):
        """
        Set/update time and/or e-tag for TI file
        :param file: a valid filename not a feed url
        :param data: dict containing info about TI file
        """
        data = json.dumps(data)
        self.rcache.hset(self.constants.TI_FILES_INFO, file, data)

    def store_known_fp_md5_hashes(self, fps: Dict[str, List[str]]):
        self.rcache.hmset(self.constants.KNOWN_FPS, fps)

    def is_known_fp_md5_hash(self, hash: str) -> Optional[str]:
        """returns the description of the given hash if it is a FP. and
        returns Fals eif the hash is not a FP"""
        return self.rcache.hmget(self.constants.KNOWN_FPS, hash)

    def delete_ips_from_ioc_ips(self, ips: List[str]):
        """
        Delete the given IPs from IoC
        """
        self.rcache.hdel(self.constants.IOC_IPS, *ips)

    def delete_domains_from_ioc_domains(self, domains: List[str]):
        """
        Delete old domains from IoC
        """
        self.rcache.hdel(self.constants.IOC_DOMAINS, *domains)
        self._invalidate_trie_cache()

    def add_ips_to_ioc(self, ips_and_description: Dict[str, str]) -> None:
        """
        Store a group of IPs in the db as they were obtained from an IoC source
        :param ips_and_description: is {ip: json.dumps{'source':..,
                                                        'tags':..,
                                                        'threat_level':... ,
                                                        'description':...}}

        """
        if ips_and_description:
            self.rcache.hmset(self.constants.IOC_IPS, ips_and_description)

    def add_domains_to_ioc(self, domains_and_description: dict) -> None:
        """
        Store a group of domains in the db as they were obtained from
        an IoC source
        :param domains_and_description: is
        {domain: json.dumps{'source':..,'tags':..,
            'threat_level':... ,'description'}}
        """
        if domains_and_description:
            self.rcache.hmset(
                self.constants.IOC_DOMAINS, domains_and_description
            )
            self._invalidate_trie_cache()

    def add_ip_range_to_ioc(self, malicious_ip_ranges: dict) -> None:
        """
        Store a group of IP ranges in the db as they were obtained from an IoC source
        :param malicious_ip_ranges: is
        {range: json.dumps{'source':..,'tags':..,
         'threat_level':... ,'description'}}
        """
        if malicious_ip_ranges:
            self.rcache.hmset(
                self.constants.IOC_IP_RANGES, malicious_ip_ranges
            )

    def add_asn_to_ioc(self, blacklisted_ASNs: dict):
        """
        Store a group of ASN in the db as they were obtained from an IoC source
        :param blacklisted_ASNs: is
        {asn: json.dumps{'source':..,'tags':..,
            'threat_level':... ,'description'}}
        """
        if blacklisted_ASNs:
            self.rcache.hmset(self.constants.IOC_ASN, blacklisted_ASNs)

    def add_ja3_to_ioc(self, ja3: dict) -> None:
        """
        Store the malicious ja3 iocs in the db
        :param ja3:  {ja3: {'source':..,'tags':..,
                            'threat_level':... ,'description'}}

        """
        self.rcache.hmset(self.constants.IOC_JA3, ja3)

    def add_jarm_to_ioc(self, jarm: dict) -> None:
        """
        Store the malicious jarm iocs in the db
        :param jarm:  {jarm: {'source':..,'tags':..,
                            'threat_level':... ,'description'}}
        """
        self.rcache.hmset(self.constants.IOC_JARM, jarm)

    def add_ssl_sha1_to_ioc(self, malicious_ssl_certs):
        """
        Store a group of ssl fingerprints in the db
        :param malicious_ssl_certs:  {sha1: {'source':..,'tags':..,
                                    'threat_level':... ,'description'}}
        """
        self.rcache.hmset(self.constants.IOC_SSL, malicious_ssl_certs)

    def is_blacklisted_asn(self, asn) -> bool:
        return self.rcache.hget(self.constants.IOC_ASN, asn)

    def is_blacklisted_jarm(self, jarm_hash: str):
        """
        search for the given hash in the malicious hashes stored in the db
        """
        return self.rcache.hget(self.constants.IOC_JARM, jarm_hash)

    def is_blacklisted_ip(self, ip: str) -> Union[Dict[str, str], bool]:
        """
        Search in the dB of malicious IPs and return a
        description if we found a match
        returns a dict like this
            {"description": "1.4858919389330276e-05",
            "source": "AIP_attackers.csv",
            "threat_level": "medium",
            "tags": ["phishing honeypot"]}

        """
        ip_info: str = self.rcache.hget(self.constants.IOC_IPS, ip)
        return False if ip_info is None else json.loads(ip_info)

    def is_blacklisted_ssl(self, sha1):
        info = self.rcache.hmget(self.constants.IOC_SSL, sha1)[0]
        return False if info is None else info

    def _match_exact_domain(self, domain: str) -> Optional[Dict[str, str]]:
        """checks if the given domain is blacklisted.
        checks only the exact given domain, no subdomains"""
        domain_description = self.rcache.hget(
            self.constants.IOC_DOMAINS, domain
        )
        if not domain_description:
            return
        return json.loads(domain_description)

    def _match_subdomain(self, domain: str) -> Optional[Dict[str, str]]:
        """
        Checks if we have any blacklisted domain that is a part of the
        given domain
        Uses a cached trie for optimization.
        """
        # the goal here is we dont retrieve that huge amount of domains
        # from the db on every domain lookup
        # so we retrieve once, put em in a trie (aka cache them in memory),
        # keep using them from that data structure until a new domain is
        # added to the db, when that happens we invalidate the cache,
        # rebuild the trie, and keep using it from there.
        if not self.is_trie_cached:
            self._build_trie()

        found, domain_info = self.trie.search(domain)
        if found:
            return domain_info

    def is_blacklisted_domain(
        self, domain: str
    ) -> Union[Tuple[Dict[str, str], bool], bool]:
        """
        Check if the given domain or its subdomain is blacklisted.
        returns a tuple (description, is_subdomain)
        description: description of the subdomain if found
        bool: True if we found a match for exactly the given
        domain False if we matched a subdomain
        """
        if match := self._match_exact_domain(domain):
            is_subdomain = False
            return match, is_subdomain

        if match := self._match_subdomain(domain):
            is_subdomain = True
            return match, is_subdomain
        return False, False

    def get_all_blacklisted_ip_ranges(self) -> dict:
        """
        Returns all the malicious ip ranges we have from different feeds
        return format is {range: json.dumps{'source':..,'tags':..,
                                            'threat_level':... ,'description'}}
        """
        return self.rcache.hgetall(self.constants.IOC_IP_RANGES)

    def get_all_blacklisted_ips(self):
        """
        Get all IPs and their description from IoC_ips
        """
        return self.rcache.hgetall(self.constants.IOC_IPS)

    def get_all_blacklisted_domains(self):
        """
        Get all Domains and their description from IoC_domains
        """
        return self.rcache.hgetall(self.constants.IOC_DOMAINS)

    def get_all_blacklisted_ja3(self):
        """
        Get all ja3 and their description from IoC_JA3
        """
        return self.rcache.hgetall(self.constants.IOC_JA3)

    def is_profile_malicious(self, profileid: str) -> str:
        return (
            self.r.hget(profileid, self.constants.LABELED_AS_MALICIOUS)
            if profileid
            else False
        )

    def is_cached_url_by_vt(self, url):
        """
        Return information about this URL
        Returns a dictionary or False if there is no IP in the database
        We need to separate these three cases:
        1- IP is in the DB without data. Return empty dict.
        2- IP is in the DB with data. Return dict.
        3- IP is not in the DB. Return False
        this is used to cache url info by the virustotal module only
        """
        data = self.rcache.hget(self.constants.VT_CACHED_URL_INFO, url)
        data = json.loads(data) if data else False
        return data

    def _store_new_url(self, url: str):
        """
        1- Stores this new URL in the URLs hash
        2- Publishes in the channels that there is a new URL, and that we want
            data from the Threat Intelligence modules
        """
        data = self.is_cached_url_by_vt(url)
        if data is False:
            # If there is no data about this URL
            # Set this URL for the first time in the virustotal_cached_url_info
            # Its VERY important that the data of the first time we see a URL
            # must be '{}', an empty dictionary! if not the logic breaks.
            # We use the empty dictionary to find if an URL exists or not
            self.rcache.hset(self.constants.VT_CACHED_URL_INFO, url, "{}")

    def get_domain_data(self, domain):
        """
        Return information about this domain
        Returns a dictionary or False if there is no domain in the database
        We need to separate these three cases:
        1- Domain is in the DB without data. Return empty dict.
        2- Domain is in the DB with data. Return dict.
        3- Domain is not in the DB. Return False
        """
        data = self.rcache.hget(self.constants.DOMAINS_INFO, domain)
        data = json.loads(data) if data or data == {} else False
        return data

    def _set_new_domain(self, domain: str):
        """
        1- Stores this new domain in the Domains hash
        2- Publishes in the channels that there is a new domain, and that we want
            data from the Threat Intelligence modules
        """
        data = self.get_domain_data(domain)
        if data is False:
            # If there is no data about this domain
            # Set this domain for the first time in the DomainsInfo
            # Its VERY important that the data of the first time we see a domain
            # must be '{}', an empty dictionary! if not the logic breaks.
            # We use the empty dictionary to find if a domain exists or not
            self.rcache.hset(self.constants.DOMAINS_INFO, domain, "{}")

    def set_info_for_domains(
        self, domain: str, info_to_set: dict, mode="leave"
    ):
        """
        Store information for this domain
        :param info_to_set: a dictionary, such as
        {'geocountry': 'rumania'} that we are going to store for this domain
        :param mode: defines how to deal with the new data
        - to 'overwrite' the data with the new data
        - to 'add' the old data to the new data
        - to 'leave' the past data untouched
        """

        # Get the previous info already stored
        domain_data = self.get_domain_data(domain)
        if not domain_data:
            # This domain is not in the dictionary, add it first:
            self._set_new_domain(domain)
            # Now get the data, which should be empty, but just in case
            domain_data = self.get_domain_data(domain)

        # Let's check each key stored for this domain
        for key in iter(info_to_set):
            # info_to_set can be {'VirusTotal': [1,2,3,4], 'Malicious': ""}
            # info_to_set can be {'VirusTotal': [1,2,3,4]}

            # I think we dont need this anymore of the conversion
            if isinstance(domain_data, str):
                # Convert the str to a dict
                domain_data = json.loads(domain_data)

            # this can be a str or a list
            data_to_store = info_to_set[key]
            # If there is data previously stored, check if we have
            # this key already
            try:
                # Do we have the key alredy?
                _ = domain_data[key]

                # convert incoming data to list
                if not isinstance(data_to_store, list):
                    # data_to_store and prev_info Should both be lists, so we can extend
                    data_to_store = [data_to_store]

                if mode == "overwrite":
                    domain_data[key] = data_to_store
                elif mode == "add":
                    prev_info = domain_data[key]

                    if isinstance(prev_info, list):
                        # for example, list of IPs
                        prev_info.extend(data_to_store)
                        domain_data[key] = list(set(prev_info))
                    elif isinstance(prev_info, str):
                        # previous info about this domain is a str, we should
                        # make it a list and extend
                        prev_info = [prev_info]
                        # add the new data_to_store to our prev_info
                        domain_data[key] = prev_info.extend(data_to_store)
                    elif prev_info is None:
                        # no previous info about this domain
                        domain_data[key] = data_to_store

                elif mode == "leave":
                    return

            except KeyError:
                # There is no data for the key so far. Add it
                if isinstance(data_to_store, list):
                    domain_data[key] = list(set(data_to_store))
                else:
                    domain_data[key] = data_to_store
            # Store
            domain_data = json.dumps(domain_data)
            self.rcache.hset(self.constants.DOMAINS_INFO, domain, domain_data)
            self.r.publish(self.channels.DNS_INFO_CHANGE, domain)

    def cache_url_info_by_virustotal(self, url: str, urldata: dict):
        """
        Store information for this URL
        We receive a dictionary, such as {'VirusTotal': {'URL':score}} that we are
        going to store for this IP.
        If it was not there before we store it. If it was there before, we
        overwrite it
        this is used to cache url info by the virustotal module only
        """
        data = self.is_cached_url_by_vt(url)
        if data is False:
            # This URL is not in the dictionary, add it first:
            self._store_new_url(url)
            # Now get the data, which should be empty, but just in case
            data = self.get_ip_info(url)
        # empty dicts evaluate to False
        dict_has_keys = bool(data)
        if dict_has_keys:
            # loop through old data found in the db
            for key in iter(data):
                # Get the new data that has the same key
                data_to_store = urldata[key]
                # If there is data previously stored, check if we have this key already
                try:
                    # We modify value in any case, because there might be new info
                    _ = data[key]
                except KeyError:
                    # There is no data for the key so far.
                    pass
                    # Publish the changes
                    # self.r.publish('url_info_change', url)
                data[key] = data_to_store
                newdata_str = json.dumps(data)
                self.rcache.hset(
                    self.constants.VT_CACHED_URL_INFO, url, newdata_str
                )
        else:
            # URL found in the database but has no keys , set the keys now
            urldata = json.dumps(urldata)
            self.rcache.hset(self.constants.VT_CACHED_URL_INFO, url, urldata)
