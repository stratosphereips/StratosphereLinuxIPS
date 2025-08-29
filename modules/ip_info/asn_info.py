# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import time
import ipaddress
import ipwhois
import json
import requests
import maxminddb

from slips_files.common.slips_utils import utils


class ASN:
    def __init__(self, db=None):
        self.db = db
        # update asn every 1 month
        self.update_period = 2592000

        # Open the maxminddb ASN offline db
        try:
            self.asn_db = maxminddb.open_database(
                "databases/GeoLite2-ASN.mmdb"
            )
        except Exception:
            # errors are printed in IP_info
            pass

    def get_cached_asn(self, ip):
        """
        If this ip belongs to a cached ip range, return the cached asn info of it
        :param ip: str
        if teh range of this ip was found, this function returns a dict with {'number' , 'org'}
        """
        first_octet: str = utils.get_first_octet(ip)
        if not first_octet:
            # invalid ip or no cached asns
            return

        cached_asn: str = self.db.get_asn_cache(first_octet=first_octet)
        if not cached_asn:
            return

        cached_asn: dict = json.loads(cached_asn)

        for range, range_info in cached_asn.items():
            # convert to objects
            ip_range = ipaddress.ip_network(range)
            ip = ipaddress.ip_address(ip)
            if ip in ip_range:
                asn_info = {
                    "asn": {
                        "org": range_info["org"],
                    }
                }
                if "number" in range_info:
                    asn_info["asn"].update({"number": range_info["number"]})
                return asn_info

    def should_update_asn(self, cached_data) -> bool:
        """
        Returns True if
        - no asn data is found in the db OR ip has no cached info
        - OR a month has passed since we last updated asn info in the db
        :param cached_data: ip cached info from the database, dict
        """
        try:
            return (
                time.time() - cached_data["asn"]["timestamp"]
            ) > self.update_period
        except (KeyError, TypeError):
            # no there's no cached asn info,or no timestamp, or
            # cached_data is None. we should update
            return True

    def get_asn_info_from_geolite(self, ip) -> dict:
        """
        Get ip info from geolite database
        :param ip: str
        return a dict with {'asn': {'org':.. , 'number': 'AS123'}}
        """
        ip_info = {}
        if not hasattr(self, "asn_db"):
            return ip_info

        asninfo = self.asn_db.get(ip)

        try:
            # found info in geolite
            org = asninfo["autonomous_system_organization"]
            number = f'AS{asninfo["autonomous_system_number"]}'

            ip_info["asn"] = {"org": org, "number": number}
        except (KeyError, TypeError):
            # asn info not found in geolite
            pass

        return ip_info

    def cache_ip_range(self, ip: str):
        """
        Get the range of the given ip and
        cache the asn of the whole ip range
        """
        if not ip:
            return False

        try:
            # Cache the range of this ip
            whois_info: dict = ipwhois.IPWhois(address=ip).lookup_rdap()
            asnorg = whois_info.get("asn_description", False)
            asn_cidr = whois_info.get("asn_cidr", False)
            asn_number = whois_info.get("asn", False)

            if asnorg and asn_cidr not in ("", "NA"):
                self.db.set_asn_cache(asnorg, asn_cidr, asn_number)
                asn_info = {
                    "asn": {"number": f"AS{asn_number}", "org": asnorg}
                }
                return asn_info
        except (
            ipwhois.exceptions.IPDefinedError,
            ipwhois.exceptions.HTTPLookupError,
            ipwhois.exceptions.ASNRegistryError,
            ipwhois.exceptions.ASNParseError,
            ipwhois.exceptions.HTTPRateLimitError,
        ):
            # private ip or RDAP lookup failed. don't cache
            # or ASN lookup failed with no more methods to try
            return False

    def get_asn_online(self, ip):
        """
        Get asn of an ip using ip-api.com only if the asn wasn't found in our offline db
        """

        asn = {}
        if utils.is_ignored_ip(ip):
            return asn

        url = "http://ip-api.com/json/"
        try:
            response = requests.get(f"{url}/{ip}", timeout=5)
            if response.status_code != 200:
                return asn

            ip_info = json.loads(response.text)
            if "as" not in ip_info:
                return asn

            asn_info = ip_info["as"].split()
            if asn_info == []:
                return

            # usually it's somthing like AS15169 Google LLC
            # separate the org name
            asn.update(
                {"asn": {"number": asn_info[0], "org": " ".join(asn_info[1:])}}
            )
            return asn
        except (
            requests.exceptions.ReadTimeout,
            requests.exceptions.ConnectionError,
            json.decoder.JSONDecodeError,
            KeyError,
            IndexError,
        ):
            # comes here if slips fails to get the as info from the response
            # OR gets it correctly, but the info doesn't contain the fields slip sis expecting
            pass

        return asn

    def update_ip_info(self, ip, cached_ip_info, asn: dict):
        """
        if an asn is found using this module, we update the IP's
        info in the db in 'IPsinfo' key with
        the ASN info we found
        asn is a dict with 2 keys 'number' and 'org'
        :param asn: new asn to add to the db. found by this module.
        :param cached_ip_info: old info from 'IPsInfo' key in the db
        """
        asn.update({"timestamp": time.time()})
        cached_ip_info.update(asn)
        # store the ASN we found in 'IPsInfo'
        self.db.set_ip_info(ip, cached_ip_info)

    def get_asn(self, ip, cached_ip_info):
        """
        Gets ASN info about IP, either cached, from our offline mmdb or
        from ip-api.com
        """
        # do we have asn cached for this range?
        if cached_asn := self.get_cached_asn(ip):
            self.update_ip_info(ip, cached_ip_info, cached_asn)
            return

        else:
            # now we have 2 options, either search for the ASN in our offline db, or online
            # either way we need to cache the asn of this ip's range so we don't search for ips in the same range
            # cache this range in our redis db
            if asn := self.cache_ip_range(ip):
                # range is cached and we managed to get the number and org of
                # the given ip using whois
                # no need to search online or offline
                self.update_ip_info(ip, cached_ip_info, asn)
                return

            # we don't have it cached in our db, get it from geolite
            if asn := self.get_asn_info_from_geolite(ip):
                self.update_ip_info(ip, cached_ip_info, asn)
                return

            # can't find asn in mmdb or using whois library, try using ip-info
            if asn := self.get_asn_online(ip):
                # found it online
                self.update_ip_info(ip, cached_ip_info, asn)
                return
