from slips_files.core.database.database import __database__
from slips_files.common.slips_utils import utils
import time
import ipaddress
import ipwhois
import json
import requests
import maxminddb

class ASN:
    def __init__(self):
        # Open the maxminddb ASN offline db
        try:
            self.asn_db = maxminddb.open_database(
                'databases/GeoLite2-ASN.mmdb'
            )
        except Exception:
            # errors are printed in IP_info
            pass

    def get_cached_asn(self, ip) -> dict:
        """
        If this ip belongs to a cached ip range, return the cached asn info of it
        :param ip: str
        if teh range of this ip was found, this function returns a dict with {'number' , 'org'}
        """
        cached_asn: dict = __database__.get_asn_cache()
        first_octet: str = utils.get_first_octet(ip)

        if not cached_asn or not first_octet:
            # invalid ip or no cached asns
            return False

        if first_octet not in cached_asn:
            return False

        for range, range_info in cached_asn[first_octet]:
            # convert to objects
            ip_range = ipaddress.ip_network(range)
            ip = ipaddress.ip_address(ip)
            if ip in ip_range:
                return range_info

    def update_asn(self, cached_data, update_period) -> bool:
        """
        Returns True if
        - no asn data is found in the db OR ip has no cached info
        - OR a month has passed since we last updated asn info in the db
        :param cached_data: ip cached info from the database, dict
        """
        try:
            update = (
                time.time() - cached_data['asn']['timestamp']
            ) > update_period
            return update
        except (KeyError, TypeError):
            # no there's no cached asn info,or no timestamp, or cached_data is None
            # we should update
            return True

    def get_asn_info_from_geolite(self, ip) -> dict:
        """
        Get ip info from geolite database
        :param ip: str
        return a dict with {'asn': {'asnorg':asnorg}}
        """
        ip_info = {}
        if not hasattr(self, 'asn_db'):
            return ip_info

        asninfo = self.asn_db.get(ip)

        try:
            # found info in geolite
            org = asninfo['autonomous_system_organization']
            number = f'AS{asninfo["autonomous_system_number"]}'
            ip_info['asn'] = {
                'org': org,
                'number': number
            }
        except (KeyError, TypeError):
            # asn info not found in geolite
            pass

        return ip_info

    def cache_ip_range(self, ip) -> bool:
        """
        Get the range of the given ip and
        cache the asn of the whole ip range
        """
        try:
            # Cache the range of this ip
            whois_info = ipwhois.IPWhois(address=ip).lookup_rdap()
            asnorg = whois_info.get('asn_description', False)
            asn_cidr = whois_info.get('asn_cidr', False)
            asn_number = whois_info.get('as', False)

            if asnorg and asn_cidr not in ('', 'NA'):
                __database__.set_asn_cache(asnorg, asn_cidr, asn_number)
            return True
        except (
            ipwhois.exceptions.IPDefinedError,
            ipwhois.exceptions.HTTPLookupError,
        ):
            # private ip or RDAP lookup failed. don't cache
            return False
        except ipwhois.exceptions.ASNRegistryError:
            # ASN lookup failed with no more methods to try
            pass


    def get_asn_online(self, ip):
        """
        Get asn of an ip using ip-api.com only if the asn wasn't found in our offline db
        """

        asn = {}
        if utils.is_ignored_ip(ip):
            return asn

        url = 'http://ip-api.com/json/'
        try:
            response = requests.get(f'{url}/{ip}', timeout=5)
            if response.status_code != 200:
                return asn

            ip_info = json.loads(response.text)
            if 'as' not in ip_info:
                return asn

            asn_info = ip_info['as'].split()
            # usually it's somthing like AS15169 Google LLC
            # separate the org name
            asn.update({
                'asn': {
                    'number': asn_info[0],
                    'org': " ".join(asn_info[1:])
                }
            })
            return asn
        except (
            requests.exceptions.ReadTimeout,
            requests.exceptions.ConnectionError,
            json.decoder.JSONDecodeError
        ):
            pass

        return asn

    def get_asn(self, ip, cached_ip_info):
        """Gets ASN info about IP, either cached, from our offline mmdb or from ip-api.com"""
        # do we have asn cached for this range?
        cached_asn: dict = self.get_cached_asn(ip)
        if cached_asn:
            # found cached asn for this ip range, store it
            cached_ip_info.update({
                'asn': {
                    'org': cached_asn['org'],
                    'number': cached_asn['number'],
                    'timestamp': time.time()
                }
            })
            __database__.setInfoForIPs(ip, cached_ip_info)

        # else:
        #     # we don't have it cached in our db, get it from geolite
        #     asn = self.get_asn_info_from_geolite(ip)
        #     if not asn:
        #         # can't find asn in mmdb
        #         asn = self.get_asn_online(ip)
        #         if asn:
        #             cached_ip_info.update(asn)
        #             # cache this range in our redis db
        #             self.cache_ip_range(ip)
        #
        #
        #     # store asn info in the db
        #     cached_ip_info['asn'].update({'timestamp': time.time()})
        #
        #     __database__.setInfoForIPs(ip, cached_ip_info)
