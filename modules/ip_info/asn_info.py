# Must imports
from slips_files.core.database.database import __database__
from slips_files.common.config_parser import ConfigParser


# Your imports
import time
import ipaddress
import ipwhois
import json
import requests
import maxminddb

# from dns.resolver import NoResolverConfiguration


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

    def get_cached_asn(self, ip):
        """
        If this ip belongs to a cached ip range, return the cached asn info of it
        :param ip: str
        """
        cached_asn = __database__.get_asn_cache()
        try:
            for asn, asn_range in cached_asn.items():
                # convert to objects
                ip_range = ipaddress.ip_network(asn_range)
                try:
                    ip = ipaddress.ip_address(ip)
                except ValueError:
                    # not a valid ip
                    break
                if ip in ip_range:
                    return asn
        except AttributeError:
            # cached_asn is not found
            return False

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
        if not hasattr(self, 'asn_db'):
            return {'asn': {'asnorg': 'Unknown'}}

        asninfo = self.asn_db.get(ip)
        data = {}
        try:
            # found info in geolite
            asnorg = asninfo['autonomous_system_organization']
            data['asn'] = {'asnorg': asnorg}
        except (KeyError, TypeError):
            # asn info not found in geolite
            data['asn'] = {'asnorg': 'Unknown'}

        return data

    def cache_ip_range(self, ip) -> bool:
        """
        Get the range of the given ip and
        caches the asn of the whole ip range
        """
        try:
            # Cache the range of this ip
            whois_info = ipwhois.IPWhois(address=ip).lookup_rdap()
            asnorg = whois_info.get('asn_description', False)
            asn_cidr = whois_info.get('asn_cidr', False)
            if asnorg and asn_cidr not in ('', 'NA'):
                __database__.set_asn_cache(asnorg, asn_cidr)
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

        asn = {'asn': {'asnorg': 'Unknown'}}
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private or ip_obj.is_multicast:
            return asn

        url = 'http://ip-api.com/json/'
        try:
            response = requests.get(f'{url}/{ip}', timeout=5)
            if response.status_code == 200:
                ip_info = json.loads(response.text)
                if ip_info.get('as', '') != '':
                    asn['asn']['asnorg'] = ip_info['as']
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
        cached_asn = self.get_cached_asn(ip)
        if not cached_asn:
            # we don't have it cached in our db, get it from geolite
            asn = self.get_asn_info_from_geolite(ip)
            if asn['asn']['asnorg'] == 'Unknown':
                # can't find asn in mmdb
                asn = self.get_asn_online(ip)
            cached_ip_info.update(asn)
            # cache this range in our redis db
            self.cache_ip_range(ip)
        else:
            # found cached asn for this ip range, store it
            cached_ip_info.update({'asn': {'asnorg': cached_asn}})

        # store asn info in the db
        cached_ip_info['asn'].update({'timestamp': time.time()})

        __database__.setInfoForIPs(ip, cached_ip_info)
