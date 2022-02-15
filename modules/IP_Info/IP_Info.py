# Must imports
from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database import __database__
from slips_files.common.slips_utils import utils
import platform
import sys

# Your imports
import time
import maxminddb
import ipaddress
import ipwhois
import socket
import json
from dns.resolver import NoResolverConfiguration
#todo add to conda env

class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'IP_Info'
    description = 'Get different info about an IP/MAC address'
    authors = ['Alya Gomaa', 'Sebastian Garcia']

    def __init__(self, outputqueue, config):
        multiprocessing.Process.__init__(self)
        # All the printing output should be sent to the outputqueue. The outputqueue is connected to another process called OutputProcess
        self.outputqueue = outputqueue
        # In case you need to read the slips.conf configuration file for your own configurations
        self.config = config
        # Start the redis DB
        __database__.start(self.config)
        # open mmdbs
        self.open_dbs()
        # Set the output queue of our database instance
        __database__.setOutputQueue(self.outputqueue)
        # To which channels do you wnat to subscribe? When a message arrives on the channel the module will wakeup
        self.c1 = __database__.subscribe('new_ip')
        self.c2 = __database__.subscribe('new_MAC')
        self.timeout = 0.0000001
        # update asn every 1 month
        self.update_period = 2592000
    
    def open_dbs(self):
        """ Function to open the different offline databases used in this module. ASN, Country etc.. """
        
        # Open the maxminddb ASN offline db 
        try:
            self.asn_db = maxminddb.open_database('databases/GeoLite2-ASN.mmdb')
        except:
            self.print('Error opening the geolite2 db in databases/GeoLite2-ASN.mmdb. Please download it from https://dev.maxmind.com/geoip/docs/databases/asn?lang=en Please note it must be the MaxMind DB version.')
        
        # Open the maminddb Country offline db
        try:
            self.country_db = maxminddb.open_database('databases/GeoLite2-Country.mmdb')
        except:
            self.print('Error opening the geolite2 db in databases/GeoLite2-Country.mmdb. Please download it from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data?lang=en. Please note it must be the MaxMind DB version.')
        
        try:
            self.mac_db = open('databases/macaddress-db.json','r')
        except OSError:
            self.print('Error opening the macaddress db in databases/macaddress-db.json. Please download it from https://macaddress.io/database-download/json.')

    def print(self, text, verbose=1, debug=0):
        """
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by taking all the processes into account
        :param verbose:
            0 - don't print
            1 - basic operation/proof of work
            2 - log I/O operations and filenames
            3 - log database/profile/timewindow changes
        :param debug:
            0 - don't print
            1 - print exceptions
            2 - unsupported and unhandled types (cases that may cause errors)
            3 - red warnings that needs examination - developer warnings
        :param text: text to print. Can include format like 'Test {}'.format('here')
        """

        levels = f'{verbose}{debug}'
        self.outputqueue.put(f"{levels}|{self.name}|{text}")

    # ASN functions
    def get_cached_asn(self, ip):
        """
        If this ip belongs to a cached ip range, return the cached asn info of it
        :param ip: str
        """
        cached_asn = __database__.get_asn_cache()
        try:
            for asn,asn_range in cached_asn.items():
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

    def update_asn(self, cached_data) -> bool:
        """
        Returns True if
        - no asn data is found in the db OR ip has no cached info
        - OR a month has passed since we last updated asn info in the db
        :param cached_data: ip cached info from the database, dict
        """
        try:
            update = (time.time() - cached_data['asn']['timestamp']) > self.update_period
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
        except (KeyError,TypeError):
            # asn info not found in geolite
            data['asn'] ={'asnorg': 'Unknown'}

        return data

    def cache_ip_range(self, ip) -> bool:
        """ caches the asn of current ip range """
        try:
            # Cache the range of this ip
            whois_info = ipwhois.IPWhois(address=ip).lookup_rdap()
            asnorg = whois_info.get('asn_description', False)
            asn_cidr = whois_info.get('asn_cidr', False)
            if asnorg and asn_cidr not in ('' , 'NA'):
                __database__.set_asn_cache(asnorg, asn_cidr)
            return True
        except (ipwhois.exceptions.IPDefinedError,ipwhois.exceptions.HTTPLookupError):
            # private ip or RDAP lookup failed. don't cache
            return False
        except NoResolverConfiguration:
            # Resolver configuration could not be read or specified no nameservers
            self.print('Error: Resolver configuration could not be read or specified no nameservers.')
            return False
        except ipwhois.exceptions.ASNRegistryError:
            # ASN lookup failed with no more methods to try
            pass
        except dns.resolver.NoResolverConfiguration:
            # ipwhois can't read /etc/resolv.conf
            # manually specify the dns server
            # ignore resolv.conf
            dns.resolver.default_resolver=dns.resolver.Resolver(configure=False)
            # use google's DNS
            dns.resolver.default_resolver.nameservers=['8.8.8.8']
            return False

    def get_asn(self, ip, cached_ip_info):
        """ Gets ASN info about IP, either cached or from our offline mmdb """

        # do we have asn cached for this range?
        cached_asn = self.get_cached_asn(ip)
        if not cached_asn:
            # we don't have it cached in our db, get it from geolite
            asn = self.get_asn_info_from_geolite(ip)
            cached_ip_info.update(asn)
            # cache this range in our redis db
            self.cache_ip_range(ip)
        else:
            # found cached asn for this ip range, store it
            cached_ip_info.update({'asn' : {'asnorg': cached_asn}})

        # store asn info in the db
        cached_ip_info['asn'].update({'timestamp': time.time()})

        __database__.setInfoForIPs(ip, cached_ip_info)

    # GeoInfo functions
    def get_geocountry(self, ip) -> dict:
        """
        Get ip geocountry from geolite database
        :param ip: str
        """
        if not hasattr(self, 'country_db'):
            return False

        geoinfo = self.country_db.get(ip)
        if geoinfo:
            try:
                countrydata = geoinfo['country']
                countryname = countrydata['names']['en']
                data = {'geocountry': countryname}
            except KeyError:
                data = {'geocountry': 'Unknown'}

        elif ipaddress.ip_address(ip).is_private:
            # Try to find if it is a local/private IP
            data = {'geocountry': 'Private'}
        else:
            data = {'geocountry': 'Unknown'}
        __database__.setInfoForIPs(ip, data)
        return data

    # RDNS functions
    def get_ip_family(self, ip):
        """
        returns the family of the IP, AF_INET or AF_INET6
        :param ip: str
        """
        if ':' in ip:
            return socket.AF_INET6
        return socket.AF_INET

    def get_rdns(self, ip):
        """
        get reverse DNS of an ip
        returns RDNS of the given ip or False if not found
        :param ip: str
        """
        data = {}
        try:
            # works with both ipv4 and ipv6
            reverse_dns = socket.gethostbyaddr(ip)[0]
            # if there's no reverse dns record for this ip, reverse_dns will be an ip.
            try:
                # reverse_dns is an ip and there's no reverse dns, don't store
                socket.inet_pton(self.get_ip_family(reverse_dns), reverse_dns)
                return False
            except socket.error:
                # all good, store it
                data['reverse_dns'] = reverse_dns
                __database__.setInfoForIPs(ip, data)
        except (socket.gaierror, socket.herror, OSError):
            # not an ip or multicast, can't get the reverse dns record of it
            return False
        return data

    # MAC functions
    def get_vendor(self, mac_addr: str, host_name: str, profileid: str):
        """
        Get vendor info of a MAC address from our offline database and add it to this profileid info in the database
        """
        if (not hasattr(self, 'mac_db')
                or 'ff:ff:ff:ff:ff:ff' in mac_addr.lower()
                or '00:00:00:00:00:00' in mac_addr.lower()):
            return False

        # don't look for the vendor again if we already have it for this profileid
        MAC_vendor = __database__.get_mac_vendor_from_profile(profileid)
        if MAC_vendor:
            return True

        MAC_info = {'MAC': mac_addr}
        if host_name:
            MAC_info.update({'host_name': host_name})

        oui = mac_addr[:8].upper()
        # parse the mac db and search for this oui
        self.mac_db.seek(0)
        while True:
            line = self.mac_db.readline()
            if line =='':
                # reached the end of file without finding the vendor
                # set the vendor to unknown to avoid searching for it again
                MAC_info.update({'Vendor': 'Unknown'})
                break

            if oui in line:
                line = json.loads(line)
                vendor = line['companyName']
                MAC_info.update({'Vendor': vendor})
                break

        # some cases we have ipv4 and ipv6 on the same computer, they should be associated with the same mac
        # and both profiles should be aware of both IPs
        __database__.search_for_profile_with_the_same_MAC(profileid, mac_addr)

        # either we found the vendor or not, store the mac of this ip to the db
        __database__.add_mac_addr_to_profile(profileid, MAC_info)
        return MAC_info

    def close_dbs(self):
        """ function to close the databases when there's an error or when shutting down"""
        if hasattr(self, 'asn_db'): self.asn_db.close()
        if hasattr(self, 'country_db'): self.country_db.close()
        if hasattr(self, 'mac_db'): self.mac_db.close()

    def run(self):
        # Main loop function
        while True:
            try:
                message = self.c1.get_message(timeout=self.timeout)
                # if timewindows are not updated for a long time (see at logsProcess.py),
                # we will stop slips automatically.The 'stop_process' line is sent from logsProcess.py.
                if message and message['data'] == 'stop_process':
                    self.close_dbs()
                    # confirm that the module is done processing
                    __database__.publish('finished_modules', self.name)
                    return True

                if utils.is_msg_intended_for(message, 'new_ip'):
                    # Get the IP from the message
                    ip = message['data']
                    try:
                        # make sure its a valid ip
                        ip_addr = ipaddress.ip_address(ip)
                        if ip_addr.is_multicast:
                            continue
                    except ValueError:
                        # not a valid ip skip
                        continue

                    # Do we have cached info about this ip in redis?
                    # If yes, load it
                    cached_ip_info = __database__.getIPData(ip)
                    if not cached_ip_info:
                        cached_ip_info = {}
                    
                    # ------ GeoCountry -------
                    # Get the geocountry
                    if cached_ip_info == {} or 'geocountry' not in cached_ip_info:
                        self.get_geocountry(ip)

                    # ------ ASN -------
                    # Get the ASN
                    # Before returning, update the ASN for this IP if more than 1 month 
                    # passed since last ASN update on this IP 
                    update_asn = self.update_asn(cached_ip_info)
                    if update_asn:
                        self.get_asn(ip, cached_ip_info)
                    self.get_rdns(ip)

                message = self.c2.get_message(timeout=self.timeout)
                if utils.is_msg_intended_for(message, 'new_MAC'):
                    data = json.loads(message['data'])
                    mac_addr = data['MAC']
                    host_name = data.get('host_name', False)
                    profileid = data['profileid']
                    self.get_vendor(mac_addr, host_name, profileid)

            except KeyboardInterrupt:
                self.close_dbs()
                continue
            except Exception as inst:
                exception_line = sys.exc_info()[2].tb_lineno
                self.print(f'Problem on run() line {exception_line}', 0, 1)
                self.print(str(type(inst)), 0, 1)
                self.print(str(inst.args), 0, 1)
                self.print(str(inst), 0, 1)
                self.close_dbs()
                return True
