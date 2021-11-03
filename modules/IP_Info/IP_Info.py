# Must imports
from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database import __database__
import platform
import sys

# Your imports
import time
import maxminddb
import ipaddress
import ipwhois
import configparser
import os
import json
#todo add to conda env

class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'IP_Info'
    description = 'Get different info about an IP address'
    authors = ['Sebastian Garcia']

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
        self.timeout = None
        # update asn every 1 month
        self.update_period = 2592000
    
    def open_dbs(self):
        """ Function to open the different offline databases used in this module. ASN, Country etc.. """
        
        # Open the maxminddb ASN offline db 
        try:
            self.asn_db = maxminddb.open_database('databases/GeoLite2-ASN.mmdb')
        except:
            self.print('Error opening the geolite2 db in databases/GeoLite2-ASN.mmdb. Please download it from https://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.tar.gz. Please note it must be the MaxMind DB version.')
        
        # Open the maminddb Country offline db
        try:
            self.country_db = maxminddb.open_database('databases/GeoLite2-Country.mmdb')
        except:
            self.print('Error opening the geolite2 db in databases/GeoLite2-Country.mmdb. Please download it from https://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.tar.gz. Please note it must be the MaxMind DB version.')
        
        
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
            update =  (time.time() - cached_data['asn']['timestamp']) > self.update_period
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
        asninfo = self.asn_db.get(ip)
        data = {}
        try:
            # found info in geolite
            asnorg = asninfo['autonomous_system_organization']
            data['asn'] = {'asnorg': asnorg}
        except KeyError:
            # asn info not found in geolite
            data['asn'] ={'asnorg': 'Unknown'}
        except TypeError:
            # geolite returned nothing at all for this ip
            data['asn'] = {'asnorg': 'Unknown'}
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
        except ipwhois.exceptions.ASNRegistryError:
            # ASN lookup failed with no more methods to try
            pass

    def get_geocountry_info(self, ip) -> dict:
        """
        Get ip geocountry from geolite database
        :param ip: str
        """
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


    def get_asn_info(self, ip, cached_ip_info):
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

    def run(self):
        # Main loop function
        while True:
            try:
                message = self.c1.get_message(timeout=self.timeout)

                # if timewindows are not updated for a long time (see at logsProcess.py),
                # we will stop slips automatically.The 'stop_process' line is sent from logsProcess.py.
                if message['data'] == 'stop_process':
                    if hasattr(self, 'asn_db'): self.asn_db.close()
                    if hasattr(self, 'country_db'): self.country_db.close()
                    # confirm that the module is done processing
                    __database__.publish('finished_modules', self.name)
                    return True

                elif message['channel'] == 'new_ip' and type(message['data'])==str:
                    ip = message['data']
                    try:
                        ip_addr = ipaddress.ip_address(ip)
                        if ip_addr.is_multicast:
                            continue
                    except ValueError:
                        # not a valid ip skip
                        continue

                    cached_ip_info = __database__.getIPData(ip)
                    if not cached_ip_info:
                        cached_ip_info = {}

                    # Check that there is data in the DB,
                    # and that the data is not empty, and that our key is not there yet
                    if hasattr(self, 'country_db') and (cached_ip_info == {} or 'geocountry' not in cached_ip_info):
                        self.get_geocountry_info(ip)

                    # Check if a month has passed since last time we updated asn
                    update_asn = self.update_asn(cached_ip_info)
                    if hasattr(self, 'asn_db') and update_asn:
                        self.get_asn_info(ip, cached_ip_info)
            except KeyboardInterrupt:
                if hasattr(self, 'asn_db'): self.asn_db.close()
                if hasattr(self, 'country_db'): self.country_db.close()
                continue
            # except Exception as inst:
            #     exception_line = sys.exc_info()[2].tb_lineno
            #     self.print(f'Problem on run() line {exception_line}', 0, 1)
            #     self.print(str(type(inst)), 0, 1)
            #     self.print(str(inst.args), 0, 1)
            #     self.print(str(inst), 0, 1)
            #     if self.asn_db: self.asn_db.close()
            #     if self.country_db: self.country_db.close()
            #     return True
