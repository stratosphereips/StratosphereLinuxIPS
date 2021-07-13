# Module to load and find the ASN of each IP

# Must imports
from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database import __database__
import platform

# Your imports
import time
import maxminddb
import ipaddress
import ipwhois
import json
#todo add to conda env

class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'asn'
    description = 'Module to find the ASN of an IP address'
    authors = ['Sebastian Garcia']

    def __init__(self, outputqueue, config):
        multiprocessing.Process.__init__(self)
        # All the printing output should be sent to the outputqueue. The outputqueue is connected to another process called OutputProcess
        self.outputqueue = outputqueue
        # In case you need to read the slips.conf configuration file for your own configurations
        self.config = config
        # Start the DB
        __database__.start(self.config)
        # Set the output queue of our database instance
        __database__.setOutputQueue(self.outputqueue)
        # Open the maminddb offline db
        try:
            self.reader = maxminddb.open_database('modules/asn/GeoLite2-ASN.mmdb')
        except:
            self.print('Error opening the geolite2 db in ./GeoLite2-Country_20190402/GeoLite2-Country.mmdb. Please download it from https://geolite.maxmind.com/download/geoip/database/GeoLite2-Country.tar.gz. Please note it must be the MaxMind DB version.')
        # To which channels do you wnat to subscribe? When a message arrives on the channel the module will wakeup
        self.c1 = __database__.subscribe('new_ip')
        self.timeout = None
        # update asn every 1 month
        self.update_period = 2592000


    def print(self, text, verbose=1, debug=0):
        """ 
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by taking all the prcocesses into account

        Input
         verbose: is the minimum verbosity level required for this text to be printed
         debug: is the minimum debugging level required for this text to be printed
         text: text to print. Can include format like 'Test {}'.format('here')
        
        If not specified, the minimum verbosity level required is 1, and the minimum debugging level is 0
        """

        vd_text = str(int(verbose) * 10 + int(debug))
        self.outputqueue.put(vd_text + '|' + self.name + '|[' + self.name + '] ' + str(text))

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
        - OR month has passed since we last updated asn info in the db
        :param cached_data: ip cached info from the database, dict
        """
        try:
            update =  (time.time() - cached_data['asn']['timestamp']) > self.update_period
            return update
        except (KeyError, TypeError):
            # no there's no cached asn info,or no timestamp, or cached_data is None
            # we should update
            return True

    def get_asn_info_from_geolite(self, ip) -> bool:
        """
        Get ip info from geolite database
        :param ip: str
        """
        asninfo = self.reader.get(ip)
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

    def run(self):
        # Main loop function
        while True:
            try:
                message = self.c1.get_message(timeout=self.timeout)
                # if timewindows are not updated for a long time (see at logsProcess.py), we will stop slips automatically.The 'stop_process' line is sent from logsProcess.py.
                if message['data'] == 'stop_process':
                    if self.reader:
                        self.reader.close()
                    # confirm that the module is done processing
                    __database__.publish('finished_modules', self.name)
                    return True
                elif message['channel'] == 'new_ip' and type(message['data'])==str:
                    # Not all the ips!! only the new one coming in the data
                    ip = message['data']
                    # The first message comes with data=1
                    data = __database__.getIPData(ip)
                    try:
                        ip_addr = ipaddress.ip_address(ip)
                    except ValueError:
                        # not a valid ip skip
                        continue
                    # Check if a month has passed since last time we updated asn
                    update_asn = self.update_asn(data)
                    if not ip_addr.is_multicast and update_asn:
                        # do we have asn cached for this range?
                        cached_asn = self.get_cached_asn(ip)
                        if not cached_asn:
                            # we don't have it cached
                            data = self.get_asn_info_from_geolite(ip)
                            self.cache_ip_range(ip)
                        else:
                            # found cached asn for this ip's range, store it
                            data['asn'] = {'asnorg': cached_asn}
                        # store asn info in the db
                        data['asn'].update({'timestamp': time.time()})
                        __database__.setInfoForIPs(ip, data)
            except KeyboardInterrupt:
                if self.reader:
                    self.reader.close()
                return True
            except Exception as inst:
                if self.reader:
                    self.reader.close()
                self.print('Problem on run()', 0, 1)
                self.print(str(type(inst)), 0, 1)
                self.print(str(inst.args), 0, 1)
                self.print(str(inst), 0, 1)
                return True
