# Must imports
from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database import __database__
from slips_files.common.slips_utils import utils
import platform
import sys

# Your imports
import time
import datetime
import maxminddb
import ipaddress
import ipwhois, whois
import socket
import json
import requests
from dns.resolver import NoResolverConfiguration
from contextlib import redirect_stdout

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
        self.c3 = __database__.subscribe('new_dns_flow')
        self.timeout = 0.0000001
        # update asn every 1 month
        self.update_period = 2592000
        # we can only getthe age of these tlds
        self.valid_tlds = ['.ac_uk', '.am', '.amsterdam', '.ar', '.at', '.au',
                           '.bank', '.be', '.biz', '.br', '.by', '.ca', '.cc',
                           '.cl', '.club', '.cn', '.co', '.co_il', '.co_jp', '.com',
                           '.com_au', '.com_tr', '.cr', '.cz', '.de', '.download', '.edu',
                           '.education', '.eu', '.fi', '.fm', '.fr', '.frl', '.game', '.global_',
                           '.hk', '.id_', '.ie', '.im', '.in_', '.info', '.ink', '.io',
                           '.ir', '.is_', '.it', '.jp', '.kr', '.kz', '.link', '.lt', '.lv',
                           '.me', '.mobi', '.mu', '.mx', '.name', '.net', '.ninja',
                           '.nl', '.nu', '.nyc', '.nz', '.online', '.org', '.pe',
                           '.pharmacy', '.pl', '.press', '.pro', '.pt', '.pub', '.pw',
                           '.rest', '.ru', '.ru_rf', '.rw', '.sale', '.se', '.security',
                           '.sh', '.site', '.space', '.store', '.tech', '.tel', '.theatre',
                           '.tickets', '.trade', '.tv', '.ua', '.uk', '.us', '.uz', '.video',
                           '.website', '.wiki', '.work', '.xyz', '.za']
    
    def open_dbs(self):
        """ Function to open the different offline databases used in this module. ASN, Country etc.. """
        
        # Open the maxminddb ASN offline db 
        try:
            self.asn_db = maxminddb.open_database('databases/GeoLite2-ASN.mmdb')
        except:
            self.print('Error opening the geolite2 db in databases/GeoLite2-ASN.mmdb. '
                       'Please download it from https://dev.maxmind.com/geoip/docs/databases/asn?lang=en '
                       'Please note it must be the MaxMind DB version.')
        
        # Open the maminddb Country offline db
        try:
            self.country_db = maxminddb.open_database('databases/GeoLite2-Country.mmdb')
        except:
            self.print('Error opening the geolite2 db in databases/GeoLite2-Country.mmdb. '
                       'Please download it from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data?lang=en. '
                       'Please note it must be the MaxMind DB version.')
        
        try:
            self.mac_db = open('databases/macaddress-db.json','r')
        except OSError:
            self.print('Error opening the macaddress db in databases/macaddress-db.json. '
                       'Please download it from https://macaddress.io/database-download/json.')

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
            response = requests.get( f'{url}/{ip}', timeout=5)
            if response.status_code == 200:
                ip_info = json.loads(response.text)
                if ip_info.get('as', '') != '':
                    asn['asn']['asnorg'] = ip_info['as']
        except (requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError):
            pass

        return asn

    def get_asn(self, ip, cached_ip_info):
        """ Gets ASN info about IP, either cached, from our offline mmdb or from ip-api.com"""

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
            if line == '':
                # reached the end of file without finding the vendor
                # set the vendor to unknown to avoid searching for it again
                MAC_info.update({'Vendor': 'Unknown'})
                break

            if oui in line:
                line = json.loads(line)
                vendor = line['companyName']
                MAC_info.update({'Vendor': vendor})
                break


        if MAC_info['Vendor'] == 'Unknown':
            # couldn't find vendor using offline db, search online
            url = 'https://www.macvendorlookup.com/api/v2'
            try:
                response = requests.get(f'{url}/{mac_addr}', timeout=5)
                if response.status_code == 200:
                    # this onnline db returns results in an array like str [{results}],
                    # make it json
                    online_info = response.text.replace("]","").replace("[","")
                    online_info = json.loads(online_info)
                    vendor = online_info.get('company', False)
                    if vendor:
                        MAC_info.update({'Vendor': vendor})
                else:
                    # If there is no match in the online database,
                    # you will receive an empty response with a status code of HTTP/1.1 204 No Content
                    pass
            except (requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError, json.decoder.JSONDecodeError):
                pass


        # either we found the vendor or not, store the mac of this ip to the db
        __database__.add_mac_addr_to_profile(profileid, MAC_info)
        return MAC_info

    def get_age(self, domain):

        if domain.endswith('.arpa') or domain.endswith('.local'):
            return False

        # make sure whois supports the given tld
        for tld in self.valid_tlds:
            if domain.endswith(tld):
                # valid tld
                break
        else:
            # tld not supported
            return False

        cached_data = __database__.getDomainData(domain)
        if cached_data and 'Age' in cached_data:
            # we already have age info about this domain
            return False

        # whois library doesn't only raise an exception, it prints the error!
        # the errors are the same exceptions we're handling
        # temorarily change stdout to /dev/null
        with open('/dev/null', 'w') as f:
            with redirect_stdout(f):
                # get registration date
                try:
                    creation_date = whois.query(domain).creation_date
                except AttributeError:
                    # the query doesn't have a creation date
                    return False
                except whois.exceptions.UnknownTld:
                    # solved by manually checking valid TLDs
                    return False
                except whois.exceptions.FailedParsingWhoisOutput:
                    # connection limit exceeded
                    # todo should we do something about this?
                    return False
                except whois.exceptions.WhoisCommandFailed:
                    # timeout while performing 'whois' command
                    return False
                except KeyError:
                    # ocassionally occurs in whois/_3_adjust.py
                    return False

        if not creation_date:
            # no creation date was found for this domain
            return False

        today = datetime.datetime.today()

        # calculate age
        day = today.day - creation_date.day
        month = today.month - creation_date.month
        year = today.year - creation_date.year

        # get the age in days
        age = (year*365) + (month*30) + day
        __database__.setInfoForDomains(domain, {'Age': age})
        return age


    def shutdown_gracefully(self):
        if hasattr(self, 'asn_db'): self.asn_db.close()
        if hasattr(self, 'country_db'): self.country_db.close()
        if hasattr(self, 'mac_db'): self.mac_db.close()
        # confirm that the module is done processing
        __database__.publish('finished_modules', self.name)

    def run(self):
        # Main loop function
        while True:
            try:
                message = self.c2.get_message(timeout=self.timeout)
                if message and message['data'] == 'stop_process':
                    self.shutdown_gracefully()
                    return True
                if utils.is_msg_intended_for(message, 'new_MAC'):
                    data = json.loads(message['data'])
                    mac_addr = data['MAC']
                    host_name = data.get('host_name', False)
                    profileid = data['profileid']
                    self.get_vendor(mac_addr, host_name, profileid)

                message = self.c3.get_message(timeout=self.timeout)
                if (message and message['data'] == 'stop_process'):
                    self.shutdown_gracefully()
                    return True
                if utils.is_msg_intended_for(message, 'new_dns_flow'):
                    data = message["data"]
                    data = json.loads(data)
                    profileid = data['profileid']
                    twid = data['twid']
                    uid = data['uid']
                    flow_data = json.loads(data['flow']) # this is a dict {'uid':json flow data}
                    domain = flow_data.get('query', False)
                    if domain:
                        self.get_age(domain)

                message = self.c1.get_message(timeout=self.timeout)
                # if timewindows are not updated for a long time (see at logsProcess.py),
                # we will stop slips automatically.The 'stop_process' line is sent from logsProcess.py.
                if message and message['data'] == 'stop_process':
                    self.shutdown_gracefully()
                    return True

                if utils.is_msg_intended_for(message, 'new_ip'):
                    # Get the IP from the message
                    ip = message['data']
                    try:
                        # make sure its a valid ip
                        ip_addr = ipaddress.ip_address(ip)
                    except ValueError:
                        # not a valid ip skip
                        continue

                    if not ip_addr.is_multicast:
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
                        # only update the ASN for this IP if more than 1 month
                        # passed since last ASN update on this IP
                        update_asn = self.update_asn(cached_ip_info)
                        if update_asn:
                            self.get_asn(ip, cached_ip_info)
                        self.get_rdns(ip)

            except KeyboardInterrupt:
                self.shutdown_gracefully()
                return True

            except Exception as inst:
                exception_line = sys.exc_info()[2].tb_lineno
                self.print(f'Problem on run() line {exception_line}', 0, 1)
                self.print(str(type(inst)), 0, 1)
                self.print(str(inst.args), 0, 1)
                self.print(str(inst), 0, 1)
                self.shutdown_gracefully()
                return True
