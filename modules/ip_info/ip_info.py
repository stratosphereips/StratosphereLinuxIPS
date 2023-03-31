from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database.database import __database__
from slips_files.common.slips_utils import utils
from .asn_info import ASN
import platform
import sys
import traceback
import datetime
import maxminddb
import ipaddress
import whois
import socket
import requests
import json
from contextlib import redirect_stdout, redirect_stderr
import subprocess
import re
import time
import asyncio


class Module(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'IP Info'
    description = 'Get different info about an IP/MAC address'
    authors = ['Alya Gomaa', 'Sebastian Garcia']

    def __init__(self, outputqueue, redis_port):
        multiprocessing.Process.__init__(self)
        # All the printing output should be sent to the outputqueue. The outputqueue is connected to another process called OutputProcess
        self.outputqueue = outputqueue
        __database__.start(redis_port)
        self.pending_mac_queries = multiprocessing.Queue()
        self.asn = ASN()
        # Set the output queue of our database instance
        __database__.setOutputQueue(self.outputqueue)
        # To which channels do you wnat to subscribe? When a message arrives on the channel the module will wakeup
        self.c1 = __database__.subscribe('new_ip')
        self.c2 = __database__.subscribe('new_MAC')
        self.c3 = __database__.subscribe('new_dns_flow')
        # update asn every 1 month
        self.update_period = 2592000
        self.is_gw_mac_set = False
        # we can only getthe age of these tlds
        self.valid_tlds = [
            '.ac_uk',
            '.am',
            '.amsterdam',
            '.ar',
            '.at',
            '.au',
            '.bank',
            '.be',
            '.biz',
            '.br',
            '.by',
            '.ca',
            '.cc',
            '.cl',
            '.club',
            '.cn',
            '.co',
            '.co_il',
            '.co_jp',
            '.com',
            '.com_au',
            '.com_tr',
            '.cr',
            '.cz',
            '.de',
            '.download',
            '.edu',
            '.education',
            '.eu',
            '.fi',
            '.fm',
            '.fr',
            '.frl',
            '.game',
            '.global_',
            '.hk',
            '.id_',
            '.ie',
            '.im',
            '.in_',
            '.info',
            '.ink',
            '.io',
            '.ir',
            '.is_',
            '.it',
            '.jp',
            '.kr',
            '.kz',
            '.link',
            '.lt',
            '.lv',
            '.me',
            '.mobi',
            '.mu',
            '.mx',
            '.name',
            '.net',
            '.ninja',
            '.nl',
            '.nu',
            '.nyc',
            '.nz',
            '.online',
            '.org',
            '.pe',
            '.pharmacy',
            '.pl',
            '.press',
            '.pro',
            '.pt',
            '.pub',
            '.pw',
            '.rest',
            '.ru',
            '.ru_rf',
            '.rw',
            '.sale',
            '.se',
            '.security',
            '.sh',
            '.site',
            '.space',
            '.store',
            '.tech',
            '.tel',
            '.theatre',
            '.tickets',
            '.trade',
            '.tv',
            '.ua',
            '.uk',
            '.us',
            '.uz',
            '.video',
            '.website',
            '.wiki',
            '.work',
            '.xyz',
            '.za',
        ]

    async def open_dbs(self):
        """Function to open the different offline databases used in this module. ASN, Country etc.."""
        # Open the maxminddb ASN offline db
        try:
            self.asn_db = maxminddb.open_database(
                'databases/GeoLite2-ASN.mmdb'
            )
        except Exception:
            self.print(
                'Error opening the geolite2 db in databases/GeoLite2-ASN.mmdb. '
                'Please download it from https://dev.maxmind.com/geoip/docs/databases/asn?lang=en '
                'Please note it must be the MaxMind DB version.'
            )

        # Open the maminddb Country offline db
        try:
            self.country_db = maxminddb.open_database(
                'databases/GeoLite2-Country.mmdb'
            )
        except Exception:
            self.print(
                'Error opening the geolite2 db in databases/GeoLite2-Country.mmdb. '
                'Please download it from https://dev.maxmind.com/geoip/geolite2-free-geolocation-data?lang=en. '
                'Please note it must be the MaxMind DB version.'
            )

        asyncio.create_task(self.read_macdb())

    async def read_macdb(self):
        while True:
            try:
                self.mac_db = open('databases/macaddress-db.json', 'r')
                return True
            except OSError:
                # update manager hasn't downloaded it yet
                try:
                    time.sleep(3)
                except KeyboardInterrupt:
                    return False

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
        self.outputqueue.put(f'{levels}|{self.name}|{text}')

    # GeoInfo functions
    def get_geocountry(self, ip) -> dict:
        """
        Get ip geocountry from geolite database
        :param ip: str
        """
        if not hasattr(self, 'country_db'):
            return False
        if ipaddress.ip_address(ip).is_private:
            # Try to find if it is a local/private IP
            data = {'geocountry': 'Private'}
        elif geoinfo := self.country_db.get(ip):
            try:
                countrydata = geoinfo['country']
                countryname = countrydata['names']['en']
                data = {'geocountry': countryname}
            except KeyError:
                data = {'geocountry': 'Unknown'}

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
        return socket.AF_INET6 if ':' in ip else socket.AF_INET

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
                # reverse_dns is an ip. there's no reverse dns. don't store
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

    def get_vendor_online(self, mac_addr):
        # couldn't find vendor using offline db, search online

        # If there is no match in the online database,
        # you will receive an empty response with a status code
        # of HTTP/1.1 204 No Content
        url = 'https://api.macvendors.com'
        try:
            response = requests.get(f'{url}/{mac_addr}', timeout=5)
            if response.status_code == 200:
                # this online db returns results in an array like str [{results}],
                # make it json
                if vendor:= response.text:
                    return vendor
            return False
        except (
            requests.exceptions.ReadTimeout,
            requests.exceptions.ConnectionError,
            json.decoder.JSONDecodeError,
        ):
            return False

    def get_vendor_offline(self, mac_addr, host_name, profileid):
        """
        Gets vendor from Slips' offline database databases/macaddr-db.json
        """
        if not hasattr(self, 'mac_db'):
            # when update manager is done updating the mac db, we should ask
            # the db for all these pending queries
            self.pending_mac_queries.put((mac_addr, host_name, profileid))
            return False

        oui = mac_addr[:8].upper()
        # parse the mac db and search for this oui
        self.mac_db.seek(0)
        while True:
            line = self.mac_db.readline()
            if line == '':
                # reached the end of file without finding the vendor
                # set the vendor to unknown to avoid searching for it again
                return False

            if oui in line:
                line = json.loads(line)
                vendor = line['vendorName']
                return vendor

    def get_vendor(self, mac_addr: str, host_name: str, profileid: str):
        """
        Returns vendor info of a MAC address either from an offline or an online
         database
        """

        if (
            'ff:ff:ff:ff:ff:ff' in mac_addr.lower()
            or '00:00:00:00:00:00' in mac_addr.lower()
        ):
            return False

        # don't look for the vendor again if we already have it for this profileid
        if __database__.get_mac_vendor_from_profile(profileid):
            return True

        MAC_info = {
            'MAC': mac_addr
        }

        if host_name:
            MAC_info['host_name'] = host_name

        if vendor:= self.get_vendor_offline(mac_addr, host_name, profileid):
            MAC_info['Vendor'] = vendor
        elif vendor:= self.get_vendor_online(mac_addr):
            MAC_info['Vendor'] = vendor
        else:
            MAC_info['Vendor'] = 'Unknown'

        # either we found the vendor or not, store the mac of this ip to the db
        __database__.add_mac_addr_to_profile(profileid, MAC_info)
        return MAC_info

    # domain info
    def get_age(self, domain):
        """
        Get the age of a domain using whois library
        """

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
            with redirect_stdout(f) and redirect_stderr(f):
                # get registration date
                try:
                    creation_date = whois.query(domain).creation_date
                except Exception as ex:
                    return False

        if not creation_date:
            # no creation date was found for this domain
            return False

        today = datetime.datetime.now()

        age = utils.get_time_diff(
            creation_date,
            today,
            return_type='days'
        )

        __database__.setInfoForDomains(domain, {'Age': age})
        return age

    def shutdown_gracefully(self):
        if hasattr(self, 'asn_db'):
            self.asn_db.close()
        if hasattr(self, 'country_db'):
            self.country_db.close()
        if hasattr(self, 'mac_db'):
            self.mac_db.close()
        # confirm that the module is done processing
        __database__.publish('finished_modules', self.name)

    # GW
    def get_gateway_ip(self):
        """
        Slips tries different ways to get the ip of the default gateway
        this method tries to get the default gateway IP address using ip route
        only works when running on an interface
        """
        if not ('-i' in sys.argv or __database__.is_growing_zeek_dir()):
            # only works if running on an interface
            return False

        gw_ip = False
        if platform.system() == 'Darwin':
            route_default_result = subprocess.check_output(
                ['route', 'get', 'default']
            ).decode()
            try:
                gw_ip = re.search(
                    r'\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}',
                    route_default_result,
                ).group(0)
            except AttributeError:
                pass

        elif platform.system() == 'Linux':
            route_default_result = re.findall(
                r"([\w.][\w.]*'?\w?)",
                subprocess.check_output(['ip', 'route']).decode(),
            )
            gw_ip = route_default_result[2]
        return gw_ip

    def get_gateway_MAC(self, gw_ip: str):
        """
        Given the gw_ip, this function tries to get the MAC
         from arp.log or from arp tables
        """
        # we keep a cache of the macs and their IPs
        # In case of a zeek dir or a pcap,
        # check if we have the mac of this ip already saved in the db.
        gw_MAC = __database__.get_mac_addr_from_profile(f'profile_{gw_ip}')
        if gw_MAC:
            __database__.set_default_gateway('MAC', gw_MAC)
            return gw_MAC

        # we don't have it in arp.log(in the db)
        running_on_interface = '-i' in sys.argv or __database__.is_growing_zeek_dir()
        if not running_on_interface:
            # no MAC in arp.log (in the db) and can't use arp tables,
            # so it's up to the db.is_gw_mac() function to determine the gw mac
            # if it's seen associated with a public IP
            return

        # get it using arp table
        cmd = "arp -a"
        output = subprocess.check_output(cmd.split()).decode()
        for line in output:
            if gw_ip in line:
                gw_MAC = line.split()[-4]
                __database__.set_default_gateway('MAC', gw_MAC)
                return gw_MAC

    def check_if_we_have_pending_mac_queries(self):
        """
        Checks if we have pending queries in pending_mac_queries queue, and asks the db for them IF
        update manager is done updating the mac db
        """
        if hasattr(self, 'mac_db') and not self.pending_mac_queries.empty():
            while True:
                try:
                    mac, host_name, profileid = self.pending_mac_queries.get(timeout=0.5)
                    self.get_vendor(mac, host_name, profileid)

                except Exception as ex:
                    # queue is empty
                    return

    def wait_for_dbs(self):
        """
        wait for update manager to finish updating the mac db and open the rest of dbs before starting this module
        """
        # this is the loop that controls te running on open_dbs
        loop = asyncio.get_event_loop()
        # run open_dbs in the background so we don't have
        # to wait for update manager to finish updating the mac db to start this module
        loop.run_until_complete(self.open_dbs())

    def run(self):
        utils.drop_root_privs()

        self.wait_for_dbs()

        # the following method only works when running on an interface
        if ip := self.get_gateway_ip():
            __database__.set_default_gateway('IP', ip)

        # Main loop function
        while True:
            try:
                message = __database__.get_message(self.c2)
                if message and message['data'] == 'stop_process':
                    self.shutdown_gracefully()
                    return True
                if utils.is_msg_intended_for(message, 'new_MAC'):
                    data = json.loads(message['data'])
                    mac_addr = data['MAC']
                    host_name = data.get('host_name', False)
                    profileid = data['profileid']
                    self.get_vendor(mac_addr, host_name, profileid)
                    self.check_if_we_have_pending_mac_queries()
                    # set the gw mac and ip if they're not set yet
                    if not self.is_gw_mac_set:
                        # whether we found the gw ip using dhcp in profileprocess
                        # or using ip route using self.get_gateway_ip()
                        # now that it's found, get and store the mac addr of it
                        if ip:= __database__.get_gateway_ip():
                            # now that we know the GW IP address,
                            # try to get the MAC of this IP (of the gw)
                            self.get_gateway_MAC(ip)
                            self.is_gw_mac_set = True

                message = __database__.get_message(self.c3)
                if message and message['data'] == 'stop_process':
                    self.shutdown_gracefully()
                    return True

                if utils.is_msg_intended_for(message, 'new_dns_flow'):
                    data = message['data']
                    data = json.loads(data)
                    # profileid = data['profileid']
                    # twid = data['twid']
                    # uid = data['uid']
                    flow_data = json.loads(
                        data['flow']
                    )   # this is a dict {'uid':json flow data}
                    if domain := flow_data.get('query', False):
                        self.get_age(domain)

                message = __database__.get_message(self.c1)
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
                        if (
                                cached_ip_info == {}
                                or 'geocountry' not in cached_ip_info
                        ):
                            self.get_geocountry(ip)

                        # ------ ASN -------
                        # Get the ASN
                        # only update the ASN for this IP if more than 1 month
                        # passed since last ASN update on this IP
                        if update_asn := self.asn.update_asn(
                                cached_ip_info,
                                self.update_period
                        ):
                            self.asn.get_asn(ip, cached_ip_info)
                        self.get_rdns(ip)


            except KeyboardInterrupt:
                self.shutdown_gracefully()
                return True

            except Exception as inst:
                exception_line = sys.exc_info()[2].tb_lineno
                self.print(f'Problem on run() line {exception_line}', 0, 1)
                self.print(traceback.format_exc(), 0, 1)
                return True
