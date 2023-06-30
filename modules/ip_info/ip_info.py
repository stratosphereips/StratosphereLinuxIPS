from slips_files.common.imports import *
from modules.ip_info.jarm import JARM
from .asn_info import ASN
import platform
import sys
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


class IPInfo(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'IP Info'
    description = 'Get different info about an IP/MAC address'
    authors = ['Alya Gomaa', 'Sebastian Garcia']

    def init(self):
        """This will be called when initializing this module"""
        self.pending_mac_queries = multiprocessing.Queue()
        self.asn = ASN(self.db)
        self.JARM = JARM()
        # Set the output queue of our database instance
        # To which channels do you wnat to subscribe? When a message arrives on the channel the module will wakeup
        self.c1 = self.db.subscribe('new_ip')
        self.c2 = self.db.subscribe('new_MAC')
        self.c3 = self.db.subscribe('new_dns')
        self.c4 = self.db.subscribe('check_jarm_hash')
        self.channels = {
            'new_ip': self.c1,
            'new_MAC': self.c2,
            'new_dns': self.c3,
            'check_jarm_hash': self.c4,
        }
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
        self.db.setInfoForIPs(ip, data)
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
                self.db.setInfoForIPs(ip, data)
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

    def get_vendor_offline(self, mac_addr, profileid):
        """
        Gets vendor from Slips' offline database databases/macaddr-db.json
        """
        if not hasattr(self, 'mac_db'):
            # when update manager is done updating the mac db, we should ask
            # the db for all these pending queries
            self.pending_mac_queries.put((mac_addr, profileid))
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
                return line['vendorName']

    def get_vendor(self, mac_addr: str, profileid: str):
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
        if self.db.get_mac_vendor_from_profile(profileid):
            return True

        MAC_info = {
            'MAC': mac_addr
        }

        if vendor:= self.get_vendor_offline(mac_addr, profileid):
            MAC_info['Vendor'] = vendor
        elif vendor:= self.get_vendor_online(mac_addr):
            MAC_info['Vendor'] = vendor
        else:
            MAC_info['Vendor'] = 'Unknown'

        # either we found the vendor or not, store the mac of this ip to the db
        self.db.add_mac_addr_to_profile(profileid, MAC_info)
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

        cached_data = self.db.getDomainData(domain)
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
                except Exception:
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

        self.db.setInfoForDomains(domain, {'Age': age})
        return age

    def shutdown_gracefully(self):
        if hasattr(self, 'asn_db'):
            self.asn_db.close()
        if hasattr(self, 'country_db'):
            self.country_db.close()
        if hasattr(self, 'mac_db'):
            self.mac_db.close()

    # GW
    def get_gateway_ip(self):
        """
        Slips tries different ways to get the ip of the default gateway
        this method tries to get the default gateway IP address using ip route
        only works when running on an interface
        """
        if not ('-i' in sys.argv or self.db.is_growing_zeek_dir()):
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
        if gw_MAC := self.db.get_mac_addr_from_profile(f'profile_{gw_ip}'):
            self.db.set_default_gateway('MAC', gw_MAC)
            return gw_MAC

        # we don't have it in arp.log(in the db)
        running_on_interface = '-i' in sys.argv or self.db.is_growing_zeek_dir()
        if not running_on_interface:
            # no MAC in arp.log (in the db) and can't use arp tables,
            # so it's up to the db.is_gw_mac() function to determine the gw mac
            # if it's seen associated with a public IP
            return

        # Obtain the MAC address by using the hosts ARP table
        # First, try the ip command
        try:
            ip_output = subprocess.run(["ip", "neigh", "show", gw_ip],
                                      capture_output=True, check=True, text=True).stdout
            gw_MAC = ip_output.split()[-2]
            self.db.set_default_gateway('MAC', gw_MAC)
            return gw_MAC
        except (subprocess.CalledProcessError, FileNotFoundError):
            # If the ip command doesn't exist or has failed, try using the arp command
            try:
                arp_output = subprocess.run(["arp", "-an"],
                                           capture_output=True, check=True, text=True).stdout
                for line in arp_output.split('\n'):
                    fields = line.split()
                    gw_ip_from_arp_cmd = fields[1].strip('()')
                    # Match the gw_ip in the output with the one given to this function
                    if len(fields) >= 2 and gw_ip_from_arp_cmd == gw_ip:
                        gw_MAC = fields[-4]
                        self.db.set_default_gateway('MAC', gw_MAC)
                        return gw_MAC
            except (subprocess.CalledProcessError, FileNotFoundError):
                # Could not find the MAC address of gw_ip
                return

        return gw_MAC

    def check_if_we_have_pending_mac_queries(self):
        """
        Checks if we have pending queries in pending_mac_queries queue, and asks the db for them IF
        update manager is done updating the mac db
        """
        if hasattr(self, 'mac_db') and not self.pending_mac_queries.empty():
            while True:
                try:
                    mac, profileid = self.pending_mac_queries.get(timeout=0.5)
                    self.get_vendor(mac, profileid)

                except Exception:
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

    def set_evidence_malicious_jarm_hash(
            self,
            flow,
            uid,
            profileid,
            twid,
    ):
        dport = flow['dport']
        dstip = flow['daddr']
        timestamp = flow['starttime']
        protocol = flow['proto']

        evidence_type = 'MaliciousJARM'
        attacker_direction = 'dstip'
        source_target_tag = 'Malware'
        attacker = dstip
        threat_level = 'medium'
        confidence = 0.7
        category = 'Anomaly.Traffic'
        portproto = f'{dport}/{protocol}'
        port_info = self.db.get_port_info(portproto)
        port_info = port_info or ""
        port_info = f'({port_info.upper()})' if port_info else ""
        dstip_id = self.db.get_ip_identification(dstip)
        description = (
           f"Malicious JARM hash detected for destination IP: {dstip}"
           f" on port: {portproto} {port_info}.  {dstip_id}"
        )

        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, source_target_tag=source_target_tag,
                                 port=dport, proto=protocol, profileid=profileid, twid=twid, uid=uid)

    def pre_main(self):
        utils.drop_root_privs()
        self.wait_for_dbs()
        # the following method only works when running on an interface
        if ip := self.get_gateway_ip():
            self.db.set_default_gateway('IP', ip)

    def handle_new_ip(self, ip):
        try:
            # make sure its a valid ip
            ip_addr = ipaddress.ip_address(ip)
        except ValueError:
            # not a valid ip skip
            return

        if not ip_addr.is_multicast:
            # Do we have cached info about this ip in redis?
            # If yes, load it
            cached_ip_info = self.db.getIPData(ip)
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

    def main(self):
        if msg:= self.get_msg('new_MAC'):
            data = json.loads(msg['data'])
            mac_addr = data['MAC']
            host_name = data.get('host_name', False)
            profileid = data['profileid']

            if host_name:
                self.db.add_host_name_to_profile(host_name, profileid)

            self.get_vendor(mac_addr, profileid)
            self.check_if_we_have_pending_mac_queries()
            # set the gw mac and ip if they're not set yet
            if not self.is_gw_mac_set:
                # whether we found the gw ip using dhcp in profileprocess
                # or using ip route using self.get_gateway_ip()
                # now that it's found, get and store the mac addr of it
                if ip:= self.db.get_gateway_ip():
                    # now that we know the GW IP address,
                    # try to get the MAC of this IP (of the gw)
                    self.get_gateway_MAC(ip)
                    self.is_gw_mac_set = True

        if msg:= self.get_msg('new_dns'):
            data = msg['data']
            data = json.loads(data)
            # profileid = data['profileid']
            # twid = data['twid']
            # uid = data['uid']
            flow_data = json.loads(
                data['flow']
            )   # this is a dict {'uid':json flow data}
            if domain := flow_data.get('query', False):
                self.get_age(domain)

        if msg:= self.get_msg('new_ip'):
            # Get the IP from the message
            ip = msg['data']
            self.handle_new_ip(ip)

