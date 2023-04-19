from slips_files.common.slips_utils import utils
from slips_files.common.config_parser import ConfigParser
from slips_files.core.database._profile_flow import ProfilingFlowsDatabase
import os
import signal
import redis
import time
import json
from typing import Tuple
import traceback
import subprocess
from datetime import datetime
import ipaddress
import sys
import validators
import ast
from uuid import uuid4



class Database(ProfilingFlowsDatabase, object):
    supported_channels = {
        'tw_modified',
        'evidence_added',
        'new_ip',
        'new_flow',
        'new_dns',
        'new_dns_flow',
        'new_http',
        'new_ssl',
        'new_profile',
        'give_threat_intelligence',
        'new_letters',
        'ip_info_change',
        'dns_info_change',
        'dns_info_change',
        'tw_closed',
        'core_messages',
        'new_blocking',
        'new_ssh',
        'new_notice',
        'new_url',
        'finished_modules',
        'new_downloaded_file',
        'reload_whitelist',
        'new_service',
        'new_arp',
        'new_MAC',
        'new_smtp',
        'new_blame',
        'new_alert',
        'new_dhcp',
        'new_weird',
        'new_software',
        'p2p_data_request',
        'remove_old_files',
        'export_evidence',
        'p2p_data_request',
        'p2p_gopy',
        'report_to_peers',
        'new_tunnel',
        'check_jarm_hash'
    }

    """ Database object management """

    def __init__(self):
        # The name is used to print in the outputprocess
        self.name = 'DB'
        self.separator = '_'
        self.normal_label = 'normal'
        self.malicious_label = 'malicious'
        self.sudo = 'sudo '
        self.running_in_docker = os.environ.get(
            'IS_IN_A_DOCKER_CONTAINER', False
        )
        self.sudo = 'sudo '
        if self.running_in_docker:
            self.sudo = ''
        # flag to know if we found the gateway MAC using the most seen MAC method
        self.gateway_MAC_found = False
        self.redis_conf_file = 'redis.conf'
        self.set_redis_options()
        self.our_ips = utils.get_own_IPs()
        # flag to know which flow is the start of the pcap/file
        self.first_flow = True
        # to make sure we only detect and store the user's localnet once
        self.is_localnet_set = False


    def set_redis_options(self):
        """
        Sets the default slips options,
         when using a different port we override it with -p
        """
        self.redis_options=\
                {
                'port': 6379,
                'daemonize': 'yes',
                'stop-writes-on-bgsave-error': 'no',
                'save': '""',
                'appendonly': 'no'
            }
        if '-s' in sys.argv:
            #   Will save the DB if both the given number of seconds and the given
            #   number of write operations against the DB occurred.
            #   In the example below the behaviour will be to save:
            #   after 30 sec if at least 500 keys changed
            #   AOF persistence logs every write operation received by the server,
            #   that will be played again at server startup
            # saved the db to <Slips-dir>/dump.rdb
            self.redis_options.update({
                'save': '30 500',
                'appendonly': 'yes',
                'dir': os.getcwd(),
                'dbfilename': 'dump.rdb',
            })
        with open(self.redis_conf_file, 'w') as f:
            for option, val in self.redis_options.items():
                f.write(f'{option} {val}\n')

    def get_redis_server_PID(self, redis_port):
        """
        get the PID of the redis server started on the given redis_port
        retrns the pid
        """
        cmd = 'ps aux | grep redis-server'
        cmd_output = os.popen(cmd).read()
        for line in cmd_output.splitlines():
            if str(redis_port) in line:
                pid = line.split()[1]
                return pid
        return False

    def connect_to_redis_server(self, port: str):
        """Connects to the given port and Sets r and rcache"""
        try:
            # start the redis server
            os.system(
                f'redis-server redis.conf --port {port}  > /dev/null 2>&1'
            )

            # db 0 changes everytime we run slips
            # set health_check_interval to avoid redis ConnectionReset errors:
            # if the connection is idle for more than 30 seconds,
            # a round trip PING/PONG will be attempted before next redis cmd.
            # If the PING/PONG fails, the connection will reestablished

            # retry_on_timeout=True after the command times out, it will be retried once,
            # if the retry is successful, it will return normally; if it fails, an exception will be thrown
            self.r = redis.StrictRedis(
                host='localhost',
                port=port,
                db=0,
                charset='utf-8',
                socket_keepalive=True,
                decode_responses=True,
                retry_on_timeout=True,
                health_check_interval=20,
            )  # password='password')
            # port 6379 db 0 is cache, delete it using -cc flag
            self.rcache = redis.StrictRedis(
                host='localhost',
                port=6379,
                db=1,
                charset='utf-8',
                socket_keepalive=True,
                retry_on_timeout=True,
                decode_responses=True,
                health_check_interval=30,
            )  # password='password')
            # the connection to redis is only established
            # when you try to execute a command on the server.
            # so make sure it's established first
            # fix  ConnectionRefused error by giving redis time to open
            time.sleep(1)
            self.r.client_list()
            return True
        except redis.exceptions.ConnectionError:
            # unable to connect to this port
            # sometimes we open the server but we have trouble connecting,
            # so we need to close it
            # if the port is used for another instance, slips.py is going to detect it
            if port != 32850:
                # 32850 is where we have the loaded rdb file when loading a saved db
                # we shouldn't close it because this is what kalipso will
                # use to view the loaded the db

                self.close_redis_server(port)
            return False

    def set_slips_mode(self, slips_mode):
        """
        function to store the current mode (daemonized/interactive)
        in the db
        """
        self.r.set("mode", slips_mode)

    def get_slips_mode(self):
        """
        function to get the current mode (daemonized/interactive)
        in the db
        """
        self.r.get("mode")
    
    def get_modified_ips_in_the_last_tw(self):
        """
        this number is updated in the db every 5s by slips.py
        used for printing running stats in slips.py or outputprocess
        """
        if modified_ips := self.r.hget('analysis', 'modified_ips_in_the_last_tw'):
            return modified_ips
        else:
            return 0
    
    def close_redis_server(self, redis_port):
        if server_pid := self.get_redis_server_PID(redis_port):
            os.kill(int(server_pid), signal.SIGKILL)

    def read_configuration(self):
        conf = ConfigParser()
        self.deletePrevdb = conf.deletePrevdb()
        self.disabled_detections = conf.disabled_detections()
        self.home_network = conf.get_home_network()
        self.width = conf.get_tw_width_as_float()


    def change_redis_limits(self, redis_client):
        """
        To fix redis closing/resetting the pub/sub connection, change redis soft and hard limits
        """
        # maximum buffer size for pub/sub clients:  = 4294967296 Bytes = 4GBs,
        # when msgs in queue reach this limit, Redis will
        # close the client connection as soon as possible.

        # soft limit for pub/sub clients: 2147483648 Bytes = 2GB over 10 mins,
        # means if the client has an output buffer bigger than 2GB
        # for, continuously, 10 mins, the connection gets closed.
        redis_client.config_set('client-output-buffer-limit', "normal 0 0 0 "
                                                        "slave 268435456 67108864 60 "
                                                        "pubsub 4294967296 2147483648 600")

    def start(self, redis_port):
        """Start the DB. Allow it to read the conf"""
        self.read_configuration()

        # Read values from the configuration file
        try:
            if not hasattr(self, 'r'):
                self.connect_to_redis_server(redis_port)
                # Set the memory limits of the output buffer,  For normal clients: no limits
                # for pub-sub 4GB maximum buffer size
                # and 2GB for soft limit
                # The original values were 50MB for maxmem and 8MB for soft limit.
                # don't flush the loaded db when using '-db'
                if (
                        self.deletePrevdb
                        and not ('-S' in sys.argv or '-cb' in sys.argv or '-d'  in sys.argv)
                ):
                    # when stopping the daemon, don't flush bc we need to get the pids
                    # to close slips files
                    self.r.flushdb()

                self.change_redis_limits(self.r)
                self.change_redis_limits(self.rcache)

                # to fix redis.exceptions.ResponseError MISCONF Redis is configured to save RDB snapshots
                # configure redis to stop writing to dump.rdb when an error occurs without throwing errors in slips
                # Even if the DB is not deleted. We need to delete some temp data
                self.r.delete('zeekfiles')


            # By default the slips internal time is 0 until we receive something
            self.setSlipsInternalTime(0)
            while self.get_slips_start_time() is None:
                self.set_slips_start_time()
        except redis.exceptions.ConnectionError as ex:
            print(f"[DB] Can't connect to redis on port {redis_port}: {ex}")
            return False

    def is_connection_error_logged(self):
        return bool(self.r.get('logged_connection_error'))

    def mark_connection_error_as_logged(self):
        """
        When redis connection error occurs, to prevent every module from logging it to slips.log and the console,
        set this variable in the db
        """
        self.r.set('logged_connection_error', 'True')

    def get_message(self, channel, timeout=0.0000001):
        """
        Wrapper for redis' get_message() to be able to handle redis.exceptions.ConnectionError
        notice: there has to be a timeout or the channel will wait forever and never receive a new msg
        """
        try:
            return channel.get_message(timeout=timeout)
        except redis.exceptions.ConnectionError as ex:
            if not self.is_connection_error_logged():
                self.publish('finished_modules', 'stop_slips')
                self.print(f'Stopping slips due to redis.exceptions.ConnectionError: {ex}',0,1)
                # make sure we publish the stop msg and log the error only once
                self.mark_connection_error_as_logged()


    def set_slips_start_time(self):
        """store the time slips started (datetime obj)"""
        now = utils.convert_format(datetime.now(), utils.alerts_format)
        self.r.set('slips_start_time', now)

    def get_slips_start_time(self):
        """get the time slips started (datetime obj)"""
        if start_time := self.r.get('slips_start_time'):
            start_time = utils.convert_format(start_time, utils.alerts_format)
            return start_time

    def setOutputQueue(self, outputqueue):
        """Set the output queue"""
        self.outputqueue = outputqueue

    def should_add(self, profileid: str) -> bool:
        """
        determine whether we should add the given profile to the db or not based on the home_network param
        is the user specified the home_network param, make sure the given profile/ip belongs to it before adding
        """
        # make sure the user specified a home network
        if not self.home_network:
            # no home_network is specified
            return True

        ip = profileid.split(self.separator)[1]
        ip_obj = ipaddress.ip_address(ip)

        return any(ip_obj in network for network in self.home_network)

    def set_loaded_ti_files(self, number_of_loaded_files: int):
        """
        Stores the number of successfully loaded TI files
        """
        self.r.set('loaded TI files', number_of_loaded_files)

    def get_loaded_ti_files(self):
        """
        returns the number of successfully loaded TI files. or 0 if none is loaded
        """
        return self.r.get('loaded TI files') or 0

    def addProfile(self, profileid, starttime, duration):
        """
        Add a new profile to the DB. Both the list of profiles and the hashmap of profile data
        Profiles are stored in two structures. A list of profiles (index) and individual hashmaps for each profile (like a table)
        Duration is only needed for registration purposes in the profile. Nothing operational
        """
        try:
            # make sure we don't add public ips if the user specified a home_network
            if self.r.sismember('profiles', str(profileid)):
                # we already have this profile
                return False
            # execlude ips outside of local network is it's set in slips.conf
            if not self.should_add(profileid):
                return False
            # Add the profile to the index. The index is called 'profiles'
            self.r.sadd('profiles', str(profileid))
            # Create the hashmap with the profileid. The hasmap of each profile is named with the profileid
            # Add the start time of profile
            self.r.hset(profileid, 'starttime', starttime)
            # For now duration of the TW is fixed
            self.r.hset(profileid, 'duration', duration)
            # When a new profiled is created assign threat level = 0 and confidence = 0.05
            self.r.hset(profileid, 'threat_level', 0)
            self.r.hset(profileid, 'confidence', 0.05)
            # The IP of the profile should also be added as a new IP we know about.
            ip = profileid.split(self.separator)[1]
            # If the ip is new add it to the list of ips
            self.setNewIP(ip)
            # Publish that we have a new profile
            self.publish('new_profile', ip)
            return True
        except redis.exceptions.ResponseError as inst:
            self.outputqueue.put(
                '00|database|Error in addProfile in database.py'
            )
            self.outputqueue.put(f'00|database|{type(inst)}')
            self.outputqueue.put(f'00|database|{inst}')

    def was_ip_seen_in_connlog_before(self, ip) -> bool:
        """
        returns true if this is not the first flow slip sees of the given ip
        """
        # we store every source address seen in a conn.log flow in this key
        # if the source address is not stored in this key, it means we may have seen it
        # but not in conn.log yet

        # if the ip's not in the following key, then its the first flow seen of this ip
        return self.r.sismember("srcips_seen_in_connlog", ip)

    def mark_srcip_as_seen_in_connlog(self, ip):
        """
        Marks the given ip as seen in conn.log
        if an ip is not present in this set, it means we may have seen it but not in conn.log
        """
        self.r.sadd("srcips_seen_in_connlog", ip)

    def add_user_agent_to_profile(self, profileid, user_agent: dict):
        """
        Used to associate this profile with it's used user_agent
        :param user_agent: dict containing user_agent, os_type , os_name and agent_name
        """
        self.r.hset(profileid, 'User-agent', user_agent)

    def add_all_user_agent_to_profile(self, profileid, user_agent: str):
        """
        Used to keep history of past user agents of profile
        :param user_agent: str of user_agent
        """
        if not self.r.hexists(profileid ,'past_user_agents'):
            self.r.hset(profileid, 'past_user_agents', json.dumps([user_agent]))
        else:
            user_agents = json.loads(self.r.hget(profileid, 'past_user_agents'))
            if user_agent not in user_agents:
                user_agents.append(user_agent)
                self.r.hset(profileid, 'past_user_agents', json.dumps(user_agents))
                
    def add_software_to_profile(
        self, profileid, flow
    ):
        """
        Used to associate this profile with it's used software and version
        """
        sw_dict = {
            flow.software: {
                    'version-major': flow.version_major,
                    'version-minor': flow.version_minor,
                    'uid': flow.uid
                }
        }
        # cached_sw is {software: {'version-major':x, 'version-minor':y, 'uid':...}}
        if cached_sw := self.get_software_from_profile(profileid):
            if flow.software in cached_sw:
                # we already have this same software for this proileid.
                # dont store this one
                return
            # add this new sw to the list of softwares this profile is using
            cached_sw.update(sw_dict)
            self.r.hset(profileid, 'used_software', json.dumps(cached_sw))
        else:
            # first time for this profile to use a software
            self.r.hset(profileid, 'used_software', json.dumps(sw_dict))

    def get_software_from_profile(self, profileid):
        """
        returns a dict with software, major_version, minor_version
        """
        if not profileid:
            return False

        if used_software := self.r.hmget(profileid, 'used_software')[0]:
            used_software = json.loads(used_software)
            return used_software


    def get_user_agent_from_profile(self, profileid) -> str:
        """
        Returns a dict of {'os_name',  'os_type', 'browser': , 'user_agent': }
        used by a certain profile or None
        """
        if not profileid:
            # profileid is None if we're dealing with a profile
            # outside of home_network when this param is given
            return False
        if user_agent := self.r.hmget(profileid, 'User-agent')[0]:
            # user agents may be OpenSSH_8.6 , no need to deserialize them
            if '{' in user_agent:
                user_agent = json.loads(user_agent)
            return user_agent

    def mark_profile_as_dhcp(self, profileid):
        """
        Used to mark this profile as dhcp server
        """
        if not profileid:
            # profileid is None if we're dealing with a profile
            # outside of home_network when this param is given
            return False

        # returns a list of dhcp if the profile is in the db
        profile_in_db = self.r.hmget(profileid, 'dhcp')
        if not profile_in_db:
            return False
        is_dhcp_set = profile_in_db[0]
        # check if it's already marked as dhcp
        if not is_dhcp_set:
            self.r.hset(profileid, 'dhcp', 'true')


    def mark_profile_as_gateway(self, profileid):
        """
        Used to mark this profile as dhcp server
        """
        if not profileid:
            # profileid is None if we're dealing with a profile
            # outside of home_network when this param is given
            return False

        self.r.hset(profileid, 'gateway', 'true')


    def set_ipv6_of_profile(self, profileid, ip: list):
        self.r.hset(profileid, 'IPv6',  json.dumps(ip))

    def set_ipv4_of_profile(self, profileid, ip):
        self.r.hset(profileid, 'IPv4', json.dumps([ip]))

    def is_gw_mac(self, MAC_info, ip) -> bool:
        """
        Detects the MAC of the gateway if 1 mac is seen assigned to 1 public destination IP
        :param ip: dst ip that should be associated with the given MAC info
        """

        MAC = MAC_info.get('MAC', '')
        if not validators.mac_address(MAC):
            return False

        if self.gateway_MAC_found:
            # gateway MAC already set using this function
            return __database__.get_gateway_MAC() == MAC

        # since we don't have a mac gw in the db, see eif this given mac is the gw mac
        ip_obj = ipaddress.ip_address(ip)
        if not ip_obj.is_private:
            # now we're given a public ip and a MAC that's supposedly belongs to it
            # we are sure this is the gw mac
            # set it if we don't already have it in the db
            # set the ip of the gw, and the mac of the gw
            for address_type, address in MAC_info.items():
                # address_type can be 'IP' or 'MAC' or 'Vendor'
                self.set_default_gateway(address_type, address)

            # mark the gw mac as found so we don't look for it again
            self.gateway_MAC_found = True
            return True


    def get_IP_of_MAC(self, MAC):
        """
        Returns the IP associated with the given MAC in our database
        """
        return self.r.hget('MAC', MAC)

    def add_mac_addr_to_profile(self, profileid, MAC_info):
        """
        Used to associate this profile with its MAC addr in the 'MAC' key in the db
        format of the MAC key is
            MAC: [ipv4, ipv6, etc.]
        :param MAC_info: dict containing mac address, hostname and vendor info
        this functions is called for all macs found in dhcp.log, conn.log, arp.log etc.
        """
        if not profileid:
            # profileid is None if we're dealing with a profile
            # outside of home_network when this param is given
            return False

        if '0.0.0.0' in profileid:
            return False

        incoming_ip = profileid.split('_')[1]

        # sometimes we create profiles with the mac address.
        # don't save that in MAC hash
        if validators.mac_address(incoming_ip):
            return False

        if (
            self.is_gw_mac(MAC_info, incoming_ip)
            and incoming_ip != self.get_gateway_ip()
        ):
            # we're trying to assign the gw mac to an ip that isn't the gateway's
            return False
        # get the ips that belong to this mac
        cached_ip = self.r.hmget('MAC', MAC_info['MAC'])[0]
        if not cached_ip:
            # no mac info stored for profileid
            ip = json.dumps([incoming_ip])
            self.r.hset('MAC', MAC_info['MAC'], ip)
            # Add the MAC addr, hostname and vendor to this profile
            self.r.hset(profileid, 'MAC', json.dumps(MAC_info))
        else:
            # we found another profile that has the same mac as this one
            # incoming_ip = profileid.split('_')[1]

            # get all the ips, v4 and 6, that are stored with this mac
            cached_ips = json.loads(cached_ip)
            # get the last one of them
            found_ip = cached_ips[-1]

            # we already have the incoming ip associated with this mac in the db
            if incoming_ip in cached_ips:
                return False

            cached_ips = set(cached_ips)
            # make sure 1 profile is ipv4 and the other is ipv6 (so we don't mess with MITM ARP detections)
            if validators.ipv6(incoming_ip) and validators.ipv4(found_ip):
                # associate the ipv4 we found with the incoming ipv6 and vice versa
                self.set_ipv4_of_profile(profileid, found_ip)
                self.set_ipv6_of_profile(f'profile_{found_ip}', [incoming_ip])
            elif validators.ipv6(found_ip) and validators.ipv4(incoming_ip):
                # associate the ipv6 we found with the incoming ipv4 and vice versa
                self.set_ipv6_of_profile(profileid, [found_ip])
                self.set_ipv4_of_profile(f'profile_{found_ip}', incoming_ip)
            elif validators.ipv6(found_ip) and validators.ipv6(incoming_ip):
                # If 2 IPV6 are claiming to have the same MAC it's fine
                # a computer is allowed to have many ipv6
                # add this found ipv6 to the list of ipv6 of the incoming ip(profileid)
                ipv6: str = self.r.hmget(profileid, 'IPv6')[0]
                if not ipv6:
                    ipv6 = [found_ip]
                else:
                    # found a list of ipv6 in the db
                    ipv6: set = set(json.loads(ipv6))
                    ipv6.add(found_ip)
                    ipv6 = list(ipv6)
                self.set_ipv6_of_profile(profileid, ipv6)

                # add this incoming ipv6(profileid) to the list of ipv6 of the found ip
                ipv6: str = self.r.hmget(f'profile_{found_ip}', 'IPv6')[0]
                if not ipv6:
                    ipv6 = [incoming_ip]
                else:
                    # found a list of ipv6 in the db
                    ipv6: set = set(json.loads(ipv6))
                    ipv6.add(incoming_ip)
                    #convert to list
                    ipv6 = list(ipv6)
                self.set_ipv6_of_profile(f'profile_{found_ip}', ipv6)

            else:
                # both are ipv4 and are claiming to have the same mac address
                # OR one of them is 0.0.0.0 and didn't take an ip yet
                # will be detected later by the ARP module
                return False

            # add the incoming ip to the list of ips that belong to this mac
            cached_ips.add(incoming_ip)
            cached_ips = json.dumps(list(cached_ips))
            self.r.hset('MAC', MAC_info['MAC'], cached_ips)

        return True

    def get_mac_addr_from_profile(self, profileid) -> str:
        """
        Returns MAC info about a certain profile or None
        """
        if not profileid:
            # profileid is None if we're dealing with a profile
            # outside of home_network when this param is given
            return False
        if MAC_info := self.r.hget(profileid, 'MAC'):
            return json.loads(MAC_info)['MAC']
        else:
            return MAC_info

    def get_mac_vendor_from_profile(self, profileid) -> str:
        """
        Returns MAC vendor about a certain profile or None
        """
        if not profileid:
            # profileid is None if we're dealing with a profile
            # outside of home_network when this param is given
            return False
        if MAC_info := self.r.hget(profileid, 'MAC'):
            return json.loads(MAC_info)['Vendor']
        else:
            return MAC_info

    def get_hostname_from_profile(self, profileid) -> str:
        """
        Returns hostname about a certain profile or None
        """
        if not profileid:
            # profileid is None if we're dealing with a profile
            # outside of home_network when this param is given
            return False
        if MAC_info := self.r.hget(profileid, 'MAC'):
            return json.loads(MAC_info).get('host_name', False)
        else:
            return MAC_info

    def get_ipv4_from_profile(self, profileid) -> str:
        """
        Returns ipv4 about a certain profile or None
        """
        return self.r.hmget(profileid, 'IPv4')[0] if profileid else False

    def get_ipv6_from_profile(self, profileid) -> str:
        """
        Returns ipv6 about a certain profile or None
        """
        return self.r.hmget(profileid, 'IPv6')[0] if profileid else False

    def get_the_other_ip_version(self, profileid):
        """
        Given an ipv4, returns the ipv6 of the same computer
        Given an ipv6, returns the ipv4 of the same computer
        """
        if not profileid:
            # profileid is None if we're dealing with a profile
            # outside of home_network when this param is given
            return False
        srcip = profileid.split('_')[1]
        ip = False
        if validators.ipv4(srcip):
            ip = self.get_ipv6_from_profile(profileid)
        elif validators.ipv6(srcip):
            ip = self.get_ipv4_from_profile(profileid)

        return ip

    def getProfileIdFromIP(self, daddr_as_obj):
        """Receive an IP and we want the profileid"""
        try:
            profileid = f'profile{self.separator}{str(daddr_as_obj)}'
            if self.r.sismember('profiles', profileid):
                return profileid
            return False
        except redis.exceptions.ResponseError as inst:
            self.outputqueue.put(
                '00|database|error in addprofileidfromip in database.py'
            )
            self.outputqueue.put(f'00|database|{type(inst)}')
            self.outputqueue.put(f'00|database|{inst}')

    def getProfiles(self):
        """Get a list of all the profiles"""
        profiles = self.r.smembers('profiles')
        return profiles if profiles != set() else {}


    def getTWsfromProfile(self, profileid):
        """
        Receives a profile id and returns the list of all the TW in that profile
        Returns a list of tuples (twid, ts) or an empty list
        """
        return (
            self.r.zrange(f'tws{profileid}', 0, -1, withscores=True)
            if profileid
            else False
        )

    def getamountTWsfromProfile(self, profileid):
        """
        Receives a profile id and returns the number of all the TWs in that profile
        """
        return len(self.getTWsfromProfile(profileid)) if profileid else False

    def getSrcIPsfromProfileTW(self, profileid, twid):
        """
        Get the src ip for a specific TW for a specific profileid
        """
        return self.r.hget(profileid + self.separator + twid, 'SrcIPs')

    def getDstIPsfromProfileTW(self, profileid, twid):
        """
        Get the dst ip for a specific TW for a specific profileid
        """
        return self.r.hget(profileid + self.separator + twid, 'DstIPs')

    def getT2ForProfileTW(self, profileid, twid, tupleid, tuple_key: str):
        """
        Get T1 and the previous_time for this previous_time, twid and tupleid
        """
        try:
            hash_id = profileid + self.separator + twid
            data = self.r.hget(hash_id, tuple_key)
            if not data:
                return False, False
            data = json.loads(data)
            try:
                (_, previous_two_timestamps) = data[tupleid]
                return previous_two_timestamps
            except KeyError:
                return False, False
        except Exception as e:
            exception_line = sys.exc_info()[2].tb_lineno
            self.outputqueue.put(
                f'01|database|[DB] Error in getT2ForProfileTW in database.py line {exception_line}'
            )

            self.outputqueue.put(f'01|database|[DB] {type(e)}')
            self.outputqueue.put(f'01|database|[DB] {e}')
            self.outputqueue.put(
                f'01|profiler|[Profile] {traceback.format_exc()}'
            )

    def has_profile(self, profileid):
        """Check if we have the given profile"""
        return self.r.sismember('profiles', profileid) if profileid else False

    def getProfilesLen(self):
        """Return the amount of profiles. Redis should be faster than python to do this count"""
        return self.r.scard('profiles')

    def getLastTWforProfile(self, profileid):
        """Return the last TW id and the time for the given profile id"""
        return (
            self.r.zrange(f'tws{profileid}', -1, -1, withscores=True)
            if profileid
            else False
        )

    def getFirstTWforProfile(self, profileid):
        """Return the first TW id and the time for the given profile id"""
        return (
            self.r.zrange(f'tws{profileid}', 0, 0, withscores=True)
            if profileid
            else False
        )

    def getTWofTime(self, profileid, time):
        """
        Return the TW id and the time for the TW that includes the given time.
        The score in the DB is the start of the timewindow, so we should search
        a TW that includes the given time by making sure the start of the TW
        is < time, and the end of the TW is > time.
        """
        # [-1] so we bring the last TW that matched this time.
        try:
            data = self.r.zrangebyscore(
                f'tws{profileid}',
                float('-inf'),
                float(time),
                withscores=True,
                start=0,
                num=-1
            )[-1]

        except IndexError:
            # We dont have any last tw?
            data = self.r.zrangebyscore(
                f'tws{profileid}',
                0,
                float(time),
                withscores=True,
                start=0,
                num=-1
            )

        return data

    def addNewOlderTW(self, profileid, startoftw):
        try:
            """
            Creates or adds a new timewindow that is OLDER than the first we have
            Return the id of the timewindow just created
            """
            # Get the first twid and obtain the new tw id
            try:
                (firstid, firstid_time) = self.getFirstTWforProfile(profileid)[
                    0
                ]
                # We have a first id
                # Decrement it!!
                twid = 'timewindow' + str(
                    int(firstid.split('timewindow')[1]) - 1
                )
            except IndexError:
                # Very weird error, since the first TW MUST exist. What are we doing here?
                pass
            # Add the new TW to the index of TW
            data = {str(twid): float(startoftw)}
            self.r.zadd(f'tws{profileid}', data)
            self.outputqueue.put(
                f'04|database|[DB]: Created and added to DB the new older TW with id {twid}. Time: {startoftw} '
            )

            # The creation of a TW now does not imply that it was modified. You need to put data to mark is at modified
            return twid
        except redis.exceptions.ResponseError as e:
            self.outputqueue.put(
                '01|database|error in addNewOlderTW in database.py', 0, 1
            )
            self.outputqueue.put(f'01|database|{type(e)}', 0, 1)
            self.outputqueue.put(f'01|database|{e}', 0, 1)



    def addNewTW(self, profileid, startoftw):
        try:
            """
            Creates or adds a new timewindow to the list of tw for the given profile
            Add the twid to the ordered set of a given profile
            Return the id of the timewindow just created
            We should not mark the TW as modified here, since there is still no data on it, and it may remain without data.
            """
            # Get the last twid and obtain the new tw id
            try:
                (lastid, lastid_time) = self.getLastTWforProfile(profileid)[0]
                # We have a last id
                # Increment it
                twid = 'timewindow' + str(
                    int(lastid.split('timewindow')[1]) + 1
                )
            except IndexError:
                # There is no first TW, create it
                twid = 'timewindow1'
            # Add the new TW to the index of TW
            data = {twid: float(startoftw)}
            self.r.zadd(f'tws{profileid}', data)
            self.outputqueue.put(
                f'04|database|[DB]: Created and added to DB for profile {profileid} on TW with id {twid}. Time: {startoftw} '
            )

            # The creation of a TW now does not imply that it was modified. You need to put data to mark is at modified

            # When a new TW is created for this profile,
            # change the threat level of the profile to 0(info) and confidence to 0.05
            self.update_threat_level(profileid, 'info',  0.5)
            return twid
        except redis.exceptions.ResponseError as e:
            self.outputqueue.put('01|database|Error in addNewTW')
            self.outputqueue.put(f'01|database|{e}')

    def getTimeTW(self, profileid, twid):
        """Return the time when this TW in this profile was created"""
        # Get all the TW for this profile
        # We need to encode it to 'search' because the data in the sorted set is encoded
        return self.r.zscore(f'tws{profileid}', twid.encode('utf-8'))

    def getAmountTW(self, profileid):
        """Return the number of tws for this profile id"""
        return self.r.zcard(f'tws{profileid}') if profileid else False

    def getModifiedTWSinceTime(self, time):
        """Return the list of modified timewindows since a certain time"""
        data = self.r.zrangebyscore(
            'ModifiedTW', time, float('+inf'), withscores=True
        )
        return data or []

    def getModifiedProfilesSince(self, time):
        """Returns a set of modified profiles since a certain time and the time of the last modified profile"""
        modified_tws = self.getModifiedTWSinceTime(time)
        if not modified_tws:
            # no modified tws, and no time_of_last_modified_tw
            return [], 0
        # get the time of last modified tw
        time_of_last_modified_tw = modified_tws[-1][-1]
        # this list will store modified profiles without tws
        profiles = []
        profiles.extend(
            modified_tw[0].split('_')[1] for modified_tw in modified_tws
        )
        # return a set of unique profiles
        return set(profiles), time_of_last_modified_tw

    def getModifiedTW(self):
        """Return all the list of modified tw"""
        data = self.r.zrange('ModifiedTW', 0, -1, withscores=True)
        return data or []

    def wasProfileTWModified(self, profileid, twid):
        """Retrieve from the db if this TW of this profile was modified"""
        data = self.r.zrank('ModifiedTW', profileid + self.separator + twid)
        return bool(data)

    def setSlipsInternalTime(self, timestamp):
        self.r.set('slips_internal_time', timestamp)

    def get_data_from_profile_tw(self, hash_key: str, key_name: str):
        try:
            """
            key_name = [Src,Dst] + [Port,IP] + [Client,Server] + [TCP,UDP, ICMP, ICMP6] + [Established, NotEstablihed]
            Example: key_name = 'SrcPortClientTCPEstablished'
            """
            data = self.r.hget(hash_key, key_name)
            value = {}
            if data:
                portdata = json.loads(data)
                value = portdata
            return value
        except Exception:
            exception_line = sys.exc_info()[2].tb_lineno
            self.outputqueue.put(
                f'01|database|[DB] Error in getDataFromProfileTW in database.py line {exception_line}'
            )
            self.outputqueue.put(f'01|database|[DB] {traceback.print_exc()}')

    def getOutTuplesfromProfileTW(self, profileid, twid):
        """Get the out tuples"""
        return self.r.hget(profileid + self.separator + twid, 'OutTuples')

    def getInTuplesfromProfileTW(self, profileid, twid):
        """Get the in tuples"""
        return self.r.hget(profileid + self.separator + twid, 'InTuples')

    def getFieldSeparator(self):
        """Return the field separator"""
        return self.separator


    def get_dhcp_flows(self, profileid, twid) -> list:
        """
        returns a dict of dhcp flows that happened in this profileid and twid
        """
        if flows := self.r.hget('DHCP_flows', f'{profileid}_{twid}'):
            return json.loads(flows)


    def set_dhcp_flow(self, profileid, twid, requested_addr, uid):
        """
        Stores all dhcp flows sorted by profileid_twid
        """
        flow = {requested_addr: uid}
        if cached_flows := self.get_dhcp_flows(profileid, twid):
            # we already have flows in this twid, update them
            cached_flows.update(flow)
            self.r.hset('DHCP_flows', f'{profileid}_{twid}', json.dumps(cached_flows))
        else:
            self.r.hset('DHCP_flows', f'{profileid}_{twid}', json.dumps(flow))


    def update_threat_level(self, profileid, threat_level: str, confidence):
        """
        Update the threat level of a certain profile
        :param threat_level: available options are 'low', 'medium' 'critical' etc
        """

        self.r.hset(profileid, 'threat_level', threat_level)
        now = time.time()
        now = utils.convert_format(now, utils.alerts_format)
        # keep track of old threat levels
        confidence = f'confidence: {confidence}'
        past_threat_levels = self.r.hget(profileid, 'past_threat_levels')
        # this is what we'll be storing in the db, tl, ts, and confidence
        threat_level_data = (threat_level, now, confidence)
        if past_threat_levels:
            # get the lists of ts and past threat levels
            past_threat_levels = json.loads(past_threat_levels)
            latest_threat_level, latest_ts, latest_confidence = past_threat_levels[-1]
            if (
                    latest_threat_level == threat_level
                    and latest_confidence == confidence
            ):
                # if the past threat level and confidence are the same as the ones we wanna store,
                # replace the timestamp only
                past_threat_levels[-1] = threat_level_data
            else:
                # add this threat level to the list of past threat levels
                past_threat_levels.append(threat_level_data)
        else:
            # first time setting a threat level for this profile
            past_threat_levels = [threat_level_data]
            # threat_levels_update_time = [now]

        past_threat_levels = json.dumps(past_threat_levels)
        self.r.hset(profileid, 'past_threat_levels', past_threat_levels)

        # set the score and confidence of the given ip in the db when it causes an evidence
        # these 2 values will be needed when sharing with peers
        ip = profileid.split('_')[-1]
        # get the numerical value of this threat level
        score = utils.threat_levels[threat_level.lower()]
        score_confidence = {
            'score': score,
            'confidence': confidence
        }
        if cached_ip_data := self.getIPData(ip):
            # append the score and conf. to the already existing data
            cached_ip_data.update(score_confidence)
            self.rcache.hset('IPsInfo', ip, json.dumps(cached_ip_data))
        else:
            self.rcache.hset('IPsInfo', ip, json.dumps(score_confidence))

    def set_evidence_causing_alert(self, profileid, twid, alert_ID, evidence_IDs: list):
        """
        When we have a bunch of evidence causing an alert,
        we associate all evidence IDs with the alert ID in our database
        this function stores evidence in 'alerts' key only
        :param alert ID: the profileid_twid_ID of the last evidence causing this alert
        :param evidence_IDs: all IDs of the evidence causing this alert
        """
        old_profileid_twid_alerts: dict = self.get_profileid_twid_alerts(profileid, twid)

        alert = {
            alert_ID: json.dumps(evidence_IDs)
        }

        if old_profileid_twid_alerts:
            # update previous alerts for this profileid twid
            # add the alert we have to the old alerts of this profileid_twid
            old_profileid_twid_alerts.update(alert)
            profileid_twid_alerts = json.dumps(old_profileid_twid_alerts)
        else:
            # no previous alerts for this profileid twid
            profileid_twid_alerts = json.dumps(alert)


        self.r.hset(f'{profileid}{self.separator}{twid}', 'alerts', profileid_twid_alerts)

        # the structure of alerts key is
        # alerts {
        #     profile_<ip>: {
        #               twid1: {
        #                   alert_ID1: [evidence_IDs],
        #                   alert_ID2: [evidence_IDs]
        #                  }
        #             }
        # }

        profile_alerts = self.r.hget('alerts', profileid)
        # alert ids look like this profile_192.168.131.2_timewindow1_92a3b9c2-330b-47ab-b73e-c5380af90439
        alert_hash = alert_ID.split('_')[-1]
        alert = {
            twid: {
                alert_hash: evidence_IDs
            }
        }
        if not profile_alerts:
            # first alert in this profile
            alert = json.dumps(alert)
            self.r.hset('alerts', profileid, alert)
            return

        # the format of this dict is {twid1: {alert_hash: [evidence_IDs]},
        #                              twid2: {alert_hash: [evidence_IDs]}}
        profile_alerts:dict = json.loads(profile_alerts)

        if twid not in profile_alerts:
            # first time having an alert for this twid
            profile_alerts.update(alert)
        else:
            # we already have a twid with alerts in this profile, update it
            # the format of twid_alerts is {alert_hash: evidence_IDs}
            twid_alerts: dict = profile_alerts[twid]
            twid_alerts[alert_hash] = evidence_IDs
            profile_alerts[twid] = twid_alerts

        profile_alerts = json.dumps(profile_alerts)
        self.r.hset('alerts', profileid, profile_alerts)


    def get_timewindow(self, flowtime, profileid):
        """
        This function should get the id of the TW in the database where the flow belong.
        If the TW is not there, we create as many tw as necessary in the future or past until we get the correct TW for this flow.
        - We use this function to avoid retrieving all the data from the DB for the complete profile. We use a separate table for the TW per profile.
        -- Returns the time window id
        THIS IS NOT WORKING:
        - The empty profiles in the middle are not being created!!!
        - The Dtp ips are stored in the first time win
        """
        try:
            # First check if we are not in the last TW. Since this will be the majority of cases
            try:
                if not profileid:
                    # profileid is None if we're dealing with a profile
                    # outside of home_network when this param is given
                    return False
                [(lasttwid, lasttw_start_time)] = self.getLastTWforProfile(profileid)
                lasttw_start_time = float(lasttw_start_time)
                lasttw_end_time = lasttw_start_time + self.width
                flowtime = float(flowtime)
                self.print(
                    f'The last TW id for profile {profileid} was {lasttwid}. Start:{lasttw_start_time}. End: {lasttw_end_time}',
                    3,
                    0,
                )
                # There was a last TW, so check if the current flow belongs here.
                if (
                    lasttw_end_time > flowtime
                    and lasttw_start_time <= flowtime
                ):
                    self.print(
                        f'The flow ({flowtime}) is on the last time window ({lasttw_end_time})',
                        3,
                        0,
                    )
                    twid = lasttwid
                elif lasttw_end_time <= flowtime:
                    # The flow was not in the last TW, its NEWER than it
                    self.print(
                        f'The flow ({flowtime}) is NOT on the last time window ({lasttw_end_time}). Its newer',
                        3,
                        0,
                    )
                    amount_of_new_tw = int(
                        (flowtime - lasttw_end_time) / self.width
                    )
                    self.print(
                        f'We have to create {amount_of_new_tw} empty TWs in the midle.',
                        3,
                        0,
                    )
                    temp_end = lasttw_end_time
                    for _ in range(amount_of_new_tw + 1):
                        new_start = temp_end
                        twid = self.addNewTW(profileid, new_start)
                        self.print(f'Creating the TW id {twid}. Start: {new_start}.', 3, 0)
                        temp_end = new_start + self.width
                        # Now get the id of the last TW so we can return it
                else:
                    # The flow was not in the last TW, its OLDER that it
                    self.print(
                        f'The flow ({flowtime}) is NOT on the last time window ({lasttw_end_time}). Its older',
                        3,
                        0,
                    )
                    if data := __database__.getTWofTime(profileid, flowtime):
                        # We found a TW where this flow belongs to
                        (twid, tw_start_time) = data
                        return twid
                    else:
                        # There was no TW that included the time of this flow, so create them in the past
                        # How many new TW we need in the past?
                        # amount_of_new_tw is the total amount of tw we should have under the new situation
                        amount_of_new_tw = int(
                            (lasttw_end_time - flowtime) / self.width
                        )
                        # amount_of_current_tw is the real amount of tw we have now
                        amount_of_current_tw = (
                            __database__.getamountTWsfromProfile(profileid)
                        )
                        # diff is the new ones we should add in the past. (Yes, we could have computed this differently)
                        diff = amount_of_new_tw - amount_of_current_tw
                        self.print(f'We need to create {diff + 1} TW before the first', 3, 0)
                        # Get the first TW
                        [
                            (firsttwid, firsttw_start_time)
                        ] = __database__.getFirstTWforProfile(profileid)
                        firsttw_start_time = float(firsttw_start_time)
                        # The start of the new older TW should be the first - the width
                        temp_start = firsttw_start_time - self.width
                        for _ in range(diff + 1):
                            new_start = temp_start
                            # The method to add an older TW is the same as
                            # to add a new one, just the starttime changes
                            twid = __database__.addNewOlderTW(
                                profileid, new_start
                            )
                            self.print(f'Creating the new older TW id {twid}. Start: {new_start}.', 3, 0)
                            temp_start = new_start - self.width
            except ValueError:
                # There is no last tw. So create the first TW
                # If the option for only-one-tw was selected, we should create the TW at least 100 years before the flowtime, to cover for
                # 'flows in the past'. Which means we should cover for any flow that is coming later with time before the first flow
                if self.width == 9999999999:
                    # Seconds in 1 year = 31536000
                    startoftw = float(flowtime - (31536000 * 100))
                else:
                    startoftw = flowtime

                # Add this TW, of this profile, to the DB
                twid = self.addNewTW(profileid, startoftw)
                # self.print("First TW ({}) created for profile {}.".format(twid, profileid), 0, 1)
            return twid
        except Exception as e:
            self.print('Error in get_timewindow().', 0, 1)
            self.print(f'{e}', 0, 1)

    def get_profileid_twid_alerts(self, profileid, twid) -> dict:
        """
        The format for the returned dict is
            {profile123_twid1_<alert_uuid>: [ev_uuid1, ev_uuid2, ev_uuid3]}
        """
        alerts = self.r.hget(f'{profileid}{self.separator}{twid}', 'alerts')
        if not alerts:
            return {}
        alerts = json.loads(alerts)
        return alerts

    def get_evidence_causing_alert(self, profileid, twid, alert_ID) -> list:
        """
        Returns all the IDs of evidence causing this alert
        :param alert_ID: ID of alert to export to warden server
        for example profile_10.0.2.15_timewindow1_4e4e4774-cdd7-4e10-93a3-e764f73af621
        """
        if alerts := self.r.hget(f'{profileid}{self.separator}{twid}', 'alerts'):
            alerts = json.loads(alerts)
            return alerts.get(alert_ID, False)
        return False

    def get_evidence_by_ID(self, profileid, twid, ID):

        evidence = self.getEvidenceForTW(profileid, twid)
        if not evidence:
            return False

        evidence: dict = json.loads(evidence)
        # loop through each evidence in this tw
        for evidence_details in evidence.values():
            evidence_details = json.loads(evidence_details)
            if evidence_details.get('ID') == ID:
                # found an evidence that has a matching ID
                return evidence_details

    def is_detection_disabled(self, evidence_type: str):
        """
        Function to check if detection is disabled in slips.conf
        """
        for disabled_detection in self.disabled_detections:
            # when we disable a detection , we add 'SSHSuccessful' in slips.conf,
            # however our evidence can depend on an addr, for example 'SSHSuccessful-by-addr'.
            # check if any disabled detection is a part of our evidence.
            # for example 'SSHSuccessful' is a part of 'SSHSuccessful-by-addr' so if  'SSHSuccessful'
            # is disabled,  'SSHSuccessful-by-addr' should also be disabled
            if disabled_detection in evidence_type:
                return True
        return False


    def set_flow_causing_evidence(self, uids: list, evidence_ID):
        self.r.hset("flows_causing_evidence", evidence_ID, json.dumps(uids))

    def get_flows_causing_evidence(self, evidence_ID) -> list:
        uids = self.r.hget("flows_causing_evidence", evidence_ID)
        return json.loads(uids) if uids else []


    def setEvidence(
            self,
            evidence_type,
            attacker_direction,
            attacker,
            threat_level,
            confidence,
            description,
            timestamp,
            category,
            source_target_tag=False,
            conn_count=False,
            port=False,
            proto=False,
            profileid='',
            twid='',
            uid=''
    ):
        """
        Set the evidence for this Profile and Timewindow.

        evidence_type: determine the type of this evidence. e.g. PortScan, ThreatIntelligence
        attacker_direction: the type of value causing the detection e.g. dstip, srcip, dstdomain, md5, url
        attacker: the actual srcip or dstdomain. e.g. 1.1.1.1 or abc.com
        threat_level: determine the importance of the evidence, available options are:
                        info, low, medium, high, critical
        confidence: determine the confidence of the detection on a scale from 0 to 1.
                        (How sure you are that this is what you say it is.)
        uid: can be a single uid as a str, or a list of uids causing the evidence.
                        needed to get the flow from the database.
        category: what is this evidence category according to IDEA categories
        conn_count: the number of packets/flows/nxdomains that formed this scan/sweep/DGA.

        source_target_tag:
            this is the IDEA category of the source and dst ip used in the evidence
            if the attacker_direction is srcip this describes the source ip,
            if the attacker_direction is dstip this describes the dst ip.
            supported source and dst types are in the SourceTargetTag section https://idea.cesnet.cz/en/classifications
            this is a keyword/optional argument because it shouldn't be used with dports and sports attacker_direction
        """


        # Ignore evidence if it's disabled in the configuration file
        if self.is_detection_disabled(evidence_type):
            return False

        if not twid:
            twid = ''

        # every evidence should have an ID according to the IDEA format
        evidence_ID = str(uuid4())

        if type(uid) == list:
            # some evidence are caused by several uids, use the last one only
            # todo check why we have duplicates in the first place
            # remove duplicate uids
            uids = list(set(uid))
        else:
            uids = [uid]

        self.set_flow_causing_evidence(uids, evidence_ID)

        if type(threat_level) != str:
            # make sure we always store str threat levels in the db
            threat_level = utils.threat_level_to_string(threat_level)

        if timestamp:
            timestamp = utils.convert_format(timestamp, utils.alerts_format)

        evidence_to_send = {
            'profileid': str(profileid),
            'twid': str(twid),
            'attacker_direction': attacker_direction,
            'attacker': attacker,
            'evidence_type': evidence_type,
            'description': description,
            'stime': timestamp,
            'uid': uids,
            'confidence': confidence,
            'threat_level': threat_level,
            'category': category,
            'ID': evidence_ID,
        }
        # not all evidence requires a conn_coun, scans only
        if conn_count:
            evidence_to_send['conn_count'] = conn_count

        # source_target_tag is defined only if attacker_direction is srcip or dstip
        if source_target_tag:
            evidence_to_send['source_target_tag'] = source_target_tag

        if port:
            evidence_to_send['port'] = port
        if proto:
            evidence_to_send['proto'] = proto

        evidence_to_send = json.dumps(evidence_to_send)


        # Check if we have and get the current evidence stored in the DB for
        # this profileid in this twid
        current_evidence = self.getEvidenceForTW(profileid, twid)
        current_evidence = json.loads(current_evidence) if current_evidence else {}
        should_publish = evidence_ID not in current_evidence.keys()
        # update our current evidence for this profileid and twid.
        # now the evidence_ID is used as the key
        current_evidence.update({evidence_ID: evidence_to_send})

        # Set evidence in the database.
        current_evidence = json.dumps(current_evidence)
        self.r.hset(
            profileid + self.separator + twid, 'Evidence', current_evidence
        )

        self.r.hset(f'evidence{profileid}', twid, current_evidence)

        # This is done to ignore repetition of the same evidence sent.
        # note that publishing HAS TO be done after updating the 'Evidence' keys
        if should_publish:
            self.publish('evidence_added', evidence_to_send)

        # an evidence is generated for this profile
        # update the threat level of this profile
        if attacker_direction in ('sip', 'srcip'):
            # the srcip is the malicious one
            self.update_threat_level(profileid, threat_level, confidence)
        elif attacker_direction in ('dip', 'dstip'):
            # the dstip is the malicious one
            self.update_threat_level(f'profile_{attacker}', threat_level, confidence)


        return True

    def mark_evidence_as_processed(self, evidence_ID):
        """
        If an evidence was processed by the evidenceprocess, mark it in the db
        """
        self.r.sadd('processed_evidence', evidence_ID)

    def is_evidence_processed(self, evidence_ID):
        return self.r.sismember('processed_evidence', evidence_ID)

    def store_tranco_whitelisted_domain(self, domain):
        """
        store whitelisted domain from tranco whitelist in the db
        """
        # the reason we store tranco whitelisted domains in the cache db
        # instead of the main db is, we don't want them cleared on every new instance of slips
        self.rcache.sadd('tranco_whitelisted_domains', domain)

    def is_whitelisted_tranco_domain(self, domain):
        return self.rcache.sismember('tranco_whitelisted_domains', domain)



    def set_evidence_for_profileid(self, evidence):
        """
        Set evidence for the profile in the same format as json in alerts.json
        """
        evidence = json.dumps(evidence)
        self.r.sadd('Evidence', evidence)


    def deleteEvidence(self, profileid, twid, evidence_ID: str):
        """
        Delete evidence from the database
        """
        # 1. delete evidence from 'evidence' key
        current_evidence = self.getEvidenceForTW(profileid, twid)
        current_evidence = json.loads(current_evidence) if current_evidence else {}
        # Delete the key regardless of whether it is in the dictionary
        current_evidence.pop(evidence_ID, None)
        current_evidence_json = json.dumps(current_evidence)
        self.r.hset(
            profileid + self.separator + twid,
            'Evidence',
            current_evidence_json,
        )
        self.r.hset(f'evidence{profileid}', twid, current_evidence_json)
        # 2. delete evidence from 'alerts' key
        profile_alerts = self.r.hget('alerts', profileid)
        if not profile_alerts:
            # this means that this evidence wasn't a part of an alert
            # give redis time to the save the changes before calling this function again
            # removing this sleep will cause this function to be called again before
            # deleting the evidence ID from the evidence keys
            time.sleep(0.5)
            return

        profile_alerts:dict = json.loads(profile_alerts)
        try:
            # we already have a twid with alerts in this profile, update it
            # the format of twid_alerts is {alert_hash: evidence_IDs}
            twid_alerts: dict = profile_alerts[twid]
            IDs = False
            hash = False
            for alert_hash, evidence_IDs in twid_alerts.items():
                if evidence_ID in evidence_IDs:
                    IDs = evidence_IDs
                    hash = alert_hash
                break
            else:
                return

            if IDs and hash:
                evidence_IDs = IDs.remove(evidence_ID)
                alert_ID = f'{profileid}_{twid}_{hash}'
                if evidence_IDs:
                    self.set_evidence_causing_alert(
                        profileid, twid, alert_ID, evidence_IDs
                    )

        except KeyError:
            # alert not added to the 'alerts' key yet!
            # this means that this evidence wasn't a part of an alert
            return

    def cache_whitelisted_evidence_ID(self, evidence_ID:str):
        """
        Keep track of whitelisted evidence IDs to avoid showing them in alerts later
        """
        # without this function, slips gets the stored evidence id from the db,
        # before deleteEvidence is called, so we need to keep track of whitelisted evidence ids
        self.r.sadd('whitelisted_evidence', evidence_ID)

    def is_whitelisted_evidence(self, evidence_ID):
        """
        Check if we have the evidence ID as whitelisted in the db to avoid showing it in alerts
        """
        return self.r.sismember('whitelisted_evidence', evidence_ID)

    def remove_whitelisted_evidence(self, all_evidence:str) -> str:
        """
        param all_evidence serialized json dict
        returns a serialized json dict
        """
        # remove whitelisted evidence from the given evidence
        all_evidence = json.loads(all_evidence)
        tw_evidence = {}
        for ID,evidence in all_evidence.items():
            if self.is_whitelisted_evidence(ID):
                continue
            tw_evidence[ID] = evidence
        return json.dumps(tw_evidence)

    def getEvidenceForTW(self, profileid, twid):
        """Get the evidence for this TW for this Profile"""
        evidence = self.r.hget(profileid + self.separator + twid, 'Evidence')
        if evidence:
            evidence = self.remove_whitelisted_evidence(evidence)
        return evidence

    def checkBlockedProfTW(self, profileid, twid):
        """
        Check if profile and timewindow is blocked
        """
        profile_tws = self.getBlockedProfTW(profileid)
        return twid in profile_tws

    def set_first_stage_ensembling_label_to_flow(
        self, profileid, twid, uid, ensembling_label
    ):
        """
        Add a final label to the flow
        """
        if flow := self.get_flow(profileid, twid, uid):
            data = json.loads(flow[uid])
            data['1_ensembling_label'] = ensembling_label
            data = json.dumps(data)
            self.r.hset(
                profileid + self.separator + twid + self.separator + 'flows',
                uid,
                data,
            )

    def set_growing_zeek_dir(self):
        """
        Mark a dir as growing so it can be treated like the zeek logs generated by an interface
        """
        self.r.set('growing_zeek_dir', 'yes')

    def is_growing_zeek_dir(self):
        """ Did slips mark the given dir as growing?"""
        return 'yes' in str(self.r.get('growing_zeek_dir'))

    def set_module_label_to_flow(
        self, profileid, twid, uid, module_name, module_label
    ):
        """
        Add a module label to the flow
        """
        flow = self.get_flow(profileid, twid, uid)
        if flow and flow[uid]:
            data = json.loads(flow[uid])
            # here we dont care if add new module lablel or changing existing one
            data['module_labels'][module_name] = module_label
            data = json.dumps(data)
            self.r.hset(
                profileid + self.separator + twid + self.separator + 'flows',
                uid,
                data,
            )
            return True
        return False

    def get_module_labels_from_flow(self, profileid, twid, uid):
        """
        Get the label from the flow
        """
        flow = self.get_flow(profileid, twid, uid)
        if flow and flow.get(uid, False):
            flow = json.loads(flow[uid])
            return flow.get('module_labels', '')
        else:
            return {}

    def markProfileTWAsBlocked(self, profileid, twid):
        """Add this profile and tw to the list of blocked"""
        tws = self.getBlockedProfTW(profileid)
        tws.append(twid)
        self.r.hset('BlockedProfTW', profileid, json.dumps(tws))

    def getAllBlockedProfTW(self):
        """Return all the list of blocked tws"""
        return self.r.hgetall('BlockedProfTW')

    def getBlockedProfTW(self, profileid):
        """Return all the list of blocked tws"""
        if tws := self.r.hget('BlockedProfTW', profileid):
            return json.loads(tws)
        return []

    def getIPIdentification(self, ip: str, get_ti_data=True):
        """
        Return the identification of this IP based
        on the data stored so far
        :param get_ti_data: do we want to get info about this IP from out TI lists?
        """
        current_data = self.getIPData(ip)
        identification = ''
        if current_data:
            if 'asn' in current_data:
                asn_details = ''
                if asnorg := current_data['asn'].get('org', ''):
                    asn_details += f'{asnorg} '

                if number := current_data['asn'].get('number', ''):
                    asn_details += f'{number} '

                if len(asn_details) >1:
                    identification += f'AS: {asn_details}'

            if 'SNI' in current_data:
                SNI = current_data['SNI']
                if type(SNI) == list:
                    SNI = SNI[0]
                identification += 'SNI: ' + SNI['server_name'] + ', '

            if 'reverse_dns' in current_data:
                identification += 'rDNS: ' + current_data['reverse_dns'] + ', '

            if 'threatintelligence' in current_data and get_ti_data:
                identification += (
                    'Description: '
                    + current_data['threatintelligence']['description']
                    + ', '
                )

                tags: list = current_data['threatintelligence'].get('tags', False)
                # remove brackets
                if tags:
                    identification += f'tags= {tags}  '

        identification = identification[:-2]
        return identification

    def get_multiaddr(self):
        """
        this is can only be called when p2p is enabled, this value is set by p2p pigeon
        """
        return self.r.get('multiAddress')

    def getURLData(self, url):
        """
        Return information about this URL
        Returns a dictionary or False if there is no IP in the database
        We need to separate these three cases:
        1- IP is in the DB without data. Return empty dict.
        2- IP is in the DB with data. Return dict.
        3- IP is not in the DB. Return False
        """
        data = self.rcache.hget('URLsInfo', url)
        data = json.loads(data) if data else False
        return data


    def setNewURL(self, url: str):
        """
        1- Stores this new URL in the URLs hash
        2- Publishes in the channels that there is a new URL, and that we want
            data from the Threat Intelligence modules
        """
        data = self.getURLData(url)
        if data is False:
            # If there is no data about this URL
            # Set this URL for the first time in the URLsInfo
            # Its VERY important that the data of the first time we see a URL
            # must be '{}', an empty dictionary! if not the logic breaks.
            # We use the empty dictionary to find if an URL exists or not
            self.rcache.hset('URLsInfo', url, '{}')

    def setInfoForURLs(self, url: str, urldata: dict):
        """
        Store information for this URL
        We receive a dictionary, such as {'VirusTotal': {'URL':score}} that we are
        going to store for this IP.
        If it was not there before we store it. If it was there before, we
        overwrite it
        """
        data = self.getURLData(url)
        if data is False:
            # This URL is not in the dictionary, add it first:
            self.setNewURL(url)
            # Now get the data, which should be empty, but just in case
            data = self.getIPData(url)
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
                self.rcache.hset('URLsInfo', url, newdata_str)
        else:
            # URL found in the database but has no keys , set the keys now
            urldata = json.dumps(urldata)
            self.rcache.hset('URLsInfo', url, urldata)

    def subscribe(self, channel: str, ignore_subscribe_messages=False):
        """Subscribe to channel"""
        # For when a TW is modified
        if channel not in self.supported_channels:
            return False

        self.pubsub = self.r.pubsub()
        self.pubsub.subscribe(
            channel, ignore_subscribe_messages=ignore_subscribe_messages
        )
        return self.pubsub

    def publish_stop(self):
        """
        Publish stop command to terminate slips
        to shutdown slips gracefully, this function should only be used by slips.py
        """
        all_channels_list = self.r.pubsub_channels()
        self.print('Sending the stop signal to all listeners', 0, 3)
        for channel in all_channels_list:
            self.r.publish(channel, 'stop_process')

    def get_all_flows_in_profileid_twid(self, profileid, twid):
        """
        Return a list of all the flows in this profileid and twid
        """
        if data := self.r.hgetall(
            profileid + self.separator + twid + self.separator + 'flows'
        ):
            return data

    def get_all_flows_in_profileid(self, profileid):
        """
        Return a list of all the flows in this profileid
        [{'uid':flow},...]
        """
        if not profileid:
            # profileid is None if we're dealing with a profile
            # outside of home_network when this param is given
            return []
        profileid_flows = []
        # get all tws in this profile
        for twid, time in self.getTWsfromProfile(profileid):
            if flows := self.get_all_flows_in_profileid_twid(profileid, twid):
                for uid, flow in list(flows.items()):
                    profileid_flows.append({uid: json.loads(flow)})
        return profileid_flows

    def get_all_flows(self) -> list:
        """
        Returns a list with all the flows in all profileids and twids
        Each element in the list is a flow
        """
        flows = []
        for profileid in self.getProfiles():
            for (twid, time) in self.getTWsfromProfile(profileid):
                if flows_dict := self.get_all_flows_in_profileid_twid(
                    profileid, twid
                ):
                    for flow in flows_dict.values():
                        dict_flow = json.loads(flow)
                        flows.append(dict_flow)
        return flows

    def get_all_contacted_ips_in_profileid_twid(self, profileid, twid) -> dict:
        """
        Get all the contacted IPs in a given profile and TW
        """
        if not profileid:
            # profileid is None if we're dealing with a profile
            # outside of home_network when this param is given
            return {}
        all_flows = self.get_all_flows_in_profileid_twid(profileid, twid)
        if not all_flows:
            return {}
        contacted_ips = {}
        for uid, flow in all_flows.items():
            # get the daddr of this flow
            flow = json.loads(flow)
            daddr = flow['daddr']
            contacted_ips[daddr] = uid
        return contacted_ips

    def get_labels(self):
        """
        Return the amount of each label so far in the DB
        Used to know how many labels are available during training
        """
        return self.r.zrange('labels', 0, -1, withscores=True)

    def get_altflow_from_uid(self, profileid, twid, uid):
        """ Given a uid, get the alternative flow realted to it """
        return (
            self.r.hget(
                profileid + self.separator + twid + self.separator + 'altflows',
                uid,
            )
            if profileid
            else False
        )

    def add_timeline_line(self, profileid, twid, data, timestamp):
        """Add a line to the timeline of this profileid and twid"""
        if not profileid:
            # profileid is None if we're dealing with a profile
            # outside of home_network when this param is given
            return
        self.print(f'Adding timeline for {profileid}, {twid}: {data}', 3, 0)
        key = str(
            profileid + self.separator + twid + self.separator + 'timeline'
        )
        data = json.dumps(data)
        mapping = {data: timestamp}
        self.r.zadd(key, mapping)
        # Mark the tw as modified since the timeline line is new data in the TW
        self.markProfileTWAsModified(profileid, twid, timestamp='')

    def get_timeline_last_lines(
        self, profileid, twid, first_index: int
    ) -> Tuple[str, int]:
        """Get only the new items in the timeline."""
        if not profileid:
            # profileid is None if we're dealing with a profile
            # outside of home_network when this param is given
            return [], []
        key = str(
            profileid + self.separator + twid + self.separator + 'timeline'
        )
        # The the amount of lines in this list
        last_index = self.r.zcard(key)
        # Get the data in the list from the index asked (first_index) until the last
        data = self.r.zrange(key, first_index, last_index - 1)
        return data, last_index


    def set_port_info(self, portproto: str, name):
        """
        Save in the DB a port with its description
        :param portproto: portnumber + / + protocol
        """
        self.rcache.hset('portinfo', portproto, name)

    def get_port_info(self, portproto: str):
        """
        Retrieve the name of a port
        :param portproto: portnumber + / + protocol
        """
        return self.rcache.hget('portinfo', portproto)

    def set_ftp_port(self, port):
        """
        Stores the used ftp port in our main db (not the cache like set_port_info)
        """
        self.r.lpush('used_ftp_ports', str(port))

    def is_ftp_port(self, port):
        # get all used ftp ports
        used_ftp_ports = self.r.lrange('used_ftp_ports', 0, -1)
        # check if the given port is used as ftp port
        return str(port) in used_ftp_ports

    def set_organization_of_port(self, organization, ip: str, portproto: str):
        """
        Save in the DB a port with its organization and the ip/ range used by this organization
        :param portproto: portnumber.lower() + / + protocol
        :param ip: can be a single org ip, or a range or ''
        """
        org_info = {'org_name': organization, 'ip': ip}
        org_info = json.dumps(org_info)
        self.rcache.hset('organization_port', portproto, org_info)

    def get_organization_of_port(self, portproto: str):
        """
        Retrieve the organization info that uses this port
        :param portproto: portnumber.lower() + / + protocol
        """
        # this key is used to store the ports the are known to be used
        #  by certain organizations
        return self.rcache.hget('organization_port', portproto.lower())

    def add_zeek_file(self, filename):
        """Add an entry to the list of zeek files"""
        self.r.sadd('zeekfiles', filename)

    def get_all_zeek_file(self):
        """Return all entries from the list of zeek files"""
        return self.r.smembers('zeekfiles')

    def get_gateway_ip(self):
        return self.r.hget('default_gateway', 'IP')

    def get_gateway_MAC(self):
        return self.r.hget('default_gateway', 'MAC')

    def get_gateway_MAC_Vendor(self):
        return self.r.hget('default_gateway', 'Vendor')


    def set_default_gateway(self, address_type:str, address:str):
        """
        :param address_type: can either be 'IP' or 'MAC'
        :param address: can be ip or mac
        """
        # make sure the IP or mac aren't already set before re-setting
        if (
                (address_type == 'IP' and not self.get_gateway_ip())
                or (address_type == 'MAC' and not self.get_gateway_MAC())
                or (address_type == 'Vendor' and not self.get_gateway_MAC_Vendor())
        ):
            self.r.hset('default_gateway', address_type, address)

    def get_ssl_info(self, sha1):
        info = self.rcache.hmget('IoC_SSL', sha1)[0]
        return False if info is None else info

    def set_profile_module_label(self, profileid, module, label):
        """
        Set a module label for a profile.
        A module label is a label set by a module, and not
        a groundtruth label
        """
        if not profileid:
            # profileid is None if we're dealing with a profile
            # outside of home_network when this param is given
            return False
        data = self.get_profile_modules_labels(profileid)
        data[module] = label
        data = json.dumps(data)
        self.r.hset(profileid, 'modules_labels', data)

    def get_profile_modules_labels(self, profileid):
        """
        Get labels set by modules in the profile.
        """
        if not profileid:
            # profileid is None if we're dealing with a profile
            # outside of home_network when this param is given
            return {}
        data = self.r.hget(profileid, 'modules_labels')
        data = json.loads(data) if data else {}
        return data

    def delete_ips_from_IoC_ips(self, ips):
        """
        Delete old IPs from IoC
        """
        self.rcache.hdel('IoC_ips', *ips)

    def delete_domains_from_IoC_domains(self, domains):
        """
        Delete old domains from IoC
        """
        self.rcache.hdel('IoC_domains', *domains)

    def add_ips_to_IoC(self, ips_and_description: dict) -> None:
        """
        Store a group of IPs in the db as they were obtained from an IoC source
        :param ips_and_description: is {ip: json.dumps{'source':..,
                                                        'tags':..,
                                                        'threat_level':... ,
                                                        'description':...}}

        """
        if ips_and_description:
            self.rcache.hmset('IoC_ips', ips_and_description)

    def add_domains_to_IoC(self, domains_and_description: dict) -> None:
        """
        Store a group of domains in the db as they were obtained from
        an IoC source
        :param domains_and_description: is {domain: json.dumps{'source':..,'tags':..,
                                                            'threat_level':... ,'description'}}
        """
        if domains_and_description:
            self.rcache.hmset('IoC_domains', domains_and_description)

    def add_ip_range_to_IoC(self, malicious_ip_ranges: dict) -> None:
        """
        Store a group of IP ranges in the db as they were obtained from an IoC source
        :param malicious_ip_ranges: is {range: json.dumps{'source':..,'tags':..,
                                                            'threat_level':... ,'description'}}
        """
        if malicious_ip_ranges:
            self.rcache.hmset('IoC_ip_ranges', malicious_ip_ranges)

    def add_asn_to_IoC(self, blacklisted_ASNs: dict):
        """
        Store a group of ASN in the db as they were obtained from an IoC source
        :param blacklisted_ASNs: is {asn: json.dumps{'source':..,'tags':..,
                                                     'threat_level':... ,'description'}}
        """
        if blacklisted_ASNs:
            self.rcache.hmset('IoC_ASNs', blacklisted_ASNs)

    def is_blacklisted_ASN(self, ASN) -> bool:
        return self.rcache.hget('IoC_ASNs', ASN)


    def add_ja3_to_IoC(self, ja3_dict) -> None:
        """
        Store a group of ja3 in the db
        :param ja3_dict:  {ja3: {'source':..,'tags':..,
                            'threat_level':... ,'description'}}

        """
        self.rcache.hmset('IoC_JA3', ja3_dict)

    def add_ssl_sha1_to_IoC(self, malicious_ssl_certs):
        """
        Store a group of ssl fingerprints in the db
        :param malicious_ssl_certs:  {sha1: {'source':..,'tags':..,
                                    'threat_level':... ,'description'}}

        """
        self.rcache.hmset('IoC_SSL', malicious_ssl_certs)

    def get_malicious_ip_ranges(self) -> dict:
        """
        Returns all the malicious ip ranges we have from different feeds
        return format is {range: json.dumps{'source':..,'tags':..,
                                            'threat_level':... ,'description'}}
        """
        return self.rcache.hgetall('IoC_ip_ranges')

    def set_malicious_ip(self, ip, profileid, twid):
        """
        Save in DB malicious IP found in the traffic
        with its profileid and twid
        """
        if not profileid:
            # profileid is None if we're dealing with a profile
            # outside of home_network when this param is given
            return False
        # Retrieve all profiles and twis, where this malicios IP was met.
        ip_profileid_twid = self.get_malicious_ip(ip)
        try:
            profile_tws = ip_profileid_twid[
                profileid
            ]             # a dictionary {profile:set(tw1, tw2)}
            profile_tws = ast.literal_eval(
                profile_tws
            )            # set(tw1, tw2)
            profile_tws.add(twid)
            ip_profileid_twid[profileid] = str(profile_tws)
        except KeyError:
            ip_profileid_twid[profileid] = str(
                {twid}
            )                   # add key-pair to the dict if does not exist
        data = json.dumps(ip_profileid_twid)

        self.r.hset('MaliciousIPs', ip, data)

    def set_malicious_domain(self, domain, profileid, twid):
        """
        Save in DB a malicious domain found in the traffic
        with its profileid and twid
        """
        if not profileid:
            # profileid is None if we're dealing with a profile
            # outside of home_network when this param is given
            return False
        # get all profiles and twis where this IP was met
        domain_profiled_twid = __database__.get_malicious_domain(domain)
        try:
            profile_tws = domain_profiled_twid[
                profileid
            ]               # a dictionary {profile:set(tw1, tw2)}
            profile_tws = ast.literal_eval(
                profile_tws
            )                 # set(tw1, tw2)
            profile_tws.add(twid)
            domain_profiled_twid[profileid] = str(profile_tws)
        except KeyError:
            domain_profiled_twid[profileid] = str(
                {twid}
            )               # add key-pair to the dict if does not exist
        data = json.dumps(domain_profiled_twid)

        self.r.hset('MaliciousDomains', domain, data)

    def get_malicious_ip(self, ip):
        """
        Return malicious IP and its list of presence in
        the traffic (profileid, twid)
        """
        data = self.r.hget('MaliciousIPs', ip)
        data = json.loads(data) if data else {}
        return data

    def get_malicious_domain(self, domain):
        """
        Return malicious domain and its list of presence in
        the traffic (profileid, twid)
        """
        data = self.r.hget('MaliciousDomains', domain)
        data = json.loads(data) if data else {}
        return data

    def get_domain_resolution(self, domain):
        """
        Returns the IPs resolved by this domain
        """
        ips = self.r.hget("DomainsResolved", domain)
        return json.loads(ips) if ips else []

    def get_all_dns_resolutions(self):
        dns_resolutions = self.r.hgetall('DNSresolution')
        return dns_resolutions or []


    def set_passive_dns(self, ip, data):
        """
        Save in DB passive DNS from virus total
        """
        if data:
            data = json.dumps(data)
            self.rcache.hset('passiveDNS', ip, data)

    def get_passive_dns(self, ip):
        """
        Gets passive DNS from the db
        """
        if data := self.rcache.hget('passiveDNS', ip):
            return json.loads(data)
        else:
            return False

    def get_IPs_in_IoC(self):
        """
        Get all IPs and their description from IoC_ips
        """
        return self.rcache.hgetall('IoC_ips')

    def get_Domains_in_IoC(self):
        """
        Get all Domains and their description from IoC_domains
        """
        return self.rcache.hgetall('IoC_domains')

    def get_ja3_in_IoC(self):
        """
        Get all ja3 and their description from IoC_JA3
        """
        return self.rcache.hgetall('IoC_JA3')

    def search_IP_in_IoC(self, ip: str) -> str:
        """
        Search in the dB of malicious IPs and return a
        description if we found a match
        """
        ip_description = self.rcache.hget('IoC_ips', ip)
        return False if ip_description is None else ip_description

    def getReconnectionsForTW(self, profileid, twid):
        """Get the reconnections for this TW for this Profile"""
        if not profileid:
            # profileid is None if we're dealing with a profile
            # outside of home_network when this param is given
            return False
        data = self.r.hget(profileid + self.separator + twid, 'Reconnections')
        data = json.loads(data) if data else {}
        return data

    def setReconnections(self, profileid, twid, data):
        """Set the reconnections for this TW for this Profile"""
        data = json.dumps(data)
        self.r.hset(
            profileid + self.separator + twid, 'Reconnections', str(data)
        )


    def is_domain_malicious(self, domain: str) -> tuple:
        """
        Search in the dB of malicious domains and return a
        description if we found a match
        returns a tuple (description, is_subdomain)
        description: description of the subdomain if found
        bool: True if we found a match for exactly the given domain False if we matched a subdomain
        """
        domain_description = self.rcache.hget('IoC_domains', domain)
        if domain_description is None:
            # try to match subdomain
            ioc_domains = self.rcache.hgetall('IoC_domains')
            for malicious_domain, description in ioc_domains.items():
                #  if the we contacted images.google.com and we have google.com in our blacklists, we find a match
                if malicious_domain in domain:
                    return description, True
            return False, False
        else:
            return domain_description, False


    def get_host_ip(self):
        """Get the IP addresses of the host from a db. There can be more than one"""
        return self.r.smembers('hostIP')

    def set_host_ip(self, ip):
        """Store the IP address of the host in a db. There can be more than one"""
        self.r.sadd('hostIP', ip)


    def is_profile_malicious(self, profileid: str) -> str:
        return self.r.hget(profileid, 'labeled_as_malicious') if profileid else False

    def set_TI_file_info(self, file, data):
        """
        Set/update time and/or e-tag for TI file
        :param file: a valid filename not a feed url
        :param data: dict containing info about TI file
        """
        # data = self.get_malicious_file_info(file)
        # for key in file_data:
        # data[key] = file_data[key]
        data = json.dumps(data)
        self.rcache.hset('TI_files_info', file, data)

    def set_last_update_time(self, file: str, time: float):
        """
        sets the 'time' of last update of the given file
        :param file: ti file
        """
        if file_info := self.rcache.hget('TI_files_info', file):
            # update an existin time
            file_info = json.loads(file_info)
            file_info.update({"time": time})
            self.rcache.hset('TI_files_info', file, json.dumps(file_info))
            return

        # no cached info about this file
        self.rcache.hset('TI_files_info', file, json.dumps({"time": time}))

    def get_TI_file_info(self, file):
        """
        Get TI file info
        :param file: a valid filename not a feed url
        """
        data = self.rcache.hget('TI_files_info', file)
        data = json.loads(data) if data else {}
        return data

    def delete_file_info(self, file):
        self.rcache.hdel('TI_files_info', file)

    def set_asn_cache(self, org: str, asn_range: str, asn_number: str) -> None:
        """
        Stores the range of asn in cached_asn hash
        """

        range_info = {
            asn_range: {
                'org': org
            }
        }
        if asn_number:
            range_info[asn_range].update(
                {'number': f'AS{asn_number}'}
            )

        first_octet = utils.get_first_octet(asn_range)
        if not first_octet:
            return

        # this is how we store ASNs; sorted by first octet
        """
        {
            '192' : {
                '192.168.1.0/x': {'number': 'AS123', 'org':'Test'},
                '192.168.1.0/x': {'number': 'AS123', 'org':'Test'},
            },
            '10': {
                '10.0.0.0/x': {'number': 'AS123', 'org':'Test'},
            }
            
        }
        """
        if cached_asn := self.get_asn_cache(first_octet=first_octet):
            # we already have a cached asn of a range that starts with the same first octet
            cached_asn: dict = json.loads(cached_asn)
            cached_asn.update(range_info)
            self.rcache.hset('cached_asn', first_octet, json.dumps(cached_asn))
        else:
            # first time storing a range starting with the same first octet
            self.rcache.hset('cached_asn', first_octet, json.dumps(range_info))

    def get_asn_cache(self, first_octet=False):
        """
         cached ASNs are sorted by first octet
        Returns cached asn of ip if present, or False.
        """
        if first_octet:
            return self.rcache.hget('cached_asn', first_octet)
        else:
            return self.rcache.hgetall('cached_asn')


    def store_process_PID(self, process, pid):
        """
        Stores each started process or module with it's PID
        :param pid: int
        :param process: str
        """
        self.r.hset('PIDs', process, pid)

    def get_PIDs(self):
        """returns a dict with module names as keys and pids as values"""
        return self.r.hgetall('PIDs')

    def set_org_info(self, org, org_info, info_type):
        """
        store ASN, IP and domains of an org in the db
        :param org: supported orgs are ('google', 'microsoft', 'apple', 'facebook', 'twitter')
        : param org_info: a json serialized list of asns or ips or domains
        :param info_type: supported types are 'asn', 'domains', 'IPs'
        """
        # info will be stored in OrgInfo key {'facebook_asn': .., 'twitter_domains': ...}
        self.rcache.hset('OrgInfo', f'{org}_{info_type}', org_info)

    def get_org_info(self, org, info_type) -> str:
        """
        get the ASN, IP and domains of an org from the db
        :param org: supported orgs are ('google', 'microsoft', 'apple', 'facebook', 'twitter')
        :param info_type: supported types are 'asn', 'domains'
        " returns a json serialized dict with info
        """
        return self.rcache.hget('OrgInfo', f'{org}_{info_type}') or '[]'

    def get_org_IPs(self, org):
        org_info = self.rcache.hget('OrgInfo', f'{org}_IPs')

        if not org_info:
            org_info = {}
            return org_info

        try:
            return json.loads(org_info)
        except TypeError:
            # it's a dict
            return org_info

    def set_whitelist(self, type, whitelist_dict):
        """
        Store the whitelist_dict in the given key
        :param type: supporte types are IPs, domains and organizations
        :param whitelist_dict: the dict of IPs, domains or orgs to store
        """
        self.r.hset('whitelist', type, json.dumps(whitelist_dict))

    def get_all_whitelist(self):
        """Return dict of 3 keys: IPs, domains, organizations or mac"""
        return self.r.hgetall('whitelist')

    def get_whitelist(self, key):
        """
        Whitelist supports different keys like : IPs domains and organizations
        this function is used to check if we have any of the above keys whitelisted
        """
        if whitelist := self.r.hget('whitelist', key):
            return json.loads(whitelist)
        else:
            return {}

    def store_dhcp_server(self, server_addr):
        """
        Store all seen DHCP servers in the database.
        """
        # make sure it's a valid ip
        try:
            ipaddress.ip_address(server_addr)
        except ValueError:
            # not a valid ip skip
            return False
        # make sure the server isn't there before adding
        DHCP_servers = self.r.lrange('DHCP_servers', 0, -1)
        if server_addr not in DHCP_servers:
            self.r.lpush('DHCP_servers', server_addr)

    def save(self, backup_file):
        """
        Save the db to disk.
        backup_file should be the path+name of the file you want to save the db in
        If you -s the same file twice the old backup will be overwritten.
        """

        # use print statements in this function won't work because by the time this
        # function is executed, the redis database would have already stopped

        # saves to /var/lib/redis/dump.rdb
        # this path is only accessible by root
        self.r.save()

        # gets the db saved to dump.rdb in the cwd
        redis_db_path = os.path.join(os.getcwd(), 'dump.rdb')

        if os.path.exists(redis_db_path):
            command = f'{self.sudo} cp {redis_db_path} {backup_file}.rdb'
            os.system(command)
            os.remove(redis_db_path)
            print(f'[Main] Database saved to {backup_file}.rdb')
            return True

        print(
            f'[DB] Error Saving: Cannot find the redis database directory {redis_db_path}'
        )
        return False

    def load(self, backup_file: str) -> bool:
        """
        Load the db from disk to the db on port 32850
        backup_file should be the full path of the .rdb
        """
        # do not use self.print here! the output queue isn't initialized yet
        def is_valid_rdb_file():
            if not os.path.exists(backup_file):
                print("{} doesn't exist.".format(backup_file))
                return False

            # Check if valid .rdb file
            command = f'file {backup_file}'
            result = subprocess.run(command.split(), stdout=subprocess.PIPE)
            file_type = result.stdout.decode('utf-8')
            if 'Redis' not in file_type:
                print(
                    f'{backup_file} is not a valid redis database file.'
                )
                return False
            return True

        if not is_valid_rdb_file():
            return False

        try:
            self.redis_options.update({
                'dbfilename': os.path.basename(backup_file),
                'dir': os.path.dirname(backup_file),
                'port': 32850,
            })

            with open(self.redis_conf_file, 'w') as f:
                for option, val in self.redis_options.items():
                    f.write(f'{option} {val}\n')
            # Stop the server first in order for redis to load another db
            os.system(f'{self.sudo}service redis-server stop')

            # Start the server again, but make sure it's flushed and doesnt have any keys
            os.system('redis-server redis.conf > /dev/null 2>&1')
            return True
        except Exception:
            self.print(
                f'Error loading the database {backup_file}.'
            )
            return False

    def delete_feed(self, url: str):
        """
        Delete all entries in IoC_domains and IoC_ips that contain the given feed as source
        """
        # get the feed name from the given url
        feed_to_delete = url.split('/')[-1]
        # get all domains that are read from TI files in our db
        IoC_domains = self.rcache.hgetall('IoC_domains')
        for domain, domain_description in IoC_domains.items():
            domain_description = json.loads(domain_description)
            if feed_to_delete in domain_description['source']:
                # this entry has the given feed as source, delete it
                self.rcache.hdel('IoC_domains', domain)

        # get all IPs that are read from TI files in our db
        IoC_ips = self.rcache.hgetall('IoC_ips')
        for ip, ip_description in IoC_ips.items():
            ip_description = json.loads(ip_description)
            if feed_to_delete in ip_description['source']:
                # this entry has the given feed as source, delete it
                self.rcache.hdel('IoC_ips', ip)

    def set_last_warden_poll_time(self, time):
        """
        :param time: epoch
        """
        self.r.hset('Warden', 'poll', time)

    def get_last_warden_poll_time(self):
        """
        returns epoch time of last poll
        """
        time = self.r.hget('Warden', 'poll')
        time = float(time) if time else float('-inf')
        return time

    def start_profiling(self):
        print('-' * 30 + ' Started profiling')
        import cProfile

        profile = cProfile.Profile()
        profile.enable()
        return profile

    def end_profiling(self, profile):
        import pstats, io

        profile.disable()
        s = io.StringIO()
        sortby = pstats.SortKey.CUMULATIVE
        ps = pstats.Stats(profile, stream=s).sort_stats(sortby)
        ps.print_stats()
        print(s.getvalue())
        print('-' * 30 + ' Done profiling')

    def store_blame_report(self, ip, network_evaluation):
        """
        :param network_evaluation: a dict with {'score': ..,'confidence': .., 'ts': ..} taken from a blame report
        """
        self.rcache.hset('p2p-received-blame-reports', ip, network_evaluation)

    def store_zeek_path(self, path):
        """used to store the path of zeek log files slips is currently using"""
        self.r.set('zeek_path', path)

    def get_zeek_path(self) -> str:
        """return the path of zeek log files slips is currently using"""
        return self.r.get('zeek_path')

    def store_std_file(self, **kwargs):
        """
        available args are
            std_files = {
                    'stderr': ,
                    'stdout': ,
                    'stdin': ,
                    'pidfile': ,
                    'logsfile': ,
                }
        """
        for file_type, path in kwargs.items():
            self.r.set(file_type, path)

    def get_stdfile(self, file_type):
        return self.r.get(file_type)

__database__ = Database()
