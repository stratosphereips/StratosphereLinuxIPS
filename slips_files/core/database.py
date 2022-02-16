import os
import redis
import time
import json
from typing import Tuple
import configparser
import traceback
import subprocess
from datetime import datetime
import ipaddress
import sys
import validators
import platform
import re
import ast
from uuid import uuid4

def timing(f):
    """ Function to measure the time another function takes."""
    def wrap(*args):
        time1 = time.time()
        ret = f(*args)
        time2 = time.time()
        print('[DB] Function took {:.3f} ms'.format((time2-time1)*1000.0))
        return ret
    return wrap

class Database(object):
    """ Database object management """
    def __init__(self):
        # The name is used to print in the outputprocess
        self.name = 'DB'
        self.separator = '_'
        self.normal_label = 'normal'
        self.malicious_label = 'malicious'
        self.running_in_docker = os.environ.get('IS_IN_A_DOCKER_CONTAINER', False)
        if self.running_in_docker:
            self.sudo =''
        else:
            self.sudo = 'sudo '


    def read_configuration(self):
        """
        Read values from the configuration file
        """
        try:
            deletePrevdbText = self.config.get('parameters', 'deletePrevdb')
            if deletePrevdbText == 'True':
                self.deletePrevdb = True
            elif deletePrevdbText == 'False':
                self.deletePrevdb = False
        except (configparser.NoOptionError, configparser.NoSectionError, NameError, ValueError, KeyError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.deletePrevdb = True
        try:
            data = self.config.get('parameters', 'time_window_width')
            self.width = float(data)
        except ValueError:
            # Its not a float
            if 'only_one_tw' in data:
                # Only one tw. Width is 10 9s, wich is ~11,500 days, ~311 years
                self.width = 9999999999
        except configparser.NoOptionError:
            # By default we use 3600 seconds, 1hs
            self.width = 3600
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no
            # configuration file specified
            self.width = 3600

        # Read disabled detections from slips.conf
        # get the configuration for this alert
        try:
            self.disabled_detections = self.config.get('DisabledAlerts', 'disabled_detections')
            self.disabled_detections = self.disabled_detections.replace('[','').replace(']','').split()
        except (configparser.NoOptionError, configparser.NoSectionError, NameError, ValueError, KeyError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            # if we failed to read a value, it will be enabled by default.
            self.disabled_detections  = []

    def start(self, config):
        """ Start the DB. Allow it to read the conf """
        self.config = config
        self.read_configuration()
        # Create the connection to redis
        if not hasattr(self, 'r'):
            try:
                # db 0 changes everytime we run slips
                # set health_check_interval to avoid redis ConnectionReset errors:
                # if the connection is idle for more than 30 seconds,
                # a round trip PING/PONG will be attempted before next redis cmd.
                # If the PING/PONG fails, the connection will reestablished

                # retry_on_timeout=True after the command times out, it will be retried once,
                # if the retry is successful, it will return normally; if it fails, an exception will be thrown

                self.r = redis.StrictRedis(host='localhost',
                                           port=6379,
                                           db=0,
                                           charset="utf-8",
                                           socket_keepalive=True,
                                           retry_on_timeout=True,
                                           decode_responses=True,
                                           health_check_interval=20)#password='password')
                # db 1 is cache, delete it using -cc flag
                self.rcache = redis.StrictRedis(host='localhost',
                                                port=6379,
                                                db=1,
                                                charset="utf-8",
                                                socket_keepalive=True,
                                                retry_on_timeout=True,
                                                decode_responses=True,
                                                health_check_interval=20)#password='password')
                if self.deletePrevdb:
                    self.r.flushdb()

                # to fix redis.exceptions.ResponseError MISCONF Redis is configured to save RDB snapshots
                # configure redis to stop writing to dump.rdb when an error occurs without throwing errors in slips
                self.r.config_set('stop-writes-on-bgsave-error','no')
                self.rcache.config_set('stop-writes-on-bgsave-error','no')

            except redis.exceptions.ConnectionError:
                print('[DB] Error in database.py: Is redis database running? You can run it as: "redis-server --daemonize yes"')
        # Even if the DB is not deleted. We need to delete some temp data
        # Zeek_files
        self.r.delete('zeekfiles')
        # By default the slips internal time is 0 until we receive something
        self.setSlipsInternalTime(0)
        while self.get_slips_start_time() == None:
            self.set_slips_start_time()

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
        try:
            self.outputqueue.put(f"{levels}|{self.name}|{text}")
        except AttributeError:
            pass


    def set_slips_start_time(self):
        """ store the time slips started (datetime obj) """
        now = datetime.now()
        now = now.strftime("%d/%m/%Y %H:%M:%S")
        self.r.set('slips_start_time', now)

    def get_slips_start_time(self):
        """ get the time slips started (datetime obj) """
        start_time = self.r.get('slips_start_time')
        if start_time:
            start_time = datetime.strptime(start_time, "%d/%m/%Y %H:%M:%S")
            return start_time

    def setOutputQueue(self, outputqueue):
        """ Set the output queue"""
        self.outputqueue = outputqueue

    def addProfile(self, profileid, starttime, duration):
        """
        Add a new profile to the DB. Both the list of profiles and the hasmap of profile data
        Profiles are stored in two structures. A list of profiles (index) and individual hashmaps for each profile (like a table)
        Duration is only needed for registration purposes in the profile. Nothing operational
        """
        try:
            if not self.r.sismember('profiles', str(profileid)):
                # Add the profile to the index. The index is called 'profiles'
                self.r.sadd('profiles', str(profileid))
                # Create the hashmap with the profileid. The hasmap of each profile is named with the profileid
                # Add the start time of profile
                self.r.hset(profileid, 'starttime', starttime)
                # For now duration of the TW is fixed
                self.r.hset(profileid, 'duration', duration)
                # The IP of the profile should also be added as a new IP we know about.
                ip = profileid.split(self.separator)[1]
                # If the ip is new add it to the list of ips
                self.setNewIP(ip)
                # Publish that we have a new profile
                self.publish('new_profile', ip)
        except redis.exceptions.ResponseError as inst:
            self.outputqueue.put('00|database|Error in addProfile in database.py')
            self.outputqueue.put('00|database|{}'.format(type(inst)))
            self.outputqueue.put('00|database|{}'.format(inst))

    def add_user_agent_to_profile(self, profileid, user_agent: str):
        """
        Used to associate this profile with it's used user_agent
        """
        self.r.hmset(profileid, {'User-agent': user_agent})

    def get_user_agent_from_profile(self, profileid) -> str:
        """
        Returns user agent used by a certain profile or None
        """
        user_agent = self.r.hmget(profileid, 'User-agent')[0]
        return user_agent



    def search_for_profile_with_the_same_MAC(self, profileid, MAC_address):
        """
        If we have different profiles for IPv6 and IPv4 of the same computer(same MAC),
        store it in the database
        This function is called whenever slips sees a new MAC address
        """
        # some cases we have ipv4 and ipv6 on the same computer, they should be associated with the same mac
        # and both profiles should be aware of both IPs
        # get all profiles in the db
        for stored_profile in self.getProfiles():
            # get the mac of the profile
            found_mac = self.get_mac_addr_from_profile(stored_profile)
            if found_mac == MAC_address:
                # we found another profile that has the same mac as this one
                incoming_ip = profileid.split('_')[1]
                found_ip = stored_profile.split('_')[1]

                # make sure 1 profile is ipv4 and the other is ipv6 (so we don't mess with MITM ARP detections)
                if (validators.ipv6(incoming_ip)
                        and validators.ipv4(found_ip)):
                    # associate the ipv4 we found with the incoming ipv6
                    self.r.hmset(profileid, {'IPv6': incoming_ip})

                elif (validators.ipv6(found_ip)
                      and validators.ipv4(incoming_ip)):
                    # associate the ipv6 we found with the incoming ipv4
                    self.r.hmset(profileid, {'IPv4': incoming_ip})
                else:
                    # both are ipv4 or ipv6 and are claiming to have the same mac address
                    # OR one of them is 0.0.0.0 and didn't take an ip yet
                    # will be detected later by the ARP module
                    pass

    def add_user_agent_to_profile(self, profileid, user_agent: str):
        """
        Used to associate this profile with it's used user_agent
        """
        self.r.hmset(profileid, {'User-agent': user_agent})

    def get_user_agent_from_profile(self, profileid) -> str:
        """
        Returns user agent used by a certain profile or None
        """
        user_agent = self.r.hmget(profileid, 'User-agent')[0]
        return user_agent

    def add_mac_addr_to_profile(self,profileid, MAC_info):
        """
        Used to associate this profile with it's MAC addr
        :param MAC_info: dict containing mac address, hostname and vendor info
        """
        # Add the MAC addr, hostname and vendor to this profile
        self.r.hmset(profileid, MAC_info)

    def mark_profile_as_dhcp(self, profileid):
        """
        Used to mark this profile as dhcp server
        """
        # check if it's already marked as dhcp
        is_dhcp_set = self.r.hmget(profileid , 'dhcp')[0]
        if not is_dhcp_set:
            self.r.hmset(profileid, {'dhcp': 'true'})


    def get_mac_addr_from_profile(self, profileid) -> str:
        """
        Returns MAC info about a certain profile or None
        """
        MAC_info = self.r.hmget(profileid, 'MAC')[0]
        return MAC_info

    def get_mac_vendor_from_profile(self, profileid) -> str:
        """
        Returns MAC vendor about a certain profile or None
        """
        MAC_vendor = self.r.hmget(profileid, 'Vendor')[0]
        return MAC_vendor

    def get_hostname_from_profile(self, profileid) -> str:
        """
        Returns hostname about a certain profile or None
        """
        hostname = self.r.hmget(profileid, 'host_name')[0]
        return hostname

    def get_IP_of_MAC(self, MAC):
        """
        Returns the IP associated with the given MAC in our database
        """
        profiles = self.getProfiles()
        if profiles:
            # get the mac of every profile we have
            for profile in profiles:
                MAC_of_profile = self.get_mac_addr_from_profile(profile)
                # does this profile has the MAC we're searching for?
                if MAC_of_profile and MAC in MAC_of_profile:
                    # found the profile with the wanted mac
                    return profile.split('_')[1]

    def getProfileIdFromIP(self, daddr_as_obj):
        """ Receive an IP and we want the profileid"""
        try:
            temp_id = 'profile' + self.separator + str(daddr_as_obj)
            data = self.r.sismember('profiles', temp_id)
            if data:
                return temp_id
            return False
        except redis.exceptions.ResponseError as inst:
            self.outputqueue.put('00|database|error in addprofileidfromip in database.py')
            self.outputqueue.put('00|database|{}'.format(type(inst)))
            self.outputqueue.put('00|database|{}'.format(inst))

    def getProfiles(self):
        """ Get a list of all the profiles """
        profiles = self.r.smembers('profiles')
        if profiles != set():
            return profiles
        else:
            return {}

    def getProfileData(self, profileid):
        """ Get all the data for this particular profile.
        Returns:
        A json formated representation of the hashmap with all the data of the profile
        """
        profile = self.r.hgetall(profileid)
        if profile != set():
            return profile
        else:
            return False

    def getTWsfromProfile(self, profileid):
        """
        Receives a profile id and returns the list of all the TW in that profile
        Returns a list of tuples (twid, ts) or an empty list
        """
        data = self.r.zrange('tws' + profileid, 0, -1, withscores=True)
        return data

    def getamountTWsfromProfile(self, profileid):
        """
        Receives a profile id and returns the number of all the TWs in that profile
        """
        return len(self.r.zrange('tws' + profileid, 0, -1, withscores=True))

    def getSrcIPsfromProfileTW(self, profileid, twid):
        """
        Get the src ip for a specific TW for a specific profileid
        """
        data = self.r.hget(profileid + self.separator + twid, 'SrcIPs')
        return data

    def getDstIPsfromProfileTW(self, profileid, twid):
        """
        Get the dst ip for a specific TW for a specific profileid
        """
        data = self.r.hget(profileid + self.separator + twid, 'DstIPs')
        return data

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
            self.outputqueue.put(f'01|database|[DB] Error in getT2ForProfileTW in database.py line {exception_line}')
            self.outputqueue.put('01|database|[DB] {}'.format(type(e)))
            self.outputqueue.put('01|database|[DB] {}'.format(e))
            self.outputqueue.put("01|profiler|[Profile] {}".format(traceback.format_exc()))

    def hasProfile(self, profileid):
        """ Check if we have the given profile """
        return self.r.sismember('profiles', profileid)

    def getProfilesLen(self):
        """ Return the amount of profiles. Redis should be faster than python to do this count """
        return self.r.scard('profiles')

    def getLastTWforProfile(self, profileid):
        """ Return the last TW id and the time for the given profile id """
        data = self.r.zrange('tws' + profileid, -1, -1, withscores=True)
        return data

    def getFirstTWforProfile(self, profileid):
        """ Return the first TW id and the time for the given profile id """
        data = self.r.zrange('tws' + profileid, 0, 0, withscores=True)
        return data

    def getTWofTime(self, profileid, time):
        """
        Return the TW id and the time for the TW that includes the given time.
        The score in the DB is the start of the timewindow, so we should search
        a TW that includes the given time by making sure the start of the TW
        is < time, and the end of the TW is > time.
        """
        # [-1] so we bring the last TW that matched this time.
        try:
            data = self.r.zrangebyscore('tws' + profileid, float('-inf'), float(time), withscores=True, start=0, num=-1)[-1]
        except IndexError:
            # We dont have any last tw?
            data = self.r.zrangebyscore('tws' + profileid, 0, float(time), withscores=True, start=0, num=-1)
        return data

    def addNewOlderTW(self, profileid, startoftw):
        try:
            """	
            Creates or adds a new timewindow that is OLDER than the first we have	
            Return the id of the timewindow just created	
            """
            # Get the first twid and obtain the new tw id
            try:
                (firstid, firstid_time) = self.getFirstTWforProfile(profileid)[0]
                # We have a first id
                # Decrement it!!
                twid = 'timewindow' + str(int(firstid.split('timewindow')[1]) - 1)
            except IndexError:
                # Very weird error, since the first TW MUST exist. What are we doing here?
                pass
            # Add the new TW to the index of TW
            data = {}
            data[str(twid)] = float(startoftw)
            self.r.zadd('tws' + profileid, data)
            self.outputqueue.put('04|database|[DB]: Created and added to DB the new older TW with id {}. Time: {} '.format(twid, startoftw))
            # The creation of a TW now does not imply that it was modified. You need to put data to mark is at modified
            return twid
        except redis.exceptions.ResponseError as e:
            self.outputqueue.put('01|database|error in addNewOlderTW in database.py')
            self.outputqueue.put('01|database|{}'.format(type(e)))
            self.outputqueue.put('01|database|{}'.format(e))

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
                twid = 'timewindow' + str(int(lastid.split('timewindow')[1]) + 1)
            except IndexError:
                # There is no first TW, create it
                twid = 'timewindow1'
            # Add the new TW to the index of TW
            data = {}
            data[str(twid)] = float(startoftw)
            self.r.zadd('tws' + profileid, data)
            self.outputqueue.put('04|database|[DB]: Created and added to DB for profile {} on TW with id {}. Time: {} '.format(profileid, twid, startoftw))
            # The creation of a TW now does not imply that it was modified. You need to put data to mark is at modified
            return twid
        except redis.exceptions.ResponseError as e:
            self.outputqueue.put('01|database|Error in addNewTW')
            self.outputqueue.put('01|database|{}'.format(e))

    def getTimeTW(self, profileid, twid):
        """ Return the time when this TW in this profile was created """
        # Get all the TW for this profile
        # We need to encode it to 'search' because the data in the sorted set is encoded
        data = self.r.zscore('tws' + profileid, twid.encode('utf-8'))
        return data

    def getAmountTW(self, profileid):
        """ Return the amount of tw for this profile id """
        return self.r.zcard('tws' + profileid)

    def getModifiedTWSinceTime(self, time):
        """ Return the list of modified timewindows since a certain time"""
        data = self.r.zrangebyscore('ModifiedTW', time, float('+inf'), withscores=True)
        if not data:
            return []
        return data

    def getModifiedProfilesSince(self, time):
        """ Returns a set of modified profiles since a certain time and the time of the last modified profile"""
        modified_tws = self.getModifiedTWSinceTime(time)
        if not modified_tws:
            # no modified tws, and no time_of_last_modified_tw
            return [],0
        # get the time of last modified tw
        time_of_last_modified_tw = modified_tws[-1][-1]
        # this list will store modified profiles without tws
        profiles = []
        for modified_tw in modified_tws:
            profiles.append(modified_tw[0].split('_')[1])
        # return a set of unique profiles
        return set(profiles), time_of_last_modified_tw

    def getModifiedTW(self):
        """ Return all the list of modified tw """
        data = self.r.zrange('ModifiedTW', 0, -1, withscores=True)
        if not data:
            return []
        return data

    def wasProfileTWModified(self, profileid, twid):
        """ Retrieve from the db if this TW of this profile was modified """
        data = self.r.zrank('ModifiedTW', profileid + self.separator + twid)
        if not data:
            # If for some reason we don't have the modified bit set,
            # then it was not modified.
            return False
        return True

    def getModifiedTWTime(self, profileid, twid):
        """
        Get the time when this TW was modified
        """
        data = self.r.zcore('ModifiedTW', profileid + self.separator + twid)
        if not data:
            data = -1
        return data

    def getSlipsInternalTime(self):
        return self.r.get('slips_internal_time')

    def setSlipsInternalTime(self, timestamp):
        self.r.set('slips_internal_time', timestamp)

    def markProfileTWAsClosed(self, profileid_tw):
        """
        Mark the TW as closed so tools can work on its data
        """
        self.r.sadd('ClosedTW', profileid_tw)
        self.r.zrem('ModifiedTW', profileid_tw)
        self.publish('tw_closed', profileid_tw)

    def markProfileTWAsModified(self, profileid, twid, timestamp):
        """
        Mark a TW in a profile as modified
        This means:
        1- To add it to the list of ModifiedTW
        2- Add the timestamp received to the time_of_last_modification
           in the TW itself
        3- To update the internal time of slips
        4- To check if we should 'close' some TW
        """
        # Add this tw to the list of modified TW, so others can
        # check only these later
        data = {}
        timestamp = time.time()
        data[profileid + self.separator + twid] = float(timestamp)
        self.r.zadd('ModifiedTW', data)
        self.publish('tw_modified', profileid + ':' + twid)
        # Check if we should close some TW
        self.check_TW_to_close()

    def check_TW_to_close(self):
        """
        Check if we should close some TW
        Search in the modifed tw list and compare when they
        were modified with the slips internal time
        """
        # Get internal time
        sit = self.getSlipsInternalTime()
        # for each modified profile
        # modification_time = float(sit) - self.width
        # To test the time
        modification_time = float(sit) - 20
        profiles_tws_to_close = self.r.zrangebyscore('ModifiedTW', 0, modification_time, withscores=True)
        for profile_tw_to_close in profiles_tws_to_close:
            profile_tw_to_close_id = profile_tw_to_close[0]
            profile_tw_to_close_time = profile_tw_to_close[1]
            self.print(f'The profile id {profile_tw_to_close_id} has to be closed because it was last modifed on {profile_tw_to_close_time} and we are closing everything older than {modification_time}. Current time {sit}. Difference: {modification_time - profile_tw_to_close_time}', 3, 0)
            self.markProfileTWAsClosed(profile_tw_to_close_id)

    def add_ips(self, profileid, twid, ip_as_obj, columns, role: str):
        """
        Function to add information about the an IP address
        The flow can go out of the IP (we are acting as Client) or into the IP
        (we are acting as Server)
        ip_as_obj: IP to add. It can be a dstIP or srcIP depending on the role
        role: 'Client' or 'Server'
        This function does two things:
            1- Add the ip to this tw in this profile, counting how many times
            it was contacted, and storing it in the key 'DstIPs' or 'SrcIPs'
            in the hash of the profile
            2- Use the ip as a key to count how many times that IP was
            contacted on each port. We store it like this because its the
               pefect structure to detect vertical port scans later on
            3- Check if this IP has any detection in the threat intelligence
            module. The information is added by the module directly in the DB.
        """
        try:
            # Get the fields
            dport = columns['dport']
            sport = columns['sport']
            totbytes = columns['bytes']
            sbytes = columns['sbytes']
            pkts = columns['pkts']
            spkts = columns['spkts']
            state = columns['state']
            proto = columns['proto'].upper()
            daddr = columns['daddr']
            saddr = columns['saddr']
            starttime = columns['starttime']
            uid = columns['uid']
            starttime = str(columns['starttime'])
            uid = columns['uid']
            # Depending if the traffic is going out or not, we are Client or Server
            # Set the type of ip as Dst if we are a client, or Src if we are a server
            if role == 'Client':
                # We are receving and adding a destination address and a dst port
                type_host_key = 'Dst'
            elif role == 'Server':
                type_host_key = 'Src'

            #############
            # Store the Dst as IP address and notify in the channel
            # We send the obj but when accessed as str, it is automatically
            # converted to str
            self.setNewIP(str(ip_as_obj))

            #############
            # Try to find evidence for this ip, in case we need to report it
            # Ask the threat intelligence modules, using a channel, that we need info about this IP
            # The threat intelligence module will process it and store the info back in IPsInfo
            # Therefore both ips will be checked for each flow
            # Check destination ip

            # BUT don't check if the state is OTH, since it means that we didnt see the true src ip and dst ip
            if columns['state'] != 'OTH':
                data_to_send = {
                    'ip': str(daddr),
                    'profileid' : str(profileid),
                    'twid' :  str(twid),
                    'proto' : str(proto),
                    'ip_state' : 'dstip',
                    'stime':starttime,
                    'uid': uid
                }
                data_to_send = json.dumps(data_to_send)
                self.publish('give_threat_intelligence', data_to_send)
                # Check source ip
                data_to_send = {
                    'ip': str(saddr),
                    'profileid' : str(profileid),
                    'twid' :  str(twid),
                    'proto' : str(proto),
                    'ip_state' : 'srcip',
                    'stime': starttime,
                    'uid': uid
                }
                data_to_send = json.dumps(data_to_send)
                self.publish('give_threat_intelligence', data_to_send)

            if role == 'Client':
                # The profile corresponds to the src ip that received this flow
                # The dstip is here the one receiving data from your profile
                # So check the dst ip
                pass
            elif role == 'Server':
                # The profile corresponds to the dst ip that received this flow
                # The srcip is here the one sending data to your profile
                # So check the src ip
                pass
            #############
            # 1- Count the dstips, and store the dstip in the db of this profile+tw
            self.print('add_ips(): As a {}, add the {} IP {} to profile {}, twid {}'.format(role, type_host_key, str(ip_as_obj), profileid, twid), 3, 0)
            # Get the hash of the timewindow
            hash_id = profileid + self.separator + twid
            # Get the DstIPs data for this tw in this profile
            # The format is data['1.1.1.1'] = 3
            data = self.r.hget(hash_id, type_host_key + 'IPs')
            if not data:
                data = {}
            try:
                # Convert the json str to a dictionary
                data = json.loads(data)
                # Add 1 because we found this ip again
                self.print('add_ips(): Not the first time for this addr. Add 1 to {}'.format(str(ip_as_obj)), 3, 0)
                data[str(ip_as_obj)] += 1
                # Convet the dictionary to json
                data = json.dumps(data)
            except (TypeError, KeyError) as e:
                # There was no previous data stored in the DB
                self.print('add_ips(): First time for addr {}. Count as 1'.format(str(ip_as_obj)), 3,0)
                data[str(ip_as_obj)] = 1
                # Convet the dictionary to json
                data = json.dumps(data)
            # Store the dstips in the dB
            self.r.hset(hash_id, type_host_key + 'IPs', str(data))
            #############
            # 2- Store, for each ip:
            # - Update how many times each individual DstPort was contacted
            # - Update the total flows sent by this ip
            # - Update the total packets sent by this ip
            # - Update the total bytes sent by this ip
            # Get the state. Established, NotEstablished
            summaryState = __database__.getFinalStateFromFlags(state, pkts)
            # Get the previous data about this key
            prev_data = self.getDataFromProfileTW(profileid, twid, type_host_key, summaryState, proto, role, 'IPs')
            try:
                innerdata = prev_data[str(ip_as_obj)]
                self.print('add_ips(): Adding for dst port {}. PRE Data: {}'.format(dport, innerdata), 3, 0)
                # We had this port
                # We need to add all the data
                innerdata['totalflows'] += 1
                innerdata['totalpkt'] += int(pkts)
                innerdata['totalbytes'] += int(totbytes)
                # Store for each dstip, the dstports
                temp_dstports= innerdata['dstports']
                try:
                    temp_dstports[str(dport)] += int(pkts)
                except KeyError:
                    # First time for this ip in the inner dictionary
                    temp_dstports[str(dport)] = int(pkts)
                innerdata['dstports'] = temp_dstports
                prev_data[str(ip_as_obj)] = innerdata
                self.print('add_ips() Adding for dst port {}. POST Data: {}'.format(dport, innerdata),3,0)
            except KeyError:
                # First time for this flow
                innerdata = {}
                innerdata['totalflows'] = 1
                innerdata['totalpkt'] = int(pkts)
                innerdata['totalbytes'] = int(totbytes)
                innerdata['stime'] = starttime
                innerdata['uid'] = uid
                temp_dstports = {}
                temp_dstports[str(dport)] = int(pkts)
                innerdata['dstports'] = temp_dstports
                self.print('add_ips() First time for dst port {}. Data: {}'.format(dport, innerdata),3,0)
                prev_data[str(ip_as_obj)] = innerdata
            ###########
            # After processing all the features of the ip, store all the info in the database
            # Convert the dictionary to json
            data = json.dumps(prev_data)
            # Create the key for storing
            key_name = type_host_key + 'IPs' + role + proto.upper() + summaryState
            # Store this data in the profile hash
            self.r.hset(profileid + self.separator + twid, key_name, str(data))
            # Mark the tw as modified
            self.markProfileTWAsModified(profileid, twid, starttime)
            return True
        except Exception as inst:
            exception_line = sys.exc_info()[2].tb_lineno
            self.outputqueue.put(f'01|database|[DB] Error in add_ips in database.py line {exception_line}')
            self.outputqueue.put('01|database|[DB] Type inst: {}'.format(type(inst)))
            self.outputqueue.put('01|database|[DB] Inst: {}'.format(inst))
            return False

    def refresh_data_tuples(self):
        """
        Go through all the tuples and refresh the data about the ipsinfo
        TODO
        """
        outtuples = self.getOutTuplesfromProfileTW()
        intuples = self.getInTuplesfromProfileTW()

    def add_tuple(self, profileid, twid, tupleid, data_tuple, role, starttime, uid):
        """
        Add the tuple going in or out for this profile
        :param tupleid: daddr:dport:proto
        role: 'Client' or 'Server'
        """
        # If the traffic is going out it is part of our outtuples, if not, part of our intuples
        if role == 'Client':
            direction = 'OutTuples'
        elif role == 'Server':
            direction = 'InTuples'
        try:
            self.print('Add_tuple called with profileid {}, twid {}, tupleid {}, data {}'.format(profileid, twid, tupleid, data_tuple), 3,0)
            # Get all the InTuples or OutTuples for this profileid in this TW
            profileid_twid = f'{profileid}{self.separator}{twid}'
            tuples = self.r.hget(profileid_twid, direction)
            # Separate the symbold to add and the previous data
            (symbol_to_add, previous_two_timestamps) = data_tuple
            if not tuples:
                # Must be str so we can convert later
                tuples = '{}'
            # Convert the json str to a dictionary
            tuples = json.loads(tuples)
            try:
                stored_tuple = tuples[tupleid]
                # Disasemble the input
                self.print('Not the first time for tuple {} as an {} for {} in TW {}. '
                           'Add the symbol: {}. Store previous_times: {}. Prev Data: {}'.format(
                    tupleid, direction, profileid, twid, symbol_to_add, previous_two_timestamps, tuples), 3,0)
                # Get the last symbols of letters in the DB
                prev_symbols = tuples[tupleid][0]
                # Add it to form the string of letters
                new_symbol = f'{prev_symbols}{symbol_to_add}'
                # Bundle the data together
                new_data = (new_symbol, previous_two_timestamps)
                # analyze behavioral model with lstm model if the length is divided by 3 -
                # so we send when there is 3 more characters added
                if len(new_symbol) % 3 == 0:
                    to_send = {
                                'new_symbol':new_symbol,
                                'profileid':profileid,
                                'twid':twid,
                                'tupleid':str(tupleid),
                                'uid':uid,
                                'stime': starttime
                    }
                    to_send = json.dumps(to_send)
                    self.publish('new_letters', to_send)
                tuples[tupleid] = new_data
                self.print('\tLetters so far for tuple {}: {}'.format(tupleid, new_symbol),3,0)
                tuples = json.dumps(tuples)
            except (TypeError, KeyError):
                # TODO check that this condition is triggered correctly only for the first case and not the rest after...
                # There was no previous data stored in the DB
                self.print('First time for tuple {} as an {} for {} in TW {}'.format(tupleid, direction, profileid, twid), 3,0)
                # Here get the info from the ipinfo key
                new_data = (symbol_to_add, previous_two_timestamps)
                tuples[tupleid] = new_data
                # Convet the dictionary to json
                tuples = json.dumps(tuples)
            # Store the new data on the db
            self.r.hset(profileid_twid, direction, str(tuples))
            # Mark the tw as modified
            self.markProfileTWAsModified(profileid, twid, starttime)
        except Exception as inst:
            exception_line = sys.exc_info()[2].tb_lineno
            self.outputqueue.put(f'01|database|[DB] Error in add_tuple in database.py line {exception_line}')
            self.outputqueue.put('01|database|[DB] Type inst: {}'.format(type(inst)))
            self.outputqueue.put('01|database|[DB] Inst: {}'.format(inst))
            self.outputqueue.put('01|database|[DB] {}'.format(traceback.format_exc()))

    def add_port(self, profileid: str, twid: str, ip_address: str, columns: dict, role: str, port_type: str):
        """
        Store info learned from ports for this flow
        The flow can go out of the IP (we are acting as Client) or into the IP (we are acting as Server)
        role: 'Client' or 'Server'. Client also defines that the flow is going out, Server that is going in
        port_type: 'Dst' or 'Src'. Depending if this port was a destination port or a source port
        """
        try:
            # Extract variables from columns
            dport = columns['dport']
            sport = columns['sport']
            totbytes = columns['bytes']
            sbytes = columns['sbytes']
            pkts = columns['pkts']
            spkts = columns['spkts']
            state = columns['state']
            proto = columns['proto'].upper()
            daddr = columns['daddr']
            saddr = columns['saddr']
            starttime = str(columns['starttime'])
            uid = columns['uid']
            # Choose which port to use based if we were asked Dst or Src
            if port_type == 'Dst':
                port = str(dport)
            elif port_type == 'Src':
                port = str(sport)
            # If we are the Client, we want to store the dstips only
            # If we are the Server, we want to store the srcips only
            # This is the only combination that makes sense.
            if role == 'Client':
                ip_key = 'dstips'
            elif role == 'Server':
                ip_key = 'srcips'
            # Get the state. Established, NotEstablished
            summaryState = __database__.getFinalStateFromFlags(state, pkts)
            # Key
            key_name = port_type + 'Ports' + role + proto + summaryState
            #self.print('add_port(): As a {} storing info about {} port {} for {}. Key: {}.'.format(role, port_type, port, profileid, key_name), 0, 3)
            prev_data = self.getDataFromProfileTW(profileid, twid, port_type, summaryState, proto, role, 'Ports')
            try:
                innerdata = prev_data[port]
                innerdata['totalflows'] += 1
                innerdata['totalpkt'] += int(pkts)
                innerdata['totalbytes'] += int(totbytes)
                temp_dstips = innerdata[ip_key]
                try:
                    temp_dstips[str(ip_address)]['pkts'] += int(pkts)
                except KeyError:
                    temp_dstips[str(ip_address)] = {}
                    temp_dstips[str(ip_address)]['pkts'] = int(pkts)
                    temp_dstips[str(ip_address)]['stime'] = str(starttime)
                    temp_dstips[str(ip_address)]['uid'] = uid
                innerdata[ip_key] = temp_dstips
                prev_data[port] = innerdata
                self.print('add_port(): Adding this new info about port {} for {}. Key: {}. NewData: {}'.format(port, profileid, key_name, innerdata), 3,0)
            except KeyError:
                # First time for this flow
                innerdata = {}
                innerdata['totalflows'] = 1
                innerdata['totalpkt'] = int(pkts)
                innerdata['totalbytes'] = int(totbytes)
                temp_dstips = {}
                temp_dstips[str(ip_address)] = {}
                temp_dstips[str(ip_address)]['pkts'] = int(pkts)
                temp_dstips[str(ip_address)]['stime'] = starttime
                temp_dstips[str(ip_address)]['uid'] = uid
                innerdata[ip_key] = temp_dstips
                prev_data[port] = innerdata
                self.print('add_port(): First time for port {} for {}. Key: {}. Data: {}'.format(port, profileid, key_name, innerdata), 3,0)
            # self.outputqueue.put('01|database|[DB] {} '.format(ip_address))
            # Convet the dictionary to json
            data = json.dumps(prev_data)
            self.print('add_port(): Storing info about port {} for {}. Key: {}. Data: {}'.format(port, profileid, key_name, prev_data), 3,0)
            # Store this data in the profile hash
            hash_key = profileid + self.separator + twid
            self.r.hset(hash_key, key_name, str(data))
            # Mark the tw as modified
            self.markProfileTWAsModified(profileid, twid, starttime)
        except Exception as inst:
            exception_line = sys.exc_info()[2].tb_lineno
            self.outputqueue.put(f'01|database|[DB] Error in add_port in database.py line {exception_line}')
            self.outputqueue.put('01|database|[DB] Type inst: {}'.format(type(inst)))
            self.outputqueue.put('01|database|[DB] Inst: {}'.format(inst))

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
        except Exception as inst:
            exception_line = sys.exc_info()[2].tb_lineno
            self.outputqueue.put(f'01|database|[DB] Error in getDataFromProfileTW in database.py line {exception_line}')
            self.outputqueue.put('01|database|[DB] Type inst: {}'.format(type(inst)))
            self.outputqueue.put('01|database|[DB] Inst: {}'.format(inst))

    def getOutTuplesfromProfileTW(self, profileid, twid):
        """ Get the out tuples """
        data = self.r.hget(profileid + self.separator + twid, 'OutTuples')
        return data

    def getInTuplesfromProfileTW(self, profileid, twid):
        """ Get the in tuples """
        data = self.r.hget(profileid + self.separator + twid, 'InTuples')
        return data

    def getFinalStateFromFlags(self, state, pkts):
        """
        Analyze the flags given and return a summary of the state. Should work with Argus and Bro flags
        We receive the pakets to distinguish some Reset connections
        """
        try:
            #self.outputqueue.put('06|database|[DB]: State received {}'.format(state))
            pre = state.split('_')[0]
            try:
                # Try suricata states
                """	
                 There are different states in which a flow can be. 	
                 Suricata distinguishes three flow-states for TCP and two for UDP. For TCP, 	
                 these are: New, Established and Closed,for UDP only new and established.	
                 For each of these states Suricata can employ different timeouts. 	
                 """
                if 'new' in state or 'established' in state:
                    return 'Established'
                elif 'closed' in state:
                    return 'NotEstablished'
                # We have varius type of states depending on the type of flow.
                # For Zeek
                if 'S0' in state or 'REJ' in state or 'RSTOS0' in state or 'RSTRH' in state or 'SH' in state or 'SHR' in state:
                    return 'NotEstablished'
                elif 'S1' in state or 'SF' in state or 'S2' in state or 'S3' in state or 'RSTO' in state or 'RSTP' in state or 'OTH' in state:
                    return 'Established'
                # For Argus
                suf = state.split('_')[1]
                if 'S' in pre and 'A' in pre and 'S' in suf and 'A' in suf:
                    """	
                    Examples:	
                    SA_SA	
                    SR_SA	
                    FSRA_SA	
                    SPA_SPA	
                    SRA_SPA	
                    FSA_FSA	
                    FSA_FSPA	
                    SAEC_SPA	
                    SRPA_SPA	
                    FSPA_SPA	
                    FSRPA_SPA	
                    FSPA_FSPA	
                    FSRA_FSPA	
                    SRAEC_SPA	
                    FSPA_FSRPA	
                    FSAEC_FSPA	
                    FSRPA_FSPA	
                    SRPAEC_SPA	
                    FSPAEC_FSPA	
                    SRPAEC_FSRPA	
                    """
                    return 'Established'
                elif 'PA' in pre and 'PA' in suf:
                    # Tipical flow that was reported in the middle
                    """	
                    Examples:	
                    PA_PA	
                    FPA_FPA	
                    """
                    return 'Established'
                elif 'ECO' in pre:
                    return 'ICMP Echo'
                elif 'ECR' in pre:
                    return 'ICMP Reply'
                elif 'URH' in pre:
                    return 'ICMP Host Unreachable'
                elif 'URP' in pre:
                    return 'ICMP Port Unreachable'
                else:
                    """	
                    Examples:	
                    S_RA	
                    S_R	
                    A_R	
                    S_SA 	
                    SR_SA	
                    FA_FA	
                    SR_RA	
                    SEC_RA	
                    """
                    return 'NotEstablished'
            except IndexError:
                # suf does not exist, which means that this is some ICMP or no response was sent for UDP or TCP
                if 'ECO' in pre:
                    # ICMP
                    return 'Established'
                elif 'UNK' in pre:
                    # ICMP6 unknown upper layer
                    return 'Established'
                elif 'CON' in pre:
                    # UDP
                    return 'Established'
                elif 'INT' in pre:
                    # UDP trying to connect, NOT preciselly not established but also NOT 'Established'. So we considered not established because there
                    # is no confirmation of what happened.
                    return 'NotEstablished'
                elif 'EST' in pre:
                    # TCP
                    return 'Established'
                elif 'RST' in pre:
                    # TCP. When -z B is not used in argus, states are single words. Most connections are reseted when finished and therefore are established
                    # It can happen that is reseted being not established, but we can't tell without -z b.
                    # So we use as heuristic the amount of packets. If <=3, then is not established because the OS retries 3 times.
                    if int(pkts) <= 3:
                        return 'NotEstablished'
                    else:
                        return 'Established'
                elif 'FIN' in pre:
                    # TCP. When -z B is not used in argus, states are single words. Most connections are finished with FIN when finished and therefore are established
                    # It can happen that is finished being not established, but we can't tell without -z b.
                    # So we use as heuristic the amount of packets. If <=3, then is not established because the OS retries 3 times.
                    if int(pkts) <= 3:
                        return 'NotEstablished'
                    else:
                        return 'Established'
                else:
                    """	
                    Examples:	
                    S_	
                    FA_	
                    PA_	
                    FSA_	
                    SEC_	
                    SRPA_	
                    """
                    return 'NotEstablished'
            self.outputqueue.put('01|database|[DB] Funcion getFinalStateFromFlags() We didnt catch the state. We should never be here')
            return None
        except Exception as inst:
            exception_line = sys.exc_info()[2].tb_lineno
            self.outputqueue.put(f'01|database|[DB] Error in getFinalStateFromFlags() in database.py line {exception_line}')
            self.outputqueue.put('01|database|[DB] Type inst: {}'.format(type(inst)))
            self.outputqueue.put('01|database|[DB] Inst: {}'.format(inst))
            self.print(traceback.format_exc())

    def getFieldSeparator(self):
        """ Return the field separator """
        return self.separator

    def set_evidence_causing_alert(self, alert_ID, evidence_IDs: list):
        """
        When we have a bunch of evidence causing an alert, we assiciate all evidence IDs with the alert ID in our database
        :param alert ID: the profileid_twid_ID of the last evidence causing this alert
        :param evidence_IDs: all IDs of the evidence causing this alert
        """
        evidence_IDs = json.dumps(evidence_IDs)
        self.r.hset('alerts', alert_ID, evidence_IDs)

    def get_evidence_causing_alert(self, alert_ID) -> list:
        """
        Returns all the IDs of evidence causing this alert
        """
        evidence_IDs = self.r.hget('alerts', alert_ID)
        if evidence_IDs:
            return json.loads(evidence_IDs)
        else:
            return False

    def get_evidence_by_ID(self, profileid, twid, ID):

        evidence = self.getEvidenceForTW(profileid, twid)
        if not evidence:
            return False

        evidence:dict = json.loads(evidence)
        # loop through each evidence in this tw
        for description, evidence_details in evidence.items():
            evidence_details = json.loads(evidence_details)
            if evidence_details.get('ID') == ID:
                # found an evidence that has a matching ID
                return evidence_details


    def is_detection_disabled(self, evidence):
        """
        Function to check if detection is disabled in slips.conf
        """
        for disabled_detection in self.disabled_detections:
            # when we disable a detection , we add 'SSHSuccessful' in slips.conf,
            # however our evidence can depend on an addr, for example 'SSHSuccessful-by-addr'.
            # check if any disabled detection is a part of our evidence.
            # for example 'SSHSuccessful' is a part of 'SSHSuccessful-by-addr' so if  'SSHSuccessful'
            # is disabled,  'SSHSuccessful-by-addr' should also be disabled
            if disabled_detection in evidence:
                return True
        return False


    def setEvidence(self, type_evidence, type_detection, detection_info,
                    threat_level, confidence, description, timestamp, category,
                    source_target_tag=False,
                    conn_count=False, port=False, proto=False, profileid='', twid='', uid=''):
        """
        Set the evidence for this Profile and Timewindow.

        type_evidence: determine the type of this evidence. e.g. PortScan, ThreatIntelligence
        type_detection: the type of value causing the detection e.g. dport, dip, flow
        detection_info: the actual dstip or dstport. e.g. 1.1.1.1 or 443
        threat_level: determine the importance of the evidence, available options are : info, low, medium, high, critical
        confidence: determine the confidence of the detection on a scale from 0 to 1. (How sure you are that this is what you say it is.)
        uid: needed to get the flow from the database
        category: what is this evidence category according to IDEA categories
        conn_count: the number of packets/flows/nxdomains that formed this scan/sweep/DGA.

        source_target_tag:
            this is the IDEA category of the source and dst ip used in the evidence
            if the type_detection is srcip this describes the source ip,
            if the type_detection is dstip this describes the dst ip.
            supported source and dst types are in the SourceTargetTag section https://idea.cesnet.cz/en/classifications
            this is a keyword/optional argument because it shouldn't be used with dports and sports type_detection
        """

        # Ignore evidence if it's disabled in the configuration file
        if self.is_detection_disabled(type_evidence):
            return False

        # Check if we have and get the current evidence stored in the DB fot this profileid in this twid
        current_evidence = self.getEvidenceForTW(profileid, twid)
        if current_evidence:
            current_evidence = json.loads(current_evidence)
        else:
            current_evidence = {}

        # every evidence should have an ID according to the IDEA format
        evidence_ID = str(uuid4())

        evidence_to_send = {
                'profileid': str(profileid),
                'twid': str(twid),
                'type_detection' : type_detection,
                'detection_info' : detection_info ,
                'type_evidence' : type_evidence,
                'description': description,
                'stime': timestamp,
                'uid' : uid,
                'confidence' : confidence,
                'threat_level': threat_level,
                'category': category,
                'ID': evidence_ID
            }
        # not all evidence requires a conn_coun, scans only
        if conn_count: evidence_to_send.update({'conn_count': conn_count })

        # source_target_tag is defined only if type_detection is srcip or dstip
        if source_target_tag: evidence_to_send.update({'source_target_tag': source_target_tag })

        if port: evidence_to_send.update({'port': port })
        if proto: evidence_to_send.update({'proto': proto })

        evidence_to_send = json.dumps(evidence_to_send)
        # This is done to ignore repetition of the same evidence sent.
        if description not in current_evidence.keys():
            self.publish('evidence_added', evidence_to_send)

        # update our current evidence for this profileid and twid. now the description is used as the key
        current_evidence.update({description : evidence_to_send})

        # Set evidence in the database.
        current_evidence = json.dumps(current_evidence)

        self.r.hset(profileid + self.separator + twid, 'Evidence', current_evidence)
        self.r.hset('evidence'+profileid, twid, current_evidence)

        return True

    def get_evidence_count(self, evidence_type, profileid, twid):
        """
        Returns the number of evidence of this type in this profiled and twid
        :param evidence_type: PortScan, ThreatIntelligence, C&C channels detection etc..
        """
        count = 0
        evidence = self.getEvidenceForTW(profileid, twid)
        if not evidence:
            return False

        evidence:dict = json.loads(evidence)
        # loop through each evidence in this tw
        for description, evidence_details in evidence.items():
            evidence_details = json.loads(evidence_details)
            if evidence_type in evidence_details['type_evidence']:
                count +=1
        return count


    def deleteEvidence(self,profileid, twid, description: str):
        """
        Delete evidence from the database
        :param description: teh description of the evidence
        """

        current_evidence = self.getEvidenceForTW(profileid, twid)
        if current_evidence:
            current_evidence = json.loads(current_evidence)
        else:
            current_evidence = {}

        # Delete the key regardless of whether it is in the dictionary
        current_evidence.pop(description, None)
        current_evidence_json = json.dumps(current_evidence)

        self.r.hset(profileid + self.separator + twid, 'Evidence', str(current_evidence_json))
        self.r.hset('evidence'+profileid, twid, current_evidence_json)

    def getEvidenceForTW(self, profileid, twid):
        """ Get the evidence for this TW for this Profile """
        data = self.r.hget(profileid + self.separator + twid, 'Evidence')
        return data

    def getEvidenceForProfileid(self,profileid):
        profile_evidence = {}
        # get all tws for this profileid
        timewindows = self.getTWsfromProfile(profileid)
        for twid,ts in timewindows:
            # get all evidence in this tw
            tw_evidence = self.getEvidenceForTW(profileid, twid)
            if tw_evidence:
                tw_evidence = json.loads(tw_evidence)
                profile_evidence.update(tw_evidence)
        return profile_evidence


    def checkBlockedProfTW(self, profileid, twid):
        """
        Check if profile and timewindow is blocked
        """
        res = self.r.sismember('BlockedProfTW', profileid + self.separator + twid)
        return res

    def set_first_stage_ensembling_label_to_flow(self, profileid, twid, uid, ensembling_label):
        """
        Add a final label to the flow
        """
        flow = self.get_flow(profileid, twid, uid)
        if flow:
            data = json.loads(flow[uid])
            data['1_ensembling_label'] = ensembling_label
            data = json.dumps(data)
            self.r.hset(profileid + self.separator + twid + self.separator + 'flows', uid, data)

    def set_module_label_to_flow(self, profileid, twid, uid, module_name, module_label):
        """
        Add a module label to the flow
        """
        flow = self.get_flow(profileid, twid, uid)
        if flow and flow[uid]:
            data = json.loads(flow[uid])
            # here we dont care if add new module lablel or changing existing one
            data['module_labels'][module_name] = module_label
            data = json.dumps(data)
            self.r.hset(profileid + self.separator + twid + self.separator + 'flows', uid, data)


    def get_module_labels_from_flow(self, profileid, twid, uid):
        """
        Get the label from the flow
        """
        flow = self.get_flow(profileid, twid, uid)
        if flow:
            data = json.loads(flow[uid])
            labels = data['module_labels']
            return labels
        else:
            return {}

    def markProfileTWAsBlocked(self, profileid, twid):
        """ Add this profile and tw to the list of blocked """
        self.r.sadd('BlockedProfTW', profileid + self.separator + twid)

    def getBlockedProfTW(self):
        """ Return all the list of blocked tws """
        data = self.r.smembers('BlockedProfTW')
        return data

    def getDomainData(self, domain):
        """
        Return information about this domain
        Returns a dictionary or False if there is no domain in the database
        We need to separate these three cases:
        1- Domain is in the DB without data. Return empty dict.
        2- Domain is in the DB with data. Return dict.
        3- Domain is not in the DB. Return False
        """
        data = self.rcache.hget('DomainsInfo', domain)
        if data or data == {}:
            # This means the domain was in the database, with or without data
            # Case 1 and 2
            # Convert the data
            data = json.loads(data)
            # print(f'In the DB: Domain {domain}, and data {data}')
        else:
            # The Domain was not in the DB
            # Case 3
            data = False
            # print(f'In the DB: Domain {domain}, and data {data}')
        return data

    def getIPIdentification(self, ip: str):
        """
        Return the identification of this IP based
        on the data stored so far
        """
        current_data = self.getIPData(ip)
        identification = ''
        if current_data:
            if 'asn' in current_data.keys():
                asn = current_data['asn']['asnorg']
                if 'Unknown' not in asn and asn != '':
                    identification += 'AS: ' + asn + ', '
            if 'SNI' in current_data.keys():
                SNI = current_data['SNI']
                if type(SNI) == list:
                    SNI = SNI[0]
                identification += 'SNI: ' + SNI['server_name'] + ', '
            if 'reverse_dns' in current_data.keys():
                identification += 'rDNS: ' + current_data['reverse_dns'] + ', '
        identification = identification[:-2]
        return identification

    def getIPData(self, ip: str):
        """
        Return information about this IP
        Returns a dictionary or False if there is no IP in the database
        We need to separate these three cases:
        1- IP is in the DB without data. Return empty dict.
        2- IP is in the DB with data. Return dict.
        3- IP is not in the DB. Return False
        """
        if type(ip) == ipaddress.IPv4Address or type(ip) == ipaddress.IPv6Address:
            ip = str(ip)
        data = self.rcache.hget('IPsInfo', ip)
        if data:
            # This means the IP was in the database, with or without data
            # Convert the data
            data = json.loads(data)
            # print(f'In the DB: IP {ip}, and data {data}')
        else:
            # The IP was not in the DB
            data = False
            # print(f'In the DB: IP {ip}, and data {data}')
        return data

    def getURLData(self,url):
        """
        Return information about this URL
        Returns a dictionary or False if there is no IP in the database
        We need to separate these three cases:
        1- IP is in the DB without data. Return empty dict.
        2- IP is in the DB with data. Return dict.
        3- IP is not in the DB. Return False
        """
        data = self.rcache.hget('URLsInfo', url)
        if data:
            # This means the URL was in the database, with or without data
            # Convert the data
            data = json.loads(data)
        else:
            # The IP was not in the DB
            data = False
        return data

    def getallIPs(self):
        """ Return list of all IPs in the DB """
        data = self.rcache.hgetall('IPsInfo')
        # data = json.loads(data)
        return data

    def getallURLs(self):
        """ Return list of all URLs in the DB """
        data = self.rcache.hgetall('URLsInfo')
        # data = json.loads(data)
        return data

    def setNewDomain(self, domain: str):
        """
        1- Stores this new domain in the Domains hash
        2- Publishes in the channels that there is a new domain, and that we want
            data from the Threat Intelligence modules
        """
        data = self.getDomainData(domain)
        if data is False:
            # If there is no data about this domain
            # Set this domain for the first time in the DomainsInfo
            # Its VERY important that the data of the first time we see a domain
            # must be '{}', an empty dictionary! if not the logic breaks.
            # We use the empty dictionary to find if a domain exists or not
            self.rcache.hset('DomainsInfo', domain, '{}')
            # Publish that there is a new IP ready in the channel
            self.publish('new_dns', domain)

    def setNewIP(self, ip: str):
        """
        1- Stores this new IP in the IPs hash
        2- Publishes in the channels that there is a new IP, and that we want
            data from the Threat Intelligence modules
        Sometimes it can happend that the ip comes as an IP object, but when
        accessed as str, it is automatically
        converted to str
        """
        data = self.getIPData(ip)
        if data is False:
            # If there is no data about this IP
            # Set this IP for the first time in the IPsInfo
            # Its VERY important that the data of the first time we see an IP
            # must be '{}', an empty dictionary! if not the logic breaks.
            # We use the empty dictionary to find if an IP exists or not
            self.rcache.hset('IPsInfo', ip, '{}')
            # Publish that there is a new IP ready in the channel
            self.publish('new_ip', ip)

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


    def getIP(self, ip):
        """ Check if this ip is the hash of the profiles! """
        data = self.rcache.hget('IPsInfo', ip)
        if data:
            return True
        else:
            return False

    def getURL(self,url):
        """ Check if this url is the hash of the profiles! """
        data = self.rcache.hget('URLsInfo', url)
        if data:
            return True
        else:
            return False

    def setInfoForDomains(self, domain: str, info_to_set: dict, mode='leave'):
        """
        Store information for this domain
        :param info_to_set: a dictionary, such as {'geocountry': 'rumania'} that we are
        going to store for this domain
        :param mode: defines how to deal with the new data
        - to 'overwrite' the data with the new data
        - to 'add' the data to the new data
        - to 'leave' the past data untouched
        """

        # Get the previous info already stored
        domain_data = self.getDomainData(domain)
        if not domain_data:
            # This domain is not in the dictionary, add it first:
            self.setNewDomain(domain)
            # Now get the data, which should be empty, but just in case
            domain_data = self.getDomainData(domain)

        # Let's check each key stored for this domain
        for key in iter(info_to_set):
            # info_to_set can be {'VirusTotal': [1,2,3,4], 'Malicious': ""}
            # info_to_set can be {'VirusTotal': [1,2,3,4]}

            # I think we dont need this anymore of the conversion
            if type(domain_data) == str:
                # Convert the str to a dict
                domain_data = json.loads(domain_data)

            # this can be a str or a list
            data_to_store = info_to_set[key]
            # If there is data previously stored, check if we have
            # this key already
            try:
                # Do we have the key alredy?
                _ = domain_data[key]

                # convert incoming data to list
                if type(data_to_store) != list:
                    # data_to_store and prev_info Should both be lists, so we can extend
                    data_to_store = [data_to_store]

                if mode == 'overwrite':
                    domain_data[key] = data_to_store
                elif mode == 'add':
                    prev_info = domain_data[key]

                    if type(prev_info) == list:
                        # for example, list of IPs
                        prev_info.extend(data_to_store)
                        domain_data[key] = list(set(prev_info))
                    elif type(prev_info) == str:
                        # previous info about this domain is a str, we should make it a list and extend
                        prev_info = [prev_info]
                        # add the new data_to_store to our prev_info
                        domain_data[key] = prev_info.extend(data_to_store)
                    elif prev_info == None:
                        # no previous info about this domain
                        domain_data[key] = data_to_store

                elif mode == 'leave':
                    return

            except KeyError:
                # There is no data for the key so far. Add it
                if type(data_to_store) == list:
                    domain_data[key] = list(set(data_to_store))
                else:
                    domain_data[key] = data_to_store
            # Store
            domain_data = json.dumps(domain_data)
            self.rcache.hset('DomainsInfo', domain, domain_data)
            # Publish the changes
            self.r.publish('dns_info_change', domain)

    def setInfoForIPs(self, ip: str, ipdata: dict):
        """
        Store information for this IP
        We receive a dictionary, such as {'geocountry': 'rumania'} that we are
        going to store for this IP.
        If it was not there before we store it. If it was there before, we
        overwrite it
        """
        # Get the previous info already stored
        data = self.getIPData(ip)
        if data is False:
            # This IP is not in the dictionary, add it first:
            self.setNewIP(ip)
            # Now get the data, which should be empty, but just in case
            data = self.getIPData(ip)

        for key in iter(ipdata):
            data_to_store = ipdata[key]
            # If there is data previously stored, check if we have this key already
            try:
                # We modify value in any case, because there might be new info
                _ = data[key]
            except KeyError:
                # There is no data for they key so far.
                # Publish the changes
                self.r.publish('ip_info_change', ip)
            data[key] = data_to_store
            newdata_str = json.dumps(data)
            self.rcache.hset('IPsInfo', ip, newdata_str)

    def setInfoForFile(self, md5: str, filedata: dict):
        """
        Store information for this file (only if it's malicious)
        We receive a dictionary, such as {'virustotal': score} that we are
        going to store for this IP.
        If it was not there before we store it. If it was there before, we
        overwrite it
        """

        file_info = json.dumps(filedata)
        self.rcache.hset('FileInfo', md5, file_info)


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


    def subscribe(self, channel):
        """ Subscribe to channel """
        # For when a TW is modified
        self.pubsub = self.r.pubsub()
        supported_channels = ['tw_modified', 'evidence_added', 'new_ip',  'new_flow',
                              'new_dns', 'new_dns_flow', 'new_http', 'new_ssl', 'new_profile',
                              'give_threat_intelligence', 'new_letters', 'ip_info_change', 'dns_info_change',
                              'dns_info_change', 'tw_closed', 'core_messages',
                              'new_blocking', 'new_ssh', 'new_notice', 'new_url',
                              'finished_modules', 'new_downloaded_file', 'reload_whitelist',
                              'new_service',  'new_arp', 'new_MAC', 'new_alert']
        for supported_channel in supported_channels:
            if supported_channel in channel:
                self.pubsub.subscribe(channel)
                break
        else:
            # channel isn't in supported_channels
            return False
        return self.pubsub

    def publish(self, channel, data):
        """ Publish something """
        self.r.publish(channel, data)

    def publish_stop(self):
        """ Publish stop command to terminate slips """
        all_channels_list = self.r.pubsub_channels()
        self.print('Sending the stop signal to all listeners', 0, 3)
        for channel in all_channels_list:
            self.r.publish(channel, 'stop_process')

    def get_all_flows_in_profileid_twid(self, profileid, twid):
        """
        Return a list of all the flows in this profileid and twid
        """
        data = self.r.hgetall(profileid + self.separator + twid + self.separator + 'flows')
        if data:
            return data

    def get_all_flows_in_profileid(self, profileid):
        """
        Return a list of all the flows in this profileid
        [{'uid':flow},...]
        """
        profileid_flows= []
        # get all tws in this profile
        for twid, time in self.getTWsfromProfile(profileid):
            flows = self.get_all_flows_in_profileid_twid(profileid, twid)
            if flows:
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
                flows_dict = self.get_all_flows_in_profileid_twid(profileid, twid)
                if flows_dict:
                    for flow in flows_dict.values():
                        dict_flow = json.loads(flow)
                        flows.append(dict_flow)
        return flows

    def get_all_contacted_ips_in_profileid_twid(self, profileid, twid) ->dict:
        """
        Get all the contacted IPs in a given profile and TW
        """
        all_flows = self.get_all_flows_in_profileid_twid(profileid,twid)
        if not all_flows:
            return {}
        contacted_ips = {}
        for uid, flow in all_flows.items():
            # get the daddr of this flow
            flow = json.loads(flow)
            daddr = flow['daddr']
            contacted_ips[daddr] = uid
        return contacted_ips


    def get_flow(self, profileid, twid, uid):
        """
        Returns the flow in the specific time
        The format is a dictionary
        """
        data = {}
        temp = self.r.hget(profileid + self.separator + twid + self.separator + 'flows', uid)
        data[uid] = temp
        # Get the dictionary format
        return data

    def get_labels(self):
        """ 
        Return the amount of each label so far in the DB
        Used to know how many labels are available during training
        """
        return self.r.zrange('labels', 0, -1, withscores=True)

    def add_flow(self, profileid='', twid='', stime='', dur='', saddr='', sport='',
                 daddr='', dport='', proto='', state='', pkts='', allbytes='', spkts='', sbytes='',
                 appproto='', uid='', label='', flow_type=''):
        """
        Function to add a flow by interpreting the data. The flow is added to the correct TW for this profile.
        The profileid is the main profile that this flow is related too.
        """
        summaryState = __database__.getFinalStateFromFlags(state, pkts)
        data = {'ts': stime,
            'dur': dur,
            'saddr': saddr,
            'sport': sport,
            'daddr': daddr,
            'dport': dport,
            'proto': proto,
            'origstate': state,
            'state': summaryState,
            'pkts': pkts,
            'allbytes': allbytes,
            'spkts': spkts, 'sbytes': sbytes,
            'appproto': appproto,
            'label': label,
            'flow_type': flow_type,
            'module_labels': {}}
         # when adding a flow, there are still no labels ftom other modules, so the values is empty dictionary

        # Convert to json string
        data = json.dumps(data)
        # Store in the hash 10.0.0.1_timewindow1_flows, a key uid, with data
        value = self.r.hset(f'{profileid}{self.separator}{twid}{self.separator}flows', uid, data)
        if not value:
            # duplicate flow
            return False

        # The key was not there before. So this flow is not repeated
        # Store the label in our uniq set, and increment it by 1
        if label:
            self.r.zincrby('labels', 1, label)
        # We can publish the flow directly without asking for it, but its good to maintain the format given by the get_flow() function.
        flow = self.get_flow(profileid, twid, uid)
        # Get the dictionary and convert to json string
        flow = json.dumps(flow)
        # Prepare the data to publish.
        to_send = {}
        to_send['profileid'] = profileid
        to_send['twid'] = twid
        to_send['flow'] = flow
        to_send['stime'] = stime
        to_send = json.dumps(to_send)
        self.publish('new_flow', to_send)
        return True


    def add_out_ssl(self, profileid, twid, stime, daddr_as_obj, dport, flowtype, uid,
                    version, cipher, resumed, established, cert_chain_fuids,
                    client_cert_chain_fuids, subject, issuer, validation_status, curve, server_name, ja3, ja3s):
        """
        Store in the DB an ssl request
        All the type of flows that are not netflows are stored in a separate hash ordered by uid.
        The idea is that from the uid of a netflow, you can access which other type of info is related to that uid
        """
        data = {
            'uid' : uid,
            'type' : flowtype,
            'version' : version,
            'cipher' : cipher,
            'resumed' : resumed,
            'established' : established,
            'cert_chain_fuids' : cert_chain_fuids,
            'client_cert_chain_fuids' : client_cert_chain_fuids,
            'subject' : subject,
            'issuer' : issuer,
            'validation_status' : validation_status,
            'curve' : curve,
            'server_name' : server_name,
            'daddr' : str(daddr_as_obj),
            'dport' : dport,
            'stime' : stime,
            'ja3' : ja3,
            'ja3s' : ja3s}
        # Convert to json string
        data = json.dumps(data)
        self.r.hset(f'{profileid}{self.separator}{twid}{self.separator}altflows', uid, data)
        to_send = {
            'profileid' : profileid,
            'twid' : twid,
            'flow' : data,
            'stime' : stime}
        to_send = json.dumps(to_send)
        self.publish('new_ssl', to_send)
        self.print('Adding SSL flow to DB: {}'.format(data), 3, 0)
        # Check if the server_name (SNI) is detected by the threat intelligence. Empty field in the end, cause we have extrafield for the IP.
        # If server_name is not empty, set in the IPsInfo and send to TI
        if not server_name: return False

        # Save new server name in the IPInfo. There might be several server_name per IP.
        ipdata = self.getIPData(str(daddr_as_obj))
        if ipdata:
            sni_ipdata = ipdata.get('SNI', [])
        else:
            sni_ipdata = []
        SNI_port = {'server_name':server_name, 'dport':dport}
        # We do not want any duplicates.
        if SNI_port not in sni_ipdata:
            # Verify that the SNI is equal to any of the domains in the DNS resolution
            # only add this SNI to our db if it has a DNS resolution
            dns_resolutions = self.r.hgetall('DNSresolution')
            if dns_resolutions:
                # dns_resolutions is a dict with {ip:{'ts'..,'domains':..., 'uid':..}}
                for ip, resolution in dns_resolutions.items():
                    resolution = json.loads(resolution)
                    if SNI_port['server_name'] in resolution['domains']:
                        # add SNI to our db as it has a DNS resolution
                        sni_ipdata.append(SNI_port)
                        self.setInfoForIPs(str(daddr_as_obj), {'SNI':sni_ipdata})
                        break
        # We are giving only new server_name to the threat_intelligence module.
        data_to_send = {
            'server_name' : server_name,
            'profileid' : str(profileid),
            'twid': str(twid),
            'stime': stime,
            'uid':uid
        }
        data_to_send = json.dumps(data_to_send)
        self.publish('give_threat_intelligence', data_to_send)

    def add_out_http(self, profileid, twid, stime, flowtype, uid,
                     method, host, uri, version, user_agent,
                     request_body_len, response_body_len,
                     status_code, status_msg, resp_mime_types,
                     resp_fuids):
        """
        Store in the DB a http request
        All the type of flows that are not netflows are stored in a separate hash ordered by uid.
        The idea is that from the uid of a netflow, you can access which other type of info is related to that uid
        """
        data = {
            'uid' : uid,
            'type' : flowtype,
            'method' : method,
            'host' : host,
            'uri' : uri,
            'version' : version,
            'user_agent' : user_agent,
            'request_body_len' : request_body_len,
            'response_body_len' : response_body_len,
            'status_code' : status_code,
            'status_msg' : status_msg,
            'resp_mime_types' : resp_mime_types,
            'resp_fuids' : resp_fuids,
            'stime' : stime}
        # Convert to json string
        data = json.dumps(data)

        self.r.hset(f'{profileid}{ self.separator }{twid}{ self.separator }altflows', uid, data)
        to_send = {
            'profileid' : profileid,
            'twid' : twid,
            'flow' : data,
            'stime' : stime}
        to_send = json.dumps(to_send)
        self.publish('new_http', to_send)
        self.publish('new_url', to_send)

        self.print('Adding HTTP flow to DB: {}'.format(data), 3, 0)
        # Check if the host domain is detected by the threat intelligence. Empty field in the end, cause we have extrafield for the IP.
        data_to_send = {
                'host': host,
                'profileid' : str(profileid),
                'twid' :  str(twid),
                'stime': stime,
                'uid':uid
            }
        data_to_send = json.dumps(data_to_send)
        self.publish('give_threat_intelligence', data_to_send)

    def add_out_ssh(self, profileid, twid, stime, flowtype,
                    uid, ssh_version, auth_attempts, auth_success,
                    client, server, cipher_alg, mac_alg, compression_alg,
                    kex_alg, host_key_alg, host_key):
        """
        Store in the DB a SSH request
        All the type of flows that are not netflows are stored in a
        separate hash ordered by uid.
        The idea is that from the uid of a netflow, you can access which
        other type of info is related to that uid
        """
        #  {"client":"SSH-2.0-OpenSSH_8.1","server":"SSH-2.0-OpenSSH_7.5p1 Debian-5","cipher_alg":"chacha20-pol y1305@openssh.com","mac_alg":"umac-64-etm@openssh.com","compression_alg":"zlib@openssh.com","kex_alg":"curve25519-sha256","host_key_alg":"ecdsa-sha2-nistp256","host_key":"de:04:98:42:1e:2a:06:86:5b:f0:5b:e3:65:9f:9d:aa"}
        data = {
            'uid' : uid,
            'type' : flowtype,
            'version' : ssh_version,
            'auth_attempts' : auth_attempts,
            'auth_success' : auth_success,
            'client' : client,
            'server' : server,
            'cipher_alg' : cipher_alg,
            'mac_alg' : mac_alg,
            'compression_alg' : compression_alg,
            'kex_alg' : kex_alg,
            'host_key_alg' : host_key_alg,
            'host_key' : host_key,
            'stime' : stime}
        # Convert to json string
        data = json.dumps(data)
        # Set the dns as alternative flow
        self.r.hset(f'{profileid}{self.separator}{twid}{self.separator}altflows', uid, data)
        # Publish the new dns received
        to_send = {
            'profileid' : profileid,
            'twid' : twid,
            'flow' : data,
            'stime' : stime,
            'uid' : uid}
        to_send = json.dumps(to_send)
        # publish a dns with its flow
        self.publish('new_ssh', to_send)
        self.print('Adding SSH flow to DB: {}'.format(data), 3, 0)
        # Check if the dns is detected by the threat intelligence. Empty field in the end, cause we have extrafield for the IP.

    def add_out_notice(self, profileid, twid,
                       stime, daddr, sport,
                       dport, note, msg, scanned_port,
                       scanning_ip, uid):
        """" Send notice.log data to new_notice channel to look for self-signed certificates """
        data = {
            'type': 'notice',
            'daddr': daddr,
            'sport': sport,
            'dport': dport,
            'note': note,
            'msg': msg,
            'scanned_port': scanned_port,
            'scanning_ip': scanning_ip,
            'stime': stime
        }
        data = json.dumps(data) # this is going to be sent insidethe to_send dict
        to_send = {
             'profileid' : profileid,
             'twid' : twid,
             'flow' : data,
             'stime' : stime,
             'uid' : uid}
        to_send = json.dumps(to_send)
        self.r.hset(f'{profileid}{self.separator}{twid}{self.separator}altflows', uid, data)
        self.publish('new_notice', to_send)
        self.print('Adding notice flow to DB: {}'.format(data), 3, 0)

    def add_out_dns(self, profileid, twid, stime, flowtype, uid, query, qclass_name, qtype_name, rcode_name, answers, ttls):
        """
        Store in the DB a DNS request
        All the type of flows that are not netflows are stored in a separate hash ordered by uid.
        The idea is that from the uid of a netflow, you can access which other type of info is related to that uid
        """
        data = {
            'uid' : uid,
            'type' : flowtype,
            'query' : query,
            'qclass_name' : qclass_name,
            'qtype_name' : qtype_name,
            'rcode_name' : rcode_name,
            'answers' : answers,
            'ttls' : ttls,
            'stime' : stime}

        # Add DNS resolution to the db if there are answers for the query
        if answers:
            self.set_dns_resolution(query, answers, stime, uid, qtype_name)
        # Convert to json string
        data = json.dumps(data)
        # Set the dns as alternative flow
        self.r.hset(f'{profileid}{self.separator}{twid}{self.separator}altflows', uid, data)
        # Publish the new dns received
        to_send = {
        'profileid': profileid,
        'twid': twid,
        'flow': data,
        'stime': stime,
        'uid': uid,
        'rcode_name': rcode_name}

        to_send = json.dumps(to_send)
        #publish a dns with its flow
        self.publish('new_dns_flow', to_send)
        self.print('Adding DNS flow to DB: {}'.format(data), 3,0)
        # Check if the dns is detected by the threat intelligence. Empty field in the end, cause we have extrafield for the IP.
        data_to_send = {
                'query': str(query),
                'profileid' : str(profileid),
                'twid' :  str(twid),
                'stime': stime,
                'uid': uid
            }
        data_to_send = json.dumps(data_to_send)
        self.publish('give_threat_intelligence', data_to_send)
        
        # Store this DNS resolution into the Info of the IPs resolved
        #self.setInfoForIPs(ip, domain)

    def get_altflow_from_uid(self, profileid, twid, uid):
        """ Given a uid, get the alternative flow realted to it """
        return self.r.hget(profileid + self.separator + twid + self.separator + 'altflows', uid)

    def add_timeline_line(self, profileid, twid, data, timestamp):
        """ Add a line to the time line of this profileid and twid """
        self.print('Adding timeline for {}, {}: {}'.format(profileid, twid, data), 3, 0)
        key = str(profileid + self.separator + twid + self.separator + 'timeline')
        data = json.dumps(data)
        mapping = {}
        mapping[data] = timestamp
        self.r.zadd(key, mapping)
        # Mark the tw as modified since the timeline line is new data in the TW
        self.markProfileTWAsModified(profileid, twid, timestamp='')

    def get_timeline_last_line(self, profileid, twid):
        """ Add a line to the time line of this profileid and twid """
        key = str(profileid + self.separator + twid + self.separator + 'timeline')
        data = self.r.zrange(key, -1, -1)
        return data

    def get_timeline_last_lines(self, profileid, twid, first_index: int) -> Tuple[str, int]:
        """ Get only the new items in the timeline."""
        key = str(profileid + self.separator + twid + self.separator + 'timeline')
        # The the amount of lines in this list
        last_index = self.r.zcard(key)
        # Get the data in the list from the index asked (first_index) until the last
        data = self.r.zrange(key, first_index, last_index - 1)
        return data, last_index

    def get_timeline_all_lines(self, profileid, twid):
        """ Add a line to the time line of this profileid and twid """
        key = str(profileid + self.separator + twid + self.separator + 'timeline')
        data = self.r.zrange(key, 0, -1)
        return data

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
        :param ip: can be a single org ip, or a range
        """
        org_info = {'org_name': organization, 'ip': ip}
        org_info = json.dumps(org_info)
        self.rcache.hset('organization_port', portproto, org_info )

    def get_organization_of_port(self, portproto: str):
        """
        Retrieve the organization info that uses this port
        :param portproto: portnumber.lower() + / + protocol
        """
        # this key is used to store the ports the are known to be used
        #  by certain organizations
        return self.rcache.hget('organization_port', portproto.lower())

    def add_zeek_file(self, filename):
        """ Add an entry to the list of zeek files """
        self.r.sadd('zeekfiles', filename)

    def get_all_zeek_file(self):
        """ Return all entries from the list of zeek files """
        data = self.r.smembers('zeekfiles')
        return data


    def get_default_gateway(self):
        # if we have the gateway in our db , return it
        stored_gateway = self.r.get('default_gateway')

        if not stored_gateway:
            # we don't have it in our db, try to get it
            gateway = False
            if platform.system() == "Darwin":
                route_default_result = subprocess.check_output(["route", "get", "default"]).decode()
                try:
                    gateway = re.search(r"\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}", route_default_result).group(0)
                except AttributeError:
                    gateway = ''

            elif platform.system() == "Linux":
                route_default_result = re.findall(r"([\w.][\w.]*'?\w?)", subprocess.check_output(["ip", "route"]).decode())
                gateway = route_default_result[2]

        return gateway

    def get_ssl_info(self, sha1):
        info = self.rcache.hmget('IoC_SSL', sha1)[0]
        if info == None:
            return False
        return info

    def set_profile_module_label(self, profileid, module, label):
        """
        Set a module label for a profile.
        A module label is a label set by a module, and not
        a groundtruth label
        """
        data = self.get_profile_modules_labels(profileid)
        data[module] = label
        data = json.dumps(data)
        self.r.hset(profileid, 'modules_labels', data)

    def get_profile_modules_labels(self, profileid):
        """
        Get labels set by modules in the profile.
        """
        data = self.r.hget(profileid, 'modules_labels')
        if data:
            data = json.loads(data)
        else:
            data = {}
        return data

    def del_zeek_file(self, filename):
        """ Delete an entry from the list of zeek files """
        self.r.srem('zeekfiles', filename)

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
        :param ips_and_description: is {ip: json.dumps{'source':..,'tags':..,
                                                        'threat_level':... ,'description'}}

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

    def add_ip_to_IoC(self, ip: str, description: str) -> None:
        """
        Store in the DB 1 IP we read from an IoC source  with its description
        """
        self.rcache.hset('IoC_ips', ip, description)


    def add_domain_to_IoC(self, domain: str, description: str) -> None:
        """
        Store in the DB 1 domain we read from an IoC source
        with its description
        """
        self.rcache.hset('IoC_domains', domain, description)

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
        # Retrieve all profiles and twis, where this malicios IP was met.
        ip_profileid_twid = self.get_malicious_ip(ip)
        try:
            profile_tws = ip_profileid_twid[profileid]             # a dictionary {profile:set(tw1, tw2)}
            profile_tws = ast.literal_eval(profile_tws)            # set(tw1, tw2)
            profile_tws.add(twid)
            ip_profileid_twid[profileid] = str(profile_tws)
        except KeyError:
            ip_profileid_twid[profileid] = str({twid})                   # add key-pair to the dict if does not exist
        data = json.dumps(ip_profileid_twid)

        self.r.hset('MaliciousIPs', ip, data)

    def set_malicious_domain(self, domain, profileid, twid):
        """
        Save in DB a malicious domain found in the traffic
        with its profileid and twid
        """
        # get all profiles and twis where this IP was met
        domain_profiled_twid = __database__.get_malicious_domain(domain)
        try:
            profile_tws = domain_profiled_twid[profileid]               # a dictionary {profile:set(tw1, tw2)}
            profile_tws = ast.literal_eval(profile_tws)                 # set(tw1, tw2)
            profile_tws.add(twid)
            domain_profiled_twid[profileid] = str(profile_tws)
        except KeyError:
            domain_profiled_twid[profileid] = str({twid})               # add key-pair to the dict if does not exist
        data = json.dumps(domain_profiled_twid)

        self.r.hset('MaliciousDomains', domain, data)

    def get_malicious_ip(self, ip):
        """
        Return malicious IP and its list of presence in
        the traffic (profileid, twid)
        """
        data = self.r.hget('MaliciousIPs', ip)
        if data:
            data = json.loads(data)
        else:
            data = {}
        return data

    def get_malicious_domain(self, domain):
        """
        Return malicious domain and its list of presence in
        the traffic (profileid, twid)
        """
        data = self.r.hget('MaliciousDomains', domain)
        if data:
            data = json.loads(data)
        else:
            data = {}
        return data

    def set_dns_resolution(self, query: str, answers: list, ts: float, uid: str, qtype_name: str):
        """
        Cache DNS answers
        1- For each ip in the answer, store the domain
        stored in DNSresolution as {ip: {ts: .. , 'domains': .. , 'uid':... }}
        2- For each domain, store the ip
        stored in DomainsInfo
        """
        # don't store queries ending with arpa as dns resolutions, they're reverse dns
        if (qtype_name == 'AAAA' or qtype_name == 'A') and answers != '-' and not query.endswith('arpa'):
            # ATENTION: the IP can be also a domain, since the dns answer can be CNAME.

            # Also store these IPs inside the domain
            ips_to_add = []
            CNAMEs = []
            for answer in answers:
                # Make sure it's an ip not a CNAME
                if not validators.ipv6(answer) and not validators.ipv4(answer):
                    # now this is not an ip, it's a CNAME or a TXT
                    if 'TXT' in answer: continue
                    # it's a CNAME
                    CNAMEs.append(answer)
                    continue

                # get stored DNS resolution from our db
                domains = self.get_dns_resolution(answer)
                # if the domain(query) we have isn't already in DNSresolution in the db, add it
                if query not in domains:
                    domains.append(query)

                # domains should be a list, not a string!, so don't use json.dumps here
                ip_info = {'ts': ts , 'domains': domains, 'uid':uid }
                ip_info = json.dumps(ip_info)
                # we store ALL dns resolutions seen since starting slips in DNSresolution
                self.r.hset('DNSresolution', answer, ip_info)
                # these ips will be associated with the query in our db
                ips_to_add.append(answer)

            if ips_to_add:
                domaindata = {}
                domaindata['IPs'] = ips_to_add

                # if an ip came in the DNS answer along with the last seen CNAME
                try:
                    # store this CNAME in the db
                    domaindata['CNAME'] = CNAMEs
                except NameError:
                    # no CNAME came with this query
                    pass

                self.setInfoForDomains(query, domaindata, mode='add')



    def get_dns_resolution(self, ip, all_info=False):
        """
        Get DNS name of the IP, a list
        :param all_info: if provided returns a dict with {ts: .. , 'answers': .. , 'uid':... } of this IP
        if not returns answers only
        this function is called for every IP in the timeline of kalipso
        """
        ip_info = self.r.hget('DNSresolution', ip)
        if ip_info:
            ip_info = json.loads(ip_info)
            if all_info:
                # return a dict with 'ts' 'uid' 'answers' about this IP
                return ip_info
            # return answers only
            domains = ip_info['domains']

            return domains
        else:
            return []

    def get_all_dns_resolutions(self):
        dns_resolutions = self.r.hgetall('DNSresolution')
        if not dns_resolutions:
            return []
        else:
            return dns_resolutions

    def get_last_dns_ts(self):
        """ returns the timestamp of the last DNS resolution slips read """
        dns_resolutions = self.get_all_dns_resolutions()
        if dns_resolutions:
            # sort resolutions by ts
            # k_v is a tuple (key, value) , each value is a serialized json dict.
            sorted_dns_resolutions = sorted(dns_resolutions.items(), key=lambda k_v: json.loads(k_v[1])['ts'])
            # return the ts of the last dns resolution in our db
            last_dns_ts = json.loads(sorted_dns_resolutions[-1][1])['ts']
            return last_dns_ts

    def set_passive_dns(self, ip, data):
        """
        Save in DB passive DNS from virus total
        """
        if data:
            data = json.dumps(data)
            self.rcache.hset('passiveDNS', ip, data)

    def get_passive_dns(self, ip):
        """
        Get passive DNS from virus total
        """
        data = self.rcache.hget('passiveDNS', ip)
        if data:
            data = json.loads(data)
            return data
        else:
            return ''

    def get_IPs_in_IoC(self):
        """
        Get all IPs and their description from IoC_ips
        """
        data = self.rcache.hgetall('IoC_ips')
        return data

    def get_Domains_in_IoC(self):
        """
        Get all Domains and their description from IoC_domains
        """
        data = self.rcache.hgetall('IoC_domains')
        return data

    def get_ja3_in_IoC(self):
        """
        Get all ja3 and their description from IoC_JA3
        """
        data = self.rcache.hgetall('IoC_JA3')
        return data

    def search_IP_in_IoC(self, ip: str) -> str:
        """
        Search in the dB of malicious IPs and return a
        description if we found a match
        """
        ip_description = self.rcache.hget('IoC_ips', ip)
        if ip_description == None:
            return False
        else:
            return ip_description

    def getReconnectionsForTW(self, profileid, twid):
        """ Get the reconnections for this TW for this Profile """
        data = self.r.hget(profileid + self.separator + twid, 'Reconnections')
        if data:
            data = json.loads(data)
        else:
            data = {}
        return data

    def setReconnections(self,profileid, twid, data):
        """Set the reconnections for this TW for this Profile"""
        data = json.dumps(data)
        self.r.hset(profileid + self.separator + twid, 'Reconnections', str(data))

    def get_flow_timestamp(self, profileid, twid, uid):
        """
        Return the timestamp of the flow
        """
        timestamp = ''
        if uid:
            try:
                time.sleep(3) # it takes time for the binetflow to put the flow into the database
                flow_information = self.r.hget(profileid + "_" + twid + "_flows", uid)
                flow_information = json.loads(flow_information)
                timestamp = flow_information.get("ts")
            except:
                pass
        return timestamp

    def search_Domain_in_IoC(self, domain: str) -> tuple:
        """
        Search in the dB of malicious domains and return a
        description if we found a match
        returns a tuple (description, is_subdomain)
        description: description of the subdomain if found
        bool: True if we found a match for exactly the given domain False if we matched a subdomain
        """
        domain_description = self.rcache.hget('IoC_domains', domain)
        if domain_description == None:
            # try to match subdomain
            ioc_domains = self.rcache.hgetall('IoC_domains')
            for malicious_domain, description in ioc_domains.items():
                #  if the we contacted images.google.com and we have google.com in our blacklists, we find a match
                if malicious_domain in domain:
                    return description, True
            return False, False
        else:
            return domain_description, False

    def getDataFromProfileTW(self, profileid: str, twid: str, direction: str, state : str, protocol: str, role: str, type_data: str) -> dict:
        """
        Get the info about a certain role (Client or Server), for a particular protocol (TCP, UDP, ICMP, etc.) for a particular State (Established, etc.)
        direction: 'Dst' or 'Src'. This is used to know if you want the data of the src ip or ports, or the data from the dst ips or ports
        state: can be 'Established' or 'NotEstablished'
        protocol: can be 'TCP', 'UDP', 'ICMP' or 'IPV6ICMP'
        role: can be 'Client' or 'Server'
        type_data: can be 'Ports' or 'IPs'
        """
        try:
            self.print('Asked to get data from profile {}, {}, {}, {}, {}, {}, {}'.format(profileid, twid, direction, state, protocol, role, type_data), 3, 0)
            key = direction + type_data + role + protocol + state
            # self.print('Asked Key: {}'.format(key))
            data = self.r.hget(profileid + self.separator + twid, key)
            value = {}
            if data:
                self.print('Key: {}. Getting info for Profile {} TW {}. Data: {}'.format(key, profileid, twid, data), 3, 0)
                # Convert the dictionary to json
                portdata = json.loads(data)
                value = portdata
            elif not data:
                self.print('There is no data for Key: {}. Profile {} TW {}'.format(key, profileid, twid), 3, 0)
            return value
        except Exception as inst:
            exception_line = sys.exc_info()[2].tb_lineno
            self.outputqueue.put(f'01|database|[DB] Error in getDataFromProfileTW database.py line {exception_line}')
            self.outputqueue.put('01|database|[DB] Type inst: {}'.format(type(inst)))
            self.outputqueue.put('01|database|[DB] Inst: {}'.format(inst))

    def get_last_update_time_malicious_file(self):
        """ Return the time of last update of the remote malicious file from the db """
        return self.r.get('last_update_malicious_file')

    def set_last_update_time_malicious_file(self, time):
        """ Return the time of last update of the remote malicious file from the db """
        self.r.set('last_update_malicious_file', time)

    def get_host_ip(self):
        """ Get the IP addresses of the host from a db. There can be more than one"""
        return self.r.smembers('hostIP')

    def set_host_ip(self, ip):
        """ Store the IP address of the host in a db. There can be more than one"""
        self.r.sadd('hostIP', ip)

    def add_all_loaded_malicous_ips(self, ips_and_description: dict) -> None:
        self.r.hmset('loaded_malicious_ips', ips_and_description)

    def add_loaded_malicious_ip(self, ip: str, description: str) -> None:
        self.r.hset('loaded_malicious_ips', ip, description)

    def get_loaded_malicious_ip(self, ip: str) -> str:
        ip_description = self.r.hget('loaded_malicious_ips', ip)
        return ip_description

    def set_profile_as_malicious(self, profileid: str, description: str) -> None:
        # Add description to this malicious ip profile.
        self.r.hset(profileid, 'labeled_as_malicious', description)

    def is_profile_malicious(self, profileid: str) -> str:
        data = self.r.hget(profileid, 'labeled_as_malicious')
        return data

    def set_TI_file_info(self, file, data):
        '''
        Set/update time and/or e-tag for TI file
        '''
        # data = self.get_malicious_file_info(file)
        # for key in file_data:
        # data[key] = file_data[key]
        data = json.dumps(data)
        self.rcache.hset('TI_files_info', file, data)

    def get_TI_file_info(self, file):
        '''
        Get TI file info
        '''
        data = self.rcache.hget('TI_files_info', file)
        if data:
            data = json.loads(data)
        else:
            data = {}
        return data




    def set_asn_cache(self, asn, asn_range) -> None:
        """
        Stores the range of asn in cached_asn hash
        :param asn: str
        :param asn_range: str
        """
        self.rcache.hset('cached_asn', asn, asn_range)

    def get_asn_cache(self):
        """
        Returns cached asn of ip if present, or False.
        """
        return self.rcache.hgetall('cached_asn')

    def store_process_PID(self, process, pid):
        """
        Stores each started process or module with it's PID
        :param pid: int
        :param process: str
        """
        self.r.hset('PIDs', process, pid)

    def get_PIDs(self):
        """ returns a dict with module names as keys and pids as values """
        return self.r.hgetall('PIDs')

    def set_whitelist(self,type, whitelist_dict):
        """
        Store the whitelist_dict in the given key
        :param type: supporte types are IPs, domains and organizations
        :param whitelist_dict: the dict of IPs, domains or orgs to store
        """
        self.r.hset("whitelist" , type, json.dumps(whitelist_dict))

    def get_all_whitelist(self):
        """ Return dict of 3 keys: IPs, domains, organizations or mac"""
        return self.r.hgetall('whitelist')

    def get_whitelist(self, key):
        """
        Whitelist supports different keys like : IPs domains and organizations
        this function is used to check if we have any of the above keys whitelisted
        """
        whitelist = self.r.hget('whitelist',key)
        if whitelist:
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
        backup_file should be the path+name of the file you want to store the db in
        If you -s the same file twice the old backup will be overwritten.
        """

        # print statements in this function won't work becaus eby the time this
        # function is executed, the redis database would have already stopped

        # Saves to /var/lib/redis/dump.rdb
        # this path is only accessible by root
        self.r.save()
        # if you're not root, this will return False even if the path exists
        if os.path.exists('/var/lib/redis/dump.rdb'):
            command = self.sudo + 'cp /var/lib/redis/dump.rdb ' + backup_file + '.rdb'
            os.system(command)
            self.print("Backup stored in {}.rdb".format(backup_file))
        else:
            self.print("Error Saving: Cannot find redis backup directory")

    def load(self,backup_file: str) -> bool:
        """
        Load the db from disk
        backup_file should be the full path of the .rdb
        """
        # Set sudo according to environment
        # Locate the default path of redis dump.rdb
        command = self.sudo + 'cat /etc/redis/*.conf | grep -w "dir"'
        redis_dir = subprocess.getoutput(command)
        if 'dir /var/lib/redis' in redis_dir:
            redis_dir = '/var/lib/redis'
        else:
            # Get the exact path without spaces
            redis_dir = redis_dir[redis_dir.index(' ')+1:]
        if os.path.exists(backup_file):
            # Check if valid .rdb file
            command = 'file ' + backup_file
            result = subprocess.run(command.split(), stdout=subprocess.PIPE)
            # Get command output
            file_type = result.stdout.decode('utf-8')
            # Check if valid redis database
            if 'Redis' in file_type:
                # All modules throw redis.exceptions.ConnectionError when we stop the redis-server so we need to close all channels first
                # We won't need them since we're loading a db that's already been analyzed
                self.publish_stop()
                # Stop the server first in order for redis to load another db
                os.system(self.sudo +'service redis-server stop')
                # todo: find/generate dump.rdb in docker.
                # Copy out saved db to the dump.rdb (the db redis uses by default)
                command = self.sudo +'cp ' + backup_file + ' ' + redis_dir +'/dump.rdb'
                os.system(command)
                # Start the server again
                os.system(self.sudo + 'service redis-server start')
                self.print("{} loaded successfully. Run ./kalipso.sh".format(backup_file))
                return True
            else:
                self.print("{} is not a valid redis database file.".format(backup_file))
                return False
        else:
            self.print("{} doesn't exist.".format(backup_file))
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
        self.r.hset('Warden','poll',time)


    def get_last_warden_poll_time(self):
        """
        returns epoch time of last poll
        """
        time = self.r.hget('Warden','poll')
        if time:
            time = float(time)
        else:
            time = float('-inf')
        return time


    def start_profiling(self):
        print("-"*30+ " Started profiling")
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
        print("-"*30+ " Done profiling")

__database__ = Database()
