import redis
import time
import json
from typing import Tuple, Dict, Set, Callable
import configparser
import traceback
from datetime import datetime


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

    def start(self, config):
        """ Start the DB. Allow it to read the conf """
        self.config = config

        # Read values from the configuration file
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

        # Create the connection to redis
        if not hasattr(self, 'r'):
            try:
                self.r = redis.StrictRedis(host='localhost', port=6379, db=0, charset="utf-8", decode_responses=True) #password='password')
                self.rcache = redis.StrictRedis(host='localhost', port=6379, db=1, charset="utf-8", decode_responses=True) #password='password')
                if self.deletePrevdb:
                    print('Deleting the previous stored DB in Redis.')
                    self.r.flushdb()
            except redis.exceptions.ConnectionError:
                print('[DB] Error in database.py: Is redis database running? You can run it as: "redis-server --daemonize yes"')
        # Even if the DB is not deleted. We need to delete some temp data
        # Zeek_files
        self.r.delete('zeekfiles')

        # By default the slips internal time is 0 until we receive something
        self.r.set('slips_internal_time', 0)

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

                # The IP of the profile should also be checked in case is malicious, but we only have the profileid, not the tw.
                self.publish('give_threat_intelligence', str(ip) + '-' + str(profileid) + '-None')

        except redis.exceptions.ResponseError as inst:
            self.outputqueue.put('00|database|Error in addProfile in database.py')
            self.outputqueue.put('00|database|{}'.format(type(inst)))
            self.outputqueue.put('00|database|{}'.format(inst))

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
        Returns a list with data or an empty list
        """
        data = self.r.zrange('tws' + profileid, 0, -1, withscores=True)
        return data

    def getamountTWsfromProfile(self, profileid):
        """
        Receives a profile id and returns the list of all the TW in that profile

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
            self.outputqueue.put('01|database|[DB] Error in getT2ForProfileTW in database.py')
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

    def getTWforScore(self, profileid, time):
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
        """ Return all the list of modified tw since a certain time"""
        data = self.r.zrangebyscore('ModifiedTW', time, float('+inf'), withscores=True)
        if not data:
            return []
        return data

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
        data = self.r.zrange('ModifiedTW', 0, -1, withscores=True)
        if not data:
            data = -1
        return data

    def getSlipsInternalTime(self):
        return self.r.get('slips_internal_time')

    def markProfileTWAsClosed(self, profileid):
        """
        Mark the TW as closed so tools can work on its data
        """
        self.r.sadd('ClosedTW', profileid)
        self.publish('tw_closed', profileid)

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

        # If we dont receive a timestmp, do not update the timestamp
        if timestamp and type(timestamp) is not float:
            # We received a datetime object, get the epoch time
            # Update the slips internal time (sit)
            self.r.set('slips_internal_time', timestamp.timestamp())
            # Store the modifed TW with the time
            data = {}
            data[profileid + self.separator + twid] = float(timestamp.timestamp())
            self.r.zadd('ModifiedTW', data)
        elif timestamp and type(timestamp) is float:
            # We recevied an epoch time
            # Update the slips internal time (sit)
            self.r.set('slips_internal_time', timestamp)
            # Store the modifed TW with the time
            data = {}
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
        sit = self.r.get('slips_internal_time')
        # for each modified profile
        modification_time = float(sit) - self.width
        # To test the time
        modification_time = float(sit) - 20
        profiles_to_close = self.r.zrangebyscore('ModifiedTW', 0, modification_time, withscores=True)
        for profile_to_close in profiles_to_close:
            profile_to_close_id = profile_to_close[0]
            profile_to_close_time = profile_to_close[1]
            self.print(f'The profile id {profile_to_close_id} has to be closed because it was last modifed on {profile_to_close_time} and we are closing everything older than {modification_time}. Current time {sit}. Difference: {modification_time - profile_to_close_time}', 7, 0)
            self.markProfileTWAsClosed(profile_to_close_id)

    def add_ips(self, profileid, twid, ip_as_obj, columns, role: str):
        """
        Function to add information about the an IP address
        The flow can go out of the IP (we are acting as Client) or into the IP
        (we are acting as Server)
        ip_as_obj: IP to add. It can be a dstIP or srcIP depending on the rol
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
            # It doesn't matter if we are client or server, since the ip_as_obj changes accordingly from being the dstip for client to being the srcip for server. 
            # Therefore both ips will be checked for each flow
            self.publish('give_threat_intelligence', str(ip_as_obj) + '-' + str(profileid) + '-' + str(twid))

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
            self.print('add_ips(): As a {}, add the {} IP {} to profile {}, twid {}'.format(role, type_host_key, str(ip_as_obj), profileid, twid), 0, 5)
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
                self.print('add_ips(): Not the first time for this addr. Add 1 to {}'.format(str(ip_as_obj)), 0, 5)
                data[str(ip_as_obj)] += 1
                # Convet the dictionary to json
                data = json.dumps(data)
            except (TypeError, KeyError) as e:
                # There was no previous data stored in the DB
                self.print('add_ips(): First time for addr {}. Count as 1'.format(str(ip_as_obj)), 0, 5)
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
                self.print('add_ips(): Adding for dst port {}. PRE Data: {}'.format(dport, innerdata), 0, 3)
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
                self.print('add_ips() Adding for dst port {}. POST Data: {}'.format(dport, innerdata), 0, 3)
            except KeyError:
                # First time for this flow
                innerdata = {}
                innerdata['totalflows'] = 1
                innerdata['totalpkt'] = int(pkts)
                innerdata['totalbytes'] = int(totbytes)
                temp_dstports = {}
                temp_dstports[str(dport)] = int(pkts)
                innerdata['dstports'] = temp_dstports
                self.print('add_ips() First time for dst port {}. Data: {}'.format(dport, innerdata), 0, 3)
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
        except Exception as inst:
            self.outputqueue.put('01|database|[DB] Error in add_ips in database.py')
            self.outputqueue.put('01|database|[DB] Type inst: {}'.format(type(inst)))
            self.outputqueue.put('01|database|[DB] Inst: {}'.format(inst))

    def refresh_data_tuples(self):
        """
        Go through all the tuples and refresh the data about the ipsinfo
        TODO
        """
        outtuples = self.getOutTuplesfromProfileTW()
        intuples = self.getInTuplesfromProfileTW()

    def add_tuple(self, profileid, twid, tupleid, data_tuple, role, starttime):
        """
        Add the tuple going in or out for this profile
        role: 'Client' or 'Server'
        """
        # If the traffic is going out it is part of our outtuples, if not, part of our intuples
        if role == 'Client':
            tuple_key = 'OutTuples'
        elif role == 'Server':
            tuple_key = 'InTuples'
        try:
            self.print('Add_tuple called with profileid {}, twid {}, tupleid {}, data {}'.format(profileid, twid, tupleid, data_tuple), 0, 5)
            # Get all the InTuples or OutTuples for this profileid in this TW
            hash_id = profileid + self.separator + twid
            data = self.r.hget(hash_id, tuple_key)
            # Separate the symbold to add and the previous data
            (symbol_to_add, previous_two_timestamps) = data_tuple
            if not data:
                # Must be str so we can convert later
                data = '{}'
            # Convert the json str to a dictionary
            data = json.loads(data)
            try:
                stored_tuple = data[tupleid]
                # Disasemble the input
                self.print('Not the first time for tuple {} as an {} for {} in TW {}. Add the symbol: {}. Store previous_times: {}. Prev Data: {}'.format(tupleid, tuple_key, profileid, twid, symbol_to_add, previous_two_timestamps, data), 0, 5)
                # Get the last symbols of letters in the DB
                prev_symbols = data[tupleid][0]
                # Add it to form the string of letters
                new_symbol = prev_symbols + symbol_to_add
                # Bundle the data together
                new_data = (new_symbol, previous_two_timestamps)
                # analyze behavioral model with lstm model if the length is divided by 3 - so we send when there is 3 more characters added
                if len(new_symbol) % 3 == 0:
                    self.publish('new_letters', new_symbol + '-' + profileid + '-' + twid + '-' + str(tupleid))

                data[tupleid] = new_data
                self.print('\tLetters so far for tuple {}: {}'.format(tupleid, new_symbol), 0, 6)
                data = json.dumps(data)
            except (TypeError, KeyError) as e:
                # TODO check that this condition is triggered correctly only for the first case and not the rest after...
                # There was no previous data stored in the DB
                self.print('First time for tuple {} as an {} for {} in TW {}'.format(tupleid, tuple_key, profileid, twid), 0, 5)
                # Here get the info from the ipinfo key
                new_data = (symbol_to_add, previous_two_timestamps)
                data[tupleid] = new_data
                # Convet the dictionary to json
                data = json.dumps(data)
            # Store the new data on the db
            self.r.hset(hash_id, tuple_key, str(data))
            # Mark the tw as modified
            self.markProfileTWAsModified(profileid, twid, starttime)
        except Exception as inst:
            self.outputqueue.put('01|database|[DB] Error in add_tuple in database.py')
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
            starttime = columns['starttime']

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
                    temp_dstips[str(ip_address)] += int(pkts)
                except KeyError:
                    temp_dstips[str(ip_address)] = int(pkts)
                innerdata[ip_key] = temp_dstips
                prev_data[port] = innerdata
                self.print('add_port(): Adding this new info about port {} for {}. Key: {}. NewData: {}'.format(port, profileid, key_name, innerdata), 0, 3)
            except KeyError:
                # First time for this flow
                innerdata = {}
                innerdata['totalflows'] = 1
                innerdata['totalpkt'] = int(pkts)
                innerdata['totalbytes'] = int(totbytes)
                temp_dstips = {}
                temp_dstips[str(ip_address)] = int(pkts)
                innerdata[ip_key] = temp_dstips
                prev_data[port] = innerdata
                self.print('add_port(): First time for port {} for {}. Key: {}. Data: {}'.format(port, profileid, key_name, innerdata), 0, 3)
            # self.outputqueue.put('01|database|[DB] {} '.format(ip_address))

            # Convet the dictionary to json
            data = json.dumps(prev_data)
            self.print('add_port(): Storing info about port {} for {}. Key: {}. Data: {}'.format(port, profileid, key_name, prev_data), 0, 3)
            # Store this data in the profile hash
            hash_key = profileid + self.separator + twid
            self.r.hset(hash_key, key_name, str(data))
            # Mark the tw as modified
            self.markProfileTWAsModified(profileid, twid, starttime)
        except Exception as inst:
            self.outputqueue.put('01|database|[DB] Error in add_port in database.py')
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
            self.outputqueue.put('01|database|[DB] Error in getDataFromProfileTW in database.py')
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
            self.outputqueue.put('01|database|[DB] Error in getFinalStateFromFlags() in database.py')
            self.outputqueue.put('01|database|[DB] Type inst: {}'.format(type(inst)))
            self.outputqueue.put('01|database|[DB] Inst: {}'.format(inst))
            self.print(traceback.format_exc())

    def getFieldSeparator(self):
        """ Return the field separator """
        return self.separator

    def setEvidence(self, key, threat_level, confidence, description, profileid='', twid='',):
        """ 
        Get the evidence for this TW for this Profile 

        Input:
        - key: This is how your evidences are grouped. E.g. if you are detecting horizontal port scans, then this would be the port used. 
               the idea is that you can later update this specific detection when it evolves. 
               Examples of keys are: 'dport:1234' for all the evidences regarding this dport, or 'dip:1.1.1.1' for all the evidences regarding that dst ip
        - type_evidence: The type of evidence you can send. For example PortScanType1
        - threat_level: How important this evidence is. Portscan? C&C channel? Exploit?
        - confidence: How sure you are that this is what you say it is. Basically: the more data the more sure you are.
        
        The evidence is stored as a dict.
        {
            'dport:32432:PortScanType1': [confidence, threat_level, 'Super complicated portscan on port 32432'], 
            'dip:10.0.0.1:PortScanType2': [confidence, threat_level, 'Horizontal port scan on ip 10.0.0.1'] 
            'dport:454:Attack3': [confidence, threat_level, 'Buffer Overflow'] 
        }

        Adapt to set the evidence of ips without profile and tw

        """
        # See if we have and get the current evidence stored in the DB fot this profileid in this twid
        current_evidence = self.getEvidenceForTW(profileid, twid)
        if current_evidence:
            current_evidence = json.loads(current_evidence)
        else:
            # We never had any evidence for nothing
            current_evidence = {}
        # We dont care if there is previous evidence or not in this key. We just change add all the values.
        data = []
        data.append(confidence)
        data.append(threat_level)
        data.append(description)
        current_evidence[key] = data

        current_evidence_json = json.dumps(current_evidence)
        self.r.hset(profileid + self.separator + twid, 'Evidence', str(current_evidence_json))
        # Tell everyone an evidence was added
        self.publish('evidence_added', profileid + ':' + twid)

    def getEvidenceForTW(self, profileid, twid):
        """ Get the evidence for this TW for this Profile """
        data = self.r.hget(profileid + self.separator + twid, 'Evidence')
        return data

    def setBlockingRequest(self, profileid, twid):
        """ Set the request to block this profile. found in this time window """
        # Store the blockrequest in the TW itself
        self.r.hset(profileid + self.separator + twid, 'BlockRequest', 'True')
        # Add this profile and tw to the list of blocked
        self.markProfileTWAsBlocked(profileid, twid)

    def getBlockingRequest(self, profileid, twid):
        """ Get the request to block this profile. found in this time window """
        data = self.r.hget(profileid + self.separator + twid, 'BlockRequest')
        return data

    def markProfileTWAsBlocked(self, profileid, twid):
        """ Add this profile and tw to the list of blocked """
        self.r.sadd('BlockedProfTW', profileid + self.separator + twid)

    def getBlockedTW(self):
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
        data = self.r.hget('DomainsInfo', domain)
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

    def getIPData(self, ip):
        """
        Return information about this IP
        Returns a dictionary or False if there is no IP in the database
        We need to separate these three cases:
        1- IP is in the DB without data. Return empty dict.
        2- IP is in the DB with data. Return dict.
        3- IP is not in the DB. Return False
        """
        data = self.rcache.hget('IPsInfo', ip)
        if data or data == {}:
            # This means the IP was in the database, with or without data
            # Case 1 and 2
            # Convert the data
            data = json.loads(data)
            # print(f'In the DB: IP {ip}, and data {data}')
        else:
            # The IP was not in the DB
            # Case 3
            data = False
            # print(f'In the DB: IP {ip}, and data {data}')
        return data

    def getallIPs(self):
        """ Return list of all IPs in the DB """
        data = self.rcache.hgetall('IPsInfo')
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
            # Set this domain for the first time in the IPsInfo
            # Its VERY important that the data of the first time we see a domain
            # must be '{}', an empty dictionary! if not the logic breaks.
            # We use the empty dictionary to find if a domain exists or not
            self.r.hset('DomainsInfo', domain, '{}')
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

    def getIP(self, ip):
        """ Check if this ip is the hash of the profiles! """
        data = self.rcache.hget('IPsInfo', ip)
        if data:
            return True
        else:
            return False

    def setInfoForDomains(self, domain: str, domaindata: dict):
        """
        Store information for this domain
        We receive a dictionary, such as {'geocountry': 'rumania'} that we are
        going to store for this domain
        If it was not there before we store it. If it was there before, we
        overwrite it
        """
        # Get the previous info already stored
        data = self.getDomainData(domain)

        if not data:
            # This domain is not in the dictionary, add it first:
            self.setNewDomain(domain)
            # Now get the data, which should be empty, but just in case
            data = self.getDomainData(domain)

        for key in iter(domaindata):
            # domaindata can be {'VirusTotal': [1,2,3,4], 'Malicious': ""}
            # domaindata can be {'VirusTotal': [1,2,3,4]}
            # I think we dont need this anymore of the conversion
            if type(data) == str:
                # Convert the str to a dict
                data = json.loads(data)

            data_to_store = domaindata[key]

            # If there is data previously stored, check if we have
            # this key already
            try:
                # If the key is already stored, do not modify it
                # Check if this decision is ok! or we should modify
                # the data
                _ = data[key]
            except KeyError:
                # There is no data for they key so far. Add it
                data[key] = data_to_store
                newdata_str = json.dumps(data)
                self.r.hset('DomainsInfo', domain, newdata_str)
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
        if not data:
            # This IP is not in the dictionary, add it first:
            self.setNewIP(ip)
            # Now get the data, which should be empty, but just in case
            data = self.getIPData(ip)
            # I think we dont need this anymore of the conversion
            if type(data) == str:
                # Convert the str to a dict
                data = json.loads(data)
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

    def subscribe(self, channel):
        """ Subscribe to channel """
        # For when a TW is modified
        pubsub = self.r.pubsub()
        if 'tw_modified' in channel:
            pubsub.subscribe(channel)
        elif 'evidence_added' in channel:
            pubsub.subscribe(channel)
        elif 'new_ip' in channel:
            pubsub.subscribe(channel)
        elif 'new_flow' in channel:
            pubsub.subscribe(channel)
        elif 'new_dns' in channel:
            pubsub.subscribe(channel)
        elif 'new_http' in channel:
            pubsub.subscribe(channel)
        elif 'new_ssl' in channel:
            pubsub.subscribe(channel)
        elif 'new_profile' in channel:
            pubsub.subscribe(channel)
        elif 'give_threat_intelligence' in channel:
            pubsub.subscribe(channel)
        elif 'new_letters' in channel:
            pubsub.subscribe(channel)
        elif 'ip_info_change' in channel:
            pubsub.subscribe(channel)
        elif 'dns_info_change' in channel:
            pubsub.subscribe(channel)
        elif 'tw_closed' in channel:
            pubsub.subscribe(channel)
        elif 'core_messages' in channel:
            pubsub.subscribe(channel)
        return pubsub

    def publish(self, channel, data):
        """ Publish something """
        self.r.publish(channel, data)

    def publish_stop(self):
        """ Publish stop command to terminate slips """
        all_channels_list = self.r.pubsub_channels()
        self.print('Sending the stop signal to all listeners', 3, 3)
        for channel in all_channels_list:
            self.r.publish(channel, 'stop_process')

    def get_all_flows_in_profileid_twid(self, profileid, twid):
        """
        Return a list of all the flows in this profileid and twid
        """
        data = self.r.hgetall(profileid + self.separator + twid + self.separator + 'flows')
        if data:
            return data

    def get_all_flows(self):
        """
        Returns a list with all the flows in all profileids and twids
        Each position in the list is a dictionary of flows.
        """
        data = []
        for profileid in self.getProfiles():
            for (twid, time) in self.getTWsfromProfile(profileid):
                temp = self.get_all_flows_in_profileid_twid(profileid, twid)
                if temp:
                    data.append(temp)
        return data

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
        """ Return the amount of each label so far """
        return self.r.zrange('labels', 0, -1, withscores=True)

    def add_flow(self, profileid='', twid='', stime='', dur='', saddr='', sport='', daddr='', dport='', proto='', state='', pkts='', allbytes='', spkts='', sbytes='', appproto='', uid='', label=''):
        """
        Function to add a flow by interpreting the data. The flow is added to the correct TW for this profile.
        The profileid is the main profile that this flow is related too.

        """
        data = {}
        # data['uid'] = uid
        data['ts'] = stime
        data['dur'] = dur
        data['saddr'] = saddr
        data['sport'] = sport
        data['daddr'] = daddr
        data['dport'] = dport
        data['proto'] = proto
        # Store the interpreted state, not the raw one
        summaryState = __database__.getFinalStateFromFlags(state, pkts)
        data['origstate'] = state
        data['state'] = summaryState
        data['pkts'] = pkts
        data['allbytes'] = allbytes
        data['spkts'] = spkts
        data['sbytes'] = sbytes
        data['appproto'] = appproto
        data['label'] = label

        # Convert to json string
        data = json.dumps(data)
        # Store in the hash 10.0.0.1_timewindow1, a key uid, with data
        value = self.r.hset(profileid + self.separator + twid + self.separator + 'flows', uid, data)
        if value:
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
            self.print('Adding complete flow to DB: {}'.format(data), 5, 0)

    def add_out_ssl(self, profileid, twid, flowtype, uid, version, cipher, resumed, established, cert_chain_fuids, client_cert_chain_fuids, subject, issuer, validation_status, curve, server_name):
        """
        Store in the DB an ssl request
        All the type of flows that are not netflows are stored in a separate hash ordered by uid.
        The idea is that from the uid of a netflow, you can access which other type of info is related to that uid
        """
        data = {}
        data['uid'] = uid
        data['type'] = flowtype
        data['version'] = version
        data['cipher'] = cipher
        data['resumed'] = resumed
        data['established'] = established
        data['cert_chain_fuids'] = cert_chain_fuids
        data['client_cert_chain_fuids'] = client_cert_chain_fuids
        data['subject'] = subject
        data['issuer'] = issuer
        data['validation_status'] = validation_status
        data['curve'] = curve
        data['server_name'] = server_name

        # Convert to json string
        data = json.dumps(data)
        self.r.hset(profileid + self.separator + twid + self.separator + 'altflows', uid, data)
        to_send = {}
        to_send['profileid'] = profileid
        to_send['twid'] = twid
        to_send['flow'] = data
        to_send = json.dumps(to_send)
        self.publish('new_ssl', to_send)
        self.print('Adding SSL flow to DB: {}'.format(data), 5,0)

    def add_out_http(self, profileid, twid, flowtype, uid, method, host, uri, version, user_agent, request_body_len, response_body_len, status_code, status_msg, resp_mime_types, resp_fuids):
        """
        Store in the DB a http request
        All the type of flows that are not netflows are stored in a separate hash ordered by uid.
        The idea is that from the uid of a netflow, you can access which other type of info is related to that uid
        """
        data = {}
        data['uid'] = uid
        data['type'] = flowtype
        data['method'] = method
        data['host'] = host
        data['uri'] = uri
        data['version'] = version
        data['user_agent'] = user_agent
        data['request_body_len'] = request_body_len
        data['response_body_len'] = response_body_len
        data['status_code'] = status_code
        data['status_msg'] = status_msg
        data['resp_mime_types'] = resp_mime_types
        data['resp_fuids'] = resp_fuids
        # Convert to json string
        data = json.dumps(data)
        self.r.hset(profileid + self.separator + twid + self.separator + 'altflows', uid, data)
        to_send = {}
        to_send['profileid'] = profileid
        to_send['twid'] = twid
        to_send['flow'] = data
        to_send = json.dumps(to_send)
        self.publish('new_http', to_send)
        self.print('Adding HTTP flow to DB: {}'.format(data), 5,0)

    def add_out_dns(self, profileid, twid, flowtype, uid, query, qclass_name, qtype_name, rcode_name, answers, ttls):
        """
        Store in the DB a DNS request

        All the type of flows that are not netflows are stored in a separate hash ordered by uid.
        The idea is that from the uid of a netflow, you can access which other type of info is related to that uid
        """
        data = {}
        data['uid'] = uid
        data['type'] = flowtype
        data['query'] = query
        data['qclass_name'] = qclass_name
        data['qtype_name'] = qtype_name
        data['rcode_name'] = rcode_name
        data['answers'] = answers
        data['ttls'] = ttls
        # Convert to json string
        data = json.dumps(data)
        
        # Set the dns as alternative flow
        self.r.hset(profileid + self.separator + twid + self.separator + 'altflows', uid, data)

        # Publish the new dns received
        to_send = {}
        to_send['profileid'] = profileid
        to_send['twid'] = twid
        to_send['flow'] = data
        to_send = json.dumps(to_send)
        self.publish('new_dns', to_send)
        self.print('Adding DNS flow to DB: {}'.format(data), 5,0)

        # Check if the dns is detected by the threat intelligence
        self.publish('give_threat_intelligence', str(query) + '-' + str(profileid) + '-' + str(twid))

    def get_altflow_from_uid(self, profileid, twid, uid):
        """ Given a uid, get the alternative flow realted to it """
        return self.r.hget(profileid + self.separator + twid + self.separator + 'altflows', uid)

    def add_timeline_line(self, profileid, twid, data, timestamp):
        """ Add a line to the time line of this profileid and twid """
        self.print('Adding timeline for {}, {}: {}'.format(profileid, twid, data), 4, 0)
        key = str(profileid + self.separator + twid + self.separator + 'timeline')
        data = json.dumps(data)
        mapping = {}
        mapping[data] = timestamp
        self.r.zadd(key, mapping)
        # Mark the tw as modified since the timeline line is new data in the TW
        self.markProfileTWAsModified(profileid, twid, timestamp='')

    def add_http_timeline_line(self, profileid, twid, data, timestamp):
        """ Add a http line to the time line of this profileid and twid """
        self.print('Adding timeline for {}, {}: {}'.format(profileid, twid, data), 4, 0)
        key = str(profileid + self.separator + twid + self.separator + 'timeline')
        data = json.dumps(data)
        mapping={}
        mapping[data] = timestamp
        self.r.zadd(key,mapping)
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

    def set_port_info(self, portproto, name):
        """ Save in the DB a port with its description """
        self.r.hset('portinfo', portproto, name)

    def get_port_info(self, portproto):
        """ Retrive the name of a port """
        return self.r.hget('portinfo', portproto)

    def add_zeek_file(self, filename):
        """ Add an entry to the list of zeek files """
        self.r.sadd('zeekfiles', filename)

    def get_all_zeek_file(self):
        """ Return all entries from the list of zeek files """
        data = self.r.smembers('zeekfiles')
        return data

    def del_zeek_file(self, filename):
        """ Delete an entry from the list of zeek files """
        self.r.srem('zeekfiles', filename)

    def delete_ips_from_IoC_ips(self, ips):
        """
        Delete old IPs from IoC
        """
        self.rcache.hdel('IoC_ips', *ips)

    def delete_domains_from_IoC_ips(self, domains):
        """
        Delete old domains from IoC
        """
        self.rcache.hdel('IoC_domains', *domains)

    def add_ips_to_IoC(self, ips_and_description: dict) -> None:
        """
        Store a group of IPs in the db as they were obtained from an IoC source
        What is the format of ips_and_description?
        """
        if ips_and_description:
            self.rcache.hmset('IoC_ips', ips_and_description)

    def add_domains_to_IoC(self, domains_and_description: dict) -> None:
        """
        Store a group of domains in the db as they were obtained from
        an IoC source
        What is the format of domains_and_description?
        """
        if domains_and_description:
            self.rcache.hmset('IoC_domains', domains_and_description)

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

    def add_malicious_ip(self, ip, profileid_twid):
        """
        Save in DB malicious IP found in the traffic
        with its profileid and twid
        """
        self.r.hset('MaliciousIPs', ip, profileid_twid)

    def add_malicious_domain(self, domain, profileid_twid):
        """
        Save in DB a malicious domain found in the traffic
        with its profileid and twid
        """
        self.r.hset('MaliciousDomains', domain, profileid_twid)

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

    def add_dns_resolution(self, query, answers):
        """
        Save in DB DNS name for each IP
        """
        for ans in answers:
            self.r.hset('DNSresolution', ans, query)

    def get_dns_resolution(self, ip):
        """
        Get DNS name of the IP
        """
        data = self.r.hget('DNSresolution', ip)
        return data

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

    def search_Domain_in_IoC(self, domain: str) -> str:
        """
        Search in the dB of malicious domainss and return a
        description if we found a match
        """
        domain_description = self.rcache.hget('IoC_domains', domain)
        if domain_description == None:
            return False
        else:
            return domain_description

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
            self.print('Asked to get data from profile {}, {}, {}, {}, {}, {}, {}'.format(profileid, twid, direction, state, protocol, role, type_data), 0, 4)
            key = direction + type_data + role + protocol + state
            # self.print('Asked Key: {}'.format(key))
            data = self.r.hget(profileid + self.separator + twid, key)
            value = {}
            if data:
                self.print('Key: {}. Getting info for Profile {} TW {}. Data: {}'.format(key, profileid, twid, data), 5, 0)
                # Convert the dictionary to json
                portdata = json.loads(data)
                value = portdata
            elif not data:
                self.print('There is no data for Key: {}. Profile {} TW {}'.format(key, profileid, twid), 5, 0)
            return value
        except Exception as inst:
            self.outputqueue.put('01|database|[DB] Error in getDataFromProfileTW database.py')
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

    def set_malicious_file_info(self, file, data):
        '''
        Set/update time and/or e-tag for malicious file
        '''
        # data = self.get_malicious_file_info(file)
        # for key in file_data:
        #     data[key] = file_data[key]
        data = json.dumps(data)
        self.rcache.hset('malicious_files_info', file, data)

    def get_malicious_file_info(self, file):
        '''
        Get malicious file info
        '''
        data = self.rcache.hget('malicious_files_info', file)
        if data:
            data = json.loads(data)
        else:
            data = ''
        return data


__database__ = Database()
