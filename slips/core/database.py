import redis
import time
import json
import sys
from typing import Tuple, Dict, Set, Callable
import configparser
import traceback



def timing(f):
    """ Function to measure the time another function takes."""
    def wrap(*args):
        time1 = time.time()
        ret = f(*args)
        time2 = time.time()
        self.outputqueue.put('01|database|Function took {:.3f} ms'.format((time2-time1)*1000.0))
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
        try:
            deletePrevdbText = self.config.get('parameters', 'deletePrevdb')
            if deletePrevdbText == 'True':
                self.deletePrevdb = True
            elif deletePrevdbText == 'False':
                self.deletePrevdb = False
        except (configparser.NoOptionError, configparser.NoSectionError, NameError, ValueError, KeyError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.deletePrevdb = True
        # Create the connection to redis
        if not hasattr(self, 'r'):
            self.r = redis.StrictRedis(host='localhost', port=6379, db=0, charset="utf-8", decode_responses=True) #password='password')
            if self.deletePrevdb:
                print('Deleting the previous stored DB in Redis.')
                self.r.flushdb()
        # Even if the DB is not deleted. We need to delete some temp data
        # Zeek_files
        self.r.delete('zeekfiles')

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
                self.r.hset(profileid, 'Starttime', starttime)
                # For now duration of the TW is fixed
                self.r.hset(profileid, 'duration', duration)
                # The IP of the profile should also be added as a new IP we know about.
                ip = profileid.split(self.separator)[1]
                # If the ip is new add it to the list of ips
                self.setNewIP(ip)

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
        The score in the DB is the start of the timewindow, so we should search a TW that includes 
        the given time by making sure the start of the TW is < time, and the end of the TW is > time.
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
        return self.r.zcard('tws'+profileid)

    def getModifiedTWLogs(self):
        """ Return all the list of modified tw """
        return self.r.smembers('ModifiedTWForLogs')

    def wasProfileTWModifiedLogs(self, profileid, twid):
        """ Retrieve from the db if this TW of this profile was modified """
        data = self.r.sismember('ModifiedTWForLogs', profileid + self.separator + twid)
        if not data:
            # If for some reason we don't have the modified bit set, then it was not modified.
            data = 0
        return bool(data)

    def markProfileTWAsNotModifiedLogs(self, profileid, twid):
        """ 
        Mark a TW in a profile as not modified after the log file is outputed
        """
        self.r.srem('ModifiedTWForLogs', profileid + self.separator + twid)

    def markProfileTWAsModified(self, profileid, twid):
        """ 
        Mark a TW in a profile as not modified 
        (As a side effect, it can create it if its not there (What does this meas?))

        The TW are marked for different processes because some of them 'wake up' 
        every X amount of time and need to check what was modified from their
        points of view. This is why we are putting mark for different modules
        """
        self.r.sadd('ModifiedTWForLogs', profileid + self.separator + twid)
        self.publish('tw_modified', profileid + ':' + twid)

    # old def add_out_dstips(self, profileid, twid, daddr_as_obj, state, pkts, proto, dport):
    # old def add_out_dstips(self, profileid, twid, columns):
    def add_ips(self, profileid, twid, ip_as_obj, columns, role: str):
        """
        Function to add information about the IP
        The flow can go out of the IP (we are acting as Client) or into the IP (we are acting as Server)
        ip_as_obj: IP to add. It can be a dstIP or srcIP depending on the rol
        role: 'Client' or 'Server'

        This function does two things:
            1- Add the dstip to this tw in this profile, counting how many times it was contacted, and storing it in the key 'DstIPs' in the hash of the profile
            2- Use the dstip as a key to count how many times that IP was contacted on each dstport. We store it like this because its the 
               pefect structure to detect vertical port scans later on
        """
        try:
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
            
            # Depending if the traffic is going out or not, we are Client or Server
            if role == 'Client':
                # We are receving and adding a destination address and a dst port
                type_host_key = 'Dst'
            elif role == 'Server':
                type_host_key = 'Src'

            #############
            # Store the Dst as IP address and notify in the channel
            self.setNewIP(str(ip_as_obj))

            #############
            # 1- Count the dstips and store them
            # TODO: Retire this info after we finish 2-. Because its duplicated
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
            # 2- Store, for each ip, how many times each DSTport was contacted

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
            # Convert the dictionary to json
            data = json.dumps(prev_data)
            # Create the key for storing
            key_name = type_host_key + 'IPs' + role + proto.upper() + summaryState
            # Store this data in the profile hash
            self.r.hset( profileid + self.separator + twid, key_name, str(data))
            # Mark the tw as modified
            self.markProfileTWAsModified(profileid, twid)
        except Exception as inst:
            self.outputqueue.put('01|database|[DB] Error in add_ips in database.py')
            self.outputqueue.put('01|database|[DB] Type inst: {}'.format(type(inst)))
            self.outputqueue.put('01|database|[DB] Inst: {}'.format(inst))

    def add_tuple(self, profileid, twid, tupleid, data_tuple, role):
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
                data[tupleid] = new_data
                self.print('\tLetters so far for tuple {}: {}'.format(tupleid, new_symbol), 0, 6)
                data = json.dumps(data)
            except (TypeError, KeyError) as e:
                # There was no previous data stored in the DB
                self.print('First time for tuple {} as an {} for {} in TW {}'.format(tupleid, tuple_key, profileid, twid), 0, 5)
                new_data = (symbol_to_add, previous_two_timestamps)
                data[tupleid] = new_data
                # Convet the dictionary to json
                data = json.dumps(data)
            # Store the new data on the db
            self.r.hset(hash_id, tuple_key, str(data))
            # Mark the tw as modified
            self.markProfileTWAsModified(profileid, twid)
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
            
            # Choose which port to use based if we were asked Dst or Src
            if port_type == 'Dst':
                port = dport
            elif port_type == 'Src':
                port = sport
            
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
            # Convet the dictionary to json
            data = json.dumps(prev_data)
            self.print('add_port(): Storing info about port {} for {}. Key: {}. Data: {}'.format(port, profileid, key_name, prev_data), 0, 3)
            # Store this data in the profile hash
            hash_key = profileid + self.separator + twid
            self.r.hset(hash_key, key_name, str(data))
            # Mark the tw as modified
            self.markProfileTWAsModified(profileid, twid)
        except Exception as inst:
            self.outputqueue.put('01|database|[DB] Error in add_port in database.py')
            self.outputqueue.put('01|database|[DB] Type inst: {}'.format(type(inst)))
            self.outputqueue.put('01|database|[DB] Inst: {}'.format(inst))

    def getOutTuplesfromProfileTW(self, profileid, twid):
        """ Get the tuples """
        data = self.r.hget(profileid + self.separator + twid, 'OutTuples')
        return data

    def getInTuplesfromProfileTW(self, profileid, twid):
        """ Get the tuples """
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

    def getFieldSeparator(self):
        """ Return the field separator """
        return self.separator

    def setEvidenceForTW(self, profileid, twid, key, threat_level, confidence, description):
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
        
        """
        # Get the current evidence stored in the DB
        current_evidence = self.getEvidenceForTW(profileid, twid)
        if current_evidence:
            current_evidence = json.loads(current_evidence)
        else:
            # We never had any evidence for nothing
            current_evidence = {}
        # We dont care if there is previous evidence or not in this key. We just change all the values.
        data = []
        data.append(confidence)
        data.append(threat_level)
        data.append(description)
        current_evidence[key] = data

        current_evidence_json = json.dumps(current_evidence)
        self.r.hset(profileid + self.separator + twid, 'Evidence', str(current_evidence_json))
        # Tell everyone an evidence was added
        self.publish('evidence_added', profileid + ':' + twid)

        # Add this evidence to the timeline
        # Default time now because I did not resolve how to add here timestamp.
        # It is tricky to define when. No time for this.
        timestamp = '\t\t\t\t  '
        self.add_timeline_line(profileid, twid, current_evidence, timestamp)

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
        # Mark the tw as modified
        self.markProfileTWAsModified(profileid, twid)

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

    def getIPData(self, ip):
        """ 
        Return information about this IP from the IPs has 
        Returns a dictionary
        """
        data = self.r.hget('IPsInfo', ip)
        if data:
            data = json.loads(data)
        else:
            data = {}
        # Always return a dictionary
        return data

    def getallIPs(self):
        """ Return list of all IPs in the DB """
        data = self.r.hgetall('IPsInfo')
        #data = json.loads(data)
        return data

    def setNewIP(self, ip):
        """ Store this new ip in the IPs hash """
        if not self.getIP(ip):
            self.r.hset('IPsInfo', ip, '{}')
            # Publish in the new_ip channel 
            self.publish('new_ip', ip)

    def getIP(self, ip):
        """ Check if this ip is the hash of the profiles! """
        data = self.r.hget('IPsInfo', ip)
        if data:
            return True
        else:
            return False

    def setInfoForIPs(self, ip, ipdata):
        """ 
        Store information for this IP 
        We receive a dictionary, such as {'geocountry': 'rumania'} that we are going to store for this IP. 
        If it was not there before we store it. If it was there before, we overwrite it

        """
        # Get the previous info already stored
        data = self.getIPData(ip)

        for key in iter(ipdata):
            if type(data) == str:
                # Convert the str to a dict
                data = json.loads(data)
            to_store = ipdata[key]
            
            # If the key is already stored, do not modify it
            #self.print(data)
            try:
                value = data[key]
            except KeyError:
                # Append the new data
                data[key] = to_store
                #data.update(ipdata)
                data = json.dumps(data)
                self.r.hset('IPsInfo', ip, data)

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
        return pubsub

    def publish(self, channel, data):
        """ Publish something """
        self.r.publish(channel, data)

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

        """
        data = {}
        #data['uid'] = uid
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
        self.r.hset(profileid + self.separator + twid + self.separator + 'altflows', uid, data)
        to_send = {}
        to_send['profileid'] = profileid
        to_send['twid'] = twid
        to_send['flow'] = data
        to_send = json.dumps(to_send)
        self.publish('new_dns', to_send)
        self.print('Adding DNS flow to DB: {}'.format(data), 5,0)

    def get_altflow_from_uid(self, profileid, twid, uid):
        """ Given a uid, get the alternative flow realted to it """
        return self.r.hget(profileid + self.separator + twid + self.separator + 'altflows', uid)

    def add_timeline_line(self, profileid, twid, data, timestamp: str):
        """ Add a line to the time line of this profileid and twid """
        #self.print('Adding timeline for {}, {}: {}'.format(profileid, twid, data))
        key = str(profileid + self.separator + twid + self.separator + 'timeline')
        data = timestamp + ' ' + str(data)
        self.r.rpush(key, data)

    def get_timeline_last_lines(self, profileid, twid, first_index: int) -> Tuple[str, int]:
        """ Get all new items in this table."""
        key = str(profileid + self.separator + twid + self.separator + 'timeline')
        last_index = self.r.llen(key)
        data = self.r.lrange(key, first_index, last_index - 1)
        return data, last_index

    def get_timeline_all_lines(self, profileid, twid):
        """ Add a line to the time line of this profileid and twid """
        key = str(profileid + self.separator + twid + self.separator + 'timeline') 
        data = self.r.lrange(key, 0, -1)
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

    def add_ips_to_IoC(self, ips_and_description: dict) -> None:
        """ 
        Store a group of IPs in the db as they were obtained from an IoC source 
        What is the format of ips_and_description?
        """
        if ips_and_description:
            self.r.hmset('IoC_ips', ips_and_description)

    def add_ip_to_IoC(self, ip: str, description: str) -> None:
        """
        Store in the DB 1 IP we read from an IoC source  with its description
        """
        self.r.hset('IoC_ips', ip, description)

    def search_IP_in_IoC(self, ip: str) -> str:
        """ Search in the dB of malicious IPs and return a description if we found a match """
        ip_description = self.r.hget('IoC_ips', ip)
        return ip_description

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
            #self.print('Asked Key: {}'.format(key))
            data = self.r.hget( profileid + self.separator + twid, key)
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



__database__ = Database()
