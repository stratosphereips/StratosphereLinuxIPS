import redis
# delete these
import time
from datetime import datetime
from datetime import timedelta
import json


# Struture of the DB
# Set 'profile'
#  Holds a set of all profile ids
# For each profile, there is a set for the timewindows. The name of the sets is the names of profiles
# The data for a profile in general is hold in a hash
# The data for each timewindow in a profile is hold in a hash
 # profile|10.0.0.1|timewindow1
 # In this hash there are strings:
  # dstips_in -> '{'1.1.1.1':10, '2.2.2.2':20}'
  # srcips_in -> '{'3.3.3.3':30, '4.4.4.4':40}'
  # dstports_in -> '{'22':30, '21':40}'
  # dstports_in -> '{'22':30, '21':40}'
  # dstips_out -> '{'1.1.1.1':10, '2.2.2.2':20}'
  # srcips_out -> '{'3.3.3.3':30, '4.4.4.4':40}'
  # dstports_out -> '{'22':30, '21':40}'
  # dstports_out -> '{'22':30, '21':40}'


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
        # Get the connection to redis database
        self.r = redis.StrictRedis(host='localhost', port=6379, db=0) #password='password')
        # For now, do not remember between runs of slips. Just delete the database when we start with flushdb
        self.r.flushdb()
        self.separator = '_'

    def setOutputQueue(self, outputqueue):
        """ Set the output queue"""
        self.outputqueue = outputqueue

    def addProfile(self, profileid, starttime, duration):
        """ 
        Add a new profile to the DB. Both the list of profiles and the hasmap of profile data
        Profiles are stored in two structures. A list of profiles (index) and individual hashmaps for each profile (like a table)
        """
        try:
            if not self.r.sismember('profiles', str(profileid)):
                # Add the profile to the index. The index is called 'profiles'
                self.r.sadd('profiles', str(profileid))
                # Create the hashmap with the profileid. The hasmap of each profile is named with the profileid
                self.r.hset(profileid, 'Starttime', starttime)
                # For now duration of the TW is fixed
                self.r.hset(profileid, 'duration', duration)
                # The name of the list with the dstips
                #self.r.hset(profileid, 'DstIps', 'DstIps')
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
            return False

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

        """
        return self.r.zrange('tws' + profileid, 0, -1, withscores=True)

    def getamountTWsfromProfile(self, profileid):
        """
        Receives a profile id and returns the list of all the TW in that profile

        """
        return len(self.r.zrange('tws' + profileid, 0, -1, withscores=True))

    def getSrcIPsfromProfileTW(self, profileid, twid):
        """
        Get the src ip for a specific TW for a specific profileid
        """
        #if type(twid) == list:
        #    twid = twid[0].decode("utf-8") 
        #return self.r.smembers(profileid + self.separator + twid + self.separator + 'SrcIPs')
        data = self.r.hget(profileid + self.separator + twid, 'SrcIPs')
        if data:
            return data.decode('utf-8')
        else:
            return ''

    def getDstIPsfromProfileTW(self, profileid, twid):
        """
        Get the dst ip for a specific TW for a specific profileid
        """
        #if type(twid) == list:
        #    twid = twid[0].decode("utf-8") 
        #return self.r.smembers(profileid + self.separator + twid + self.separator + 'DstIPs')
        data = self.r.hget(profileid + self.separator + twid, 'DstIPs')
        if data:
            return data.decode('utf-8')
        else:
            return ''

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
        """ Return the TW id and the time for the TW that includes the given time.
        The score in the DB is the start of the timewindow, so we should search a TW that includes 
        the given time by making sure the start of the TW is < time, and the end of the TW is > time.
        """
        # [-1] so we bring the last TW that matched this time.
        try:
            data = self.r.zrangebyscore('tws' + profileid, 0, float(time), withscores=True, start=0, num=-1)[-1]
        except IndexError:
            # There is no TW that has this time inside it
            data = []
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
                firstid = firstid.decode("utf-8") 
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
            # Create the hash for the timewindow and mark it as modified
            self.markProfileTWAsModified(profileid, twid)
            return twid
        except redis.exceptions.ResponseError as e:
            self.outputqueue.put('00|database|error in addNewOlderTW in database.py')
            self.outputqueue.put('00|database|{}'.format(type(inst)))
            self.outputqueue.put('00|database|{}'.format(inst))

    def addNewTW(self, profileid, startoftw):
        try:
            """ 
            Creates or adds a new timewindow to the list of tw for the given profile
            Add the twid to the ordered set of a given profile 
            Return the id of the timewindow just created
            """
            # Get the last twid and obtain the new tw id
            try:
                (lastid, lastid_time) = self.getLastTWforProfile(profileid)[0]
                # We have a last id
                lastid = lastid.decode("utf-8") 
                # Increment it
                twid = 'timewindow' + str(int(lastid.split('timewindow')[1]) + 1)
            except IndexError:
                # There is no first TW, create it
                twid = 'timewindow1'
            # Add the new TW to the index of TW
            data = {}
            data[str(twid)] = float(startoftw)
            self.r.zadd('tws' + profileid, data)
            self.outputqueue.put('04|database|[DB]: Created and added to DB the TW with id {}. Time: {} '.format(twid, startoftw))
            return twid
        except redis.exceptions.ResponseError as e:
            self.outputqueue.put('01|database|Error in addNewTW')
            self.outputqueue.put('01|database|{}'.format(e))

    def getAmountTW(self, profileid):
        """ Return the amount of tw for this profile id """
        return self.r.zcard('tws'+profileid)

    def wasProfileTWModified(self, profileid, twid):
        """ Retrieve from the db if this TW of this profile was modified """
        data = self.r.hget(profileid + self.separator + twid, 'Modified')
        return bool(int(data))

    def markProfileTWAsNotModified(self, profileid, twid):
        """ Mark a TW in a profile as not modified """
        self.r.hset( profileid + self.separator + twid, 'Modified', '0')

    def markProfileTWAsModified(self, profileid, twid):
        """ 
        Mark a TW in a profile as not modified 
        As a side effect, it can create it if its not there
        """
        self.r.hset( profileid + self.separator + twid, 'Modified', '1')

    def add_out_dstips(self, profileid, twid, daddr_as_obj):
        """
        Function if the flow is going out from the profile IP
        Add the dstip to this tw in this profile
        """
        try:
            # Get the hash of the timewindow
            hash_id = profileid + self.separator + twid
            data = self.r.hget(hash_id, 'DstIPs')
            if not data:
                data = {}
            try:
                temp_data = self.r.hget(profileid + self.separator + twid, 'DstIPs')
                # Convert the json str to a dictionary
                data = json.loads(temp_data)
                # Add 1 because we found this ip again
                data[str(daddr_as_obj)] += 1
                #self.outputqueue.put('03|database|[DB]: Not the first time. Add 1 to {}'.format(daddr_as_obj))
            except (KeyError, TypeError) as e:
                data[str(daddr_as_obj)] = 1
                # Convet the dictionary to json
                data = json.dumps(data)
            #self.outputqueue.put('03|database|[DB]: Data to store back in the hash {}'.format(data))
            self.r.hset( profileid + self.separator + twid, 'DstIPs', str(data))
            # Mark the tw as modified
            self.markProfileTWAsModified(profileid, twid)
        except Exception as inst:
            self.outputqueue.put('01|database|Error in add_dstips in database.py')
            self.outputqueue.put('01|database|{}'.format(type(inst)))
            self.outputqueue.put('01|database|{}'.format(inst))

    def add_out_dstport(self, profileid, twid, dport):
        """ """
        pass

    def add_out_srcport(self, profileid, twid, sport):
        """ """
        pass

    def add_in_srcips(self, profileid, twid, saddr_as_obj):
        """
        Function if the flow is going in to the profile IP
        Add the srcip to this tw in this profile
        """
        try:
            # Get the hash of the timewindow
            hash_id = profileid + self.separator + twid
            data = self.r.hget(hash_id, 'SrcIPs')
            if not data:
                data = {}
            try:
                temp_data = self.r.hget(profileid + self.separator + twid, 'SrcIPs')
                # Convert the json str to a dictionary
                data = json.loads(temp_data)
                # Add 1 because we found this ip again
                data[str(saddr_as_obj)] += 1
            except (KeyError, TypeError) as e:
                data[str(saddr_as_obj)] = 1
                # Convet the dictionary to json
                data = json.dumps(data)
            self.r.hset( profileid + self.separator + twid, 'SrcIPs', str(data))
            # Mark the tw as modified
            self.markProfileTWAsModified(profileid, twid)
        except Exception as inst:
            self.outputqueue.put('01|database|Error in add_dstips in database.py')
            self.outputqueue.put('01|database|{}'.format(type(inst)))
            self.outputqueue.put('01|database|{}'.format(inst))

    def add_in_dstport(self, profileid, twid, dport):
        """ """
        pass

    def add_in_srcport(self, profileid, twid, sport):
        """ """
        pass

    def add_srcips(self, profileid, twid, saddr):
        """ """
        pass

    def getFieldSeparator(self):
        """ Return the field separator """
        return self.separator





__database__ = Database()
