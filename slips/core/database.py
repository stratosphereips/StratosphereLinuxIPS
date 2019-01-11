import redis
# delete these
import time
from datetime import datetime
from datetime import timedelta


# Struture of the DB
# Set 'profile'
#  Holds a set of all profile ids
# For each profile, there is a set for the timewindows. The name of the sets is the names of profiles


def timing(f):
    """ Function to measure the time another function takes."""
    def wrap(*args):
        time1 = time.time()
        ret = f(*args)
        time2 = time.time()
        print('function took {:.3f} ms'.format((time2-time1)*1000.0))
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
        except redis.exceptions.ResponseError as e:
            print('Error in addProfile')
            print(e)

    def getProfileIdFromIP(self, daddr_as_obj):
        """ Receive an IP and we want the profileid"""
        try:
            temp_id = 'profile' + self.separator + str(daddr_as_obj)
            data = self.r.sismember('profiles', temp_id)
            if data:
                return temp_id
            return False
        except redis.exceptions.ResponseError as e:
            print('Error in addProfile')
            print(e)

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
        if type(twid) == list:
            twid = twid[0].decode("utf-8") 
        return self.r.smembers(profileid + self.separator + twid + self.separator + 'SrcIPs')

    def getDstIPsfromProfileTW(self, profileid, twid):
        """
        Get the dst ip for a specific TW for a specific profileid
        """
        if type(twid) == list:
            twid = twid[0].decode("utf-8") 
        return self.r.smembers(profileid + self.separator + twid + self.separator + 'DstIPs')

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
            #print('In DB: Created and added to DB the new older TW with id {}. Time: {} '.format(twid, startoftw))
            # Mark the TW as modified
            self.r.set(profileid + self.separator + twid + self.separator + 'Modified', '1')
            return twid
        except redis.exceptions.ResponseError as e:
            print('Error in addNewTW')
            print(e)
        #except Exception as inst:
            #print('Error in AddNewTW in database.py')
            #print(inst)

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
            #print('In DB: Created and added to DB the TW with id {}. Time: {} '.format(twid, startoftw))
            # Mark the TW as modified
            self.r.set(profileid + self.separator + twid + self.separator + 'Modified', '1')
            return twid
        except redis.exceptions.ResponseError as e:
            print('Error in addNewTW')
            print(e)
        #except Exception as inst:
            #print('Error in AddNewTW in database.py')
            #print(inst)

    def getAmountTW(self, profileid):
        """ Return the amount of tw for this profile id """
        return self.r.zcard('tws'+profileid)

    def wasProfileTWModified(self, profileid, twid):
        """ Retrieve from the db if this TW of this profile was modified """
        data = self.r.get(profileid + self.separator + twid + self.separator + 'Modified')
        return bool(int(data.decode("utf-8")))

    def markProfileTWAsNotModified(self, profileid, twid):
        """ Mark a TW in a profile as not modified """
        self.r.set( profileid + self.separator + twid + self.separator + 'Modified', '0')

    def add_dstips(self, profileid, twid, daddr):
        """
        Add the dstip to this tw in this profile
        """
        try:
            if type(twid) == list:
                twid = twid[0].decode("utf-8") 
            self.r.sadd( profileid + self.separator + twid + self.separator + 'DstIPs', str(daddr))
            # Save in the profile that it was modified, so we know we should report on this
            self.r.set(profileid + self.separator + twid + self.separator + 'Modified', '1')
        except Exception as inst:
            print('Error in add_dstips in database.py')
            print(type(inst))
            print(inst)

    def add_srcips(self, profileid, twid, saddr):
        """
        Add the srcip to this tw in this profile
        """
        try:
            if type(twid) == list:
                twid = twid[0].decode("utf-8") 
            self.r.sadd( profileid + self.separator + twid + self.separator + 'SrcIPs', str(saddr))
            # Save in the profile that it was modified, so we know we should report on this
            self.r.set(profileid + self.separator + twid + self.separator + 'Modified', '1')
        except Exception as inst:
            print('Error in add_dstips in database.py')
            print(type(inst))
            print(inst)

    def getFieldSeparator(self):
        """ Return the field separator """
        return self.separator





__database__ = Database()
