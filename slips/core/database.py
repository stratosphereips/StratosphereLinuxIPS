import redis
# delete these
import time
from datetime import datetime
from datetime import timedelta

# Struture of the DB
# Set 'profile'
#  Holds a set of all profile ids
# For each profile, there is a set for the timewindows. The name of the sets is the names of profiles

class Database(object):
    """ Database object management """

    def __init__(self):
        # Get the connection to redis database
        self.r = redis.StrictRedis(host='localhost', port=6379, db=0) #password='password')
        # For now, do not remember between runs of slips. Just delete the database when we start with flushdb
        self.r.flushdb()

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

            # debugging
            # Crate two fake tw
            self.addNewTW(profileid, starttime, 60)
            self.addNewTW(profileid, time.mktime(datetime.strptime('2015-07-26T10:12:53.784566', '%Y-%m-%dT%H:%M:%S.%f').timetuple()), 60)
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

    def getDstIPsfromProfileTW(self, profileid, twid):
        """
        Get all the data for a specific TW for a specific profileid
        """
        if type(twid) == list:
            twid = twid[0].decode("utf-8") 
        return self.r.smembers(profileid + '|' + twid + '|' + 'DstIPs')

    def hasProfile(self, profileid):
        """ Check if we have the given profile """
        return self.r.sismember('profiles', profileid)

    def getProfilesLen(self):
        """ Return the amount of profiles. Redis should be faster than python to do this count """
        return self.r.scard('profiles') 
   
    def getLastTWforProfile(self, profileid):
        """ Return the last TW id for the given profile id """
        # We add [0] at the end so we return a byte string and not a list
        return self.r.zrange('tws' + profileid, -1, -1)

    def addNewTW(self, profileid, startoftw, width):
        try:
            """ 
            Creates or adds a new timewindow to the list of tw for the given profile
            Add the twid to the ordered set of a given profile 
            """
            # Get the last twid and obtain the new tw id
            lastid = self.getLastTWforProfile(profileid)
            # Take it out of the list
            if lastid == list() and lastid != []:
                lastid = lastid[0].decode("utf-8") 
                twid = 'timewindow' + str(int(lastid.split('timewindow')[1]) + 1)
            else:
                twid = 'timewindow1'
            # Add the new TW to the index of TW
            self.r.zadd('tws' + profileid, float(startoftw), twid)
        except Exception as inst:
            print('Error in AddNewTW')
            print(inst)
        except redis.exceptions.ResponseError as e:
            print('Error in addNewTW')
            print(e)

    def getAmountTW(self, profileid):
        """ Return the amount of tw for this profile id """
        return self.r.zcard('tws'+profileid)

    def add_dstips(self, profileid, twid, daddr):
        """
        Add the dstip to this tw in this profile
        """
        try:
            if type(twid) == list:
                twid = twid[0].decode("utf-8") 
            self.r.sadd( profileid + '|' + twid + '|' + 'DstIPs', daddr)
            #self.r.sadd( profileid + '|' + twid + '|' + 'DstIPs', '1.1.1.1')
            #print(self.getTWProfileData(profileid, twid))
        except Exception as inst:
            print('Error in add_dstips')
            print(inst)












__database__ = Database()
