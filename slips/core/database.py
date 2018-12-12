import redis

"""
Connection Pools
Behind the scenes, redis-py uses a connection pool to manage connections to a Redis server. By default, each Redis instance you create will in turn create its own connection pool. You can override this behavior and use an existing connection pool by passing an already created connection pool instance to the connection_pool argument of the Redis class. You may choose to do this in order to implement client side sharding or have finer grain control of how connections are managed.

pool = redis.ConnectionPool(host='localhost', port=6379, db=0)
r = redis.Redis(connection_pool=pool)
"""


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

    def addProfile(self, profileid, starttime):
        """ Add a new profile to the DB. Both the list of profiles and the hasmap of profile data"""
        if not self.r.sismember('profiles', str(profileid)):
            self.r.sadd('profiles', str(profileid))
            self.r.hset(profileid, 'Starttime', starttime)
            # For now duration of the TW is fixed
            self.r.hset(profileid, 'duration', 60)
            # The name of the list with the dstips
            self.r.hset(profileid, 'DstIps', 'DstIps')

    def getProfiles(self):
        """ Get a list of all the profiles """
        profiles = self.r.smembers('profiles')
        if profiles != set():
            return profiles
        else:
            return False

    def getProfileData(self, profileid):
        """ Get all the data for this particular profile """
        profile = self.r.hgetall(profileid)
        if profile != set():
            return profile
        else:
            return False

    def hasProfile(self, profileid):
        """ Check if we have the given profile """
        return self.r.sismember('profiles', profileid)

    def getProfilesLen(self):
        """ Return the amount of profiles. Redis should be faster than python to do this count """
        return self.r.scard('profiles') 
   
    def getLastTWforProfile(self, profileid):
        """ Return the last TW id for the given profile id """
        return self.r.zrange('tws'+profileid, -1, -1)

    def addNewTW(self, profileid, twid, startoftw, width):
        try:
            """ Add the twid to the ordered set of a given profile """
            self.r.zadd('tws'+profileid, float(startoftw), twid)
            # Add this TW to the hasmap of profiles
            self.r.hset(profileid, twid, 'Created')
        except redis.exceptions.ResponseError as e:
            print('Error in addNewTW')
            print(e)

    def getAmountTW(self, profileid):
        """ Return the amount of tw for this profile id """
        return self.r.zcard('tws'+profileid)







__database__ = Database()
