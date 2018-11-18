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
        # For now, do not remember between runs of slips. Just delete the database when we start
        self.r.flushdb()

    def addProfile(self, profileid):
        """ Add a new profile to the DB."""
        self.r.sadd('profiles', str(profileid))

    def getProfiles(self):
        """ Get a list of all the profiles """
        profiles = self.r.smembers('profiles')
        if profiles != set():
            return profiles
        else:
            return False

    def hasProfile(self, profileid):
        """ Check if we have the given profile """
        return self.r.sismember('profiles', profileid)

    def getProfilesLen(self):
        """ Return the amount of profiles. Redis should be faster than python to do this count """
        return self.r.scard('profiles') 
   
    def getLastTWforProfile(self, profilename):
        """ Return the last TW id for the given profile id """
        return self.r.zrange(profilename, -1, -1)

    def addNewTW(self, profilename, twid, startoftw, width):
        """ Add the twid to the ordered set of a given profile """
        self.r.zadd(profilename, float(startoftw), twid)
        # Create the hashmap of this TW, add the width as an int
        self.r.hset(profilename + ':' + twid, 'width', int(width))

    def getAmountTW(self, profilename):
        """ Return the amount of tw for this profile id """
        return self.r.zcard(profilename)


















__database__ = Database()
