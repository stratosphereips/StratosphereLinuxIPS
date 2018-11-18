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
        return self.r.smembers('profiles')

    def hasProfile(self, profileid):
        """ Check if we have the given profile """
        return self.r.sismember('profiles', profileid)

    def getProfilesLen(self ):
        """ Return the amount of profiles. Redis should be faster than python to do this count """
        return self.r.scard('profiles')

__database__ = Database()
