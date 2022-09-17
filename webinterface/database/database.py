import redis
class Database(object):
    def __init__(self):
        self.db = self.connect_to_database()
        self.cachedb = self.connect_to_database(db_number=1)

    def set_db(self, port, db_number):
        self.db = self.connect_to_database(port, db_number)

    def set_cachedb(self, port, db_number):
        self.cachedb = self.connect_to_database(port, db_number)

    def connect_to_database(self, port=6379, db_number=0):
        return redis.StrictRedis(host='localhost',
                                 port=port,
                                 db=db_number,
                                 charset="utf-8",
                                 socket_keepalive=True,
                                 retry_on_timeout=True,
                                 decode_responses=True,
                                 health_check_interval=30)


__database__ = Database()
