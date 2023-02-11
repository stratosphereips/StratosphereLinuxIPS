import redis
from .signals import message_sent
from utils import *


class Database(object):
    def __init__(self):
        self.db = self.init_db()
        self.cachedb = self.connect_to_database(port=6379, db_number=1) # default cache

    def set_db(self, port, db_number):
        self.db = self.connect_to_database(port, db_number)

    def set_cachedb(self, port, db_number):
        self.cachedb = self.connect_to_database(port, db_number)

    def init_db(self):
        available_dbs = read_db_file()
        port, db_number = 6379, 0
   
        if len(available_dbs) >= 1:
            port = available_dbs[-1]["redis_port"]
        
        return self.connect_to_database(port, db_number)

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

@message_sent.connect
def update_db(app, port, dbnumber):
    __database__.set_db(port, dbnumber)
