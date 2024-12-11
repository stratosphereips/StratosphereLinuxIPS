# This file is truncated file from original Slips repository - only methods that are necessary for module to build
# were left
# https://github.com/stratosphereips/StratosphereLinuxIPS/blob/5015990188f21176224e093976f80311524efe4e/slips_files/core/database.py
# --------------------------------------------------------------------------------------------------
from redis.client import Redis


class Database(object):
    """ Database object management """

    def __init__(self):
        self.r: Redis

    def start(self, slip_conf):
        raise NotImplemented('Use real implementation for Slips!')


__database__ = Database()
