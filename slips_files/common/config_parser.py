import hashlib
from datetime import datetime, timezone, timedelta
import validators
from git import Repo
import socket
import subprocess
import json
import time
import platform
import os
import ipaddress
import configparser

class ConfigParser(object):
    name = 'ConfigParser'
    description = 'Parse and sanitize slips.conf values. used by all modules'
    authors = ['Alya Gomaa']

    def __init__(self):
        self.home_network_ranges = (
            '192.168.0.0/16',
            '172.16.0.0/12',
            '10.0.0.0/8',
        )
        self.home_network_ranges = list(map(
            ipaddress.ip_network, self.home_network_ranges
        ))


    def read_configuration(self, config, section, name, default_value):
        """
        Read the configuration file for what slips.py needs.
         Other processes also access the configuration
        """
        try:
            return config.get(section, name)
        except (
            configparser.NoOptionError,
            configparser.NoSectionError,
            NameError,
            ValueError
        ):
            # There is a conf, but there is no option,
            # or no section or no configuration file specified
            return default_value

    def get_home_network(self, config) -> list:
        """
        :param config: configparser instance
        Returns a list of network objects
        """
        home_net = self.read_configuration(
            config, 'parameters', 'home_network', False
        )

        if home_net:
            # we have home_network param set in slips.conf
            home_nets = home_net.replace(']','').replace('[','').split(',')
            home_nets = [network.strip() for network in home_nets]
        else:
            return self.home_network_ranges

        return list(map(ipaddress.ip_network, home_nets))


    def get_tw_width(self, config):
        """
        :param config: configparser instance
        """
        twid_width = self.read_configuration(
            config, 'parameters', 'time_window_width', 3600
        )
        twid_width = int(twid_width)
        # twid_width = f'{twid_width / 60} mins' if twid_width <= 60
        # else f'{twid_width / 60 / 60}h'
        twid_width = str(timedelta(seconds=twid_width))
        if ', 0:00:00' in twid_width:
            # and int number of days. '1 day, 0:00:00' for example,
            # we only need 1 day
            return twid_width.replace(', 0:00:00', '')

        if ':' in twid_width and 'day' not in twid_width:
            # less than a day
            hrs, mins, sec = twid_width.split(':')
            hrs = int(hrs)
            mins = int(mins)
            sec = int(sec)

            res = ''
            if hrs:
                res += f'{hrs} hrs '
                # remove the s
                if hrs == 1: res=res[:-2] + ' '

            if mins:
                res += f'{mins} mins '
                if mins == 1: res=res[:-2] + ' '

            if sec:
                res += f'{sec} seconds '
                if sec == 1: res=res[:-2] + ' '

            if res.endswith(' '): res=res[:-1]
            return res

        # width is a combination of days mins and seconds
        return twid_width


conf = ConfigParser()

