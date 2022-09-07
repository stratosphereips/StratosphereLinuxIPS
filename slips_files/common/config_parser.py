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
import sys
import ipaddress
import configparser
from slips_files.common.argparse import ArgumentParser


class ConfigParser(object):
    name = 'ConfigParser'
    description = 'Parse and sanitize slips.conf values. used by all modules'
    authors = ['Alya Gomaa']

    def __init__(self):
        self.args = self.get_args()
        self.config = self.read_config_file()
        self.home_network_ranges = (
            '192.168.0.0/16',
            '172.16.0.0/12',
            '10.0.0.0/8',
        )
        self.home_network_ranges = list(map(
            ipaddress.ip_network, self.home_network_ranges
        ))

    def read_config_file(self):
        """
        reads slips configuration file, slips.conf is the default file
        """
        config = configparser.ConfigParser(interpolation=None)
        try:
            with open(self.args.config) as source:
                config.read_file(source)
        except (IOError, TypeError):
            pass
        return config

    def get_args(self):
        """
        Returns the args given to slips parsed by ArgumentParser
        """
        parser = ArgumentParser(
            usage='./slips.py -c <configfile> [options] [file]', add_help=False
        )
        return parser.parse_arguments()

    def read_configuration(self, section, name, default_value):
        """
        Read the configuration file for what slips.py needs.
         Other processes also access the configuration
        """
        try:
            return self.config.get(section, name)
        except (
            configparser.NoOptionError,
            configparser.NoSectionError,
            NameError,
            ValueError
        ):
            # There is a conf, but there is no option,
            # or no section or no configuration file specified
            return default_value

    def get_home_network(self) -> list:
        """
        Returns a list of network objects
        """
        home_net = self.read_configuration(
            'parameters', 'home_network', False
        )

        if home_net:
            # we have home_network param set in slips.conf
            home_nets = home_net.replace(']','').replace('[','').split(',')
            home_nets = [network.strip() for network in home_nets]
        else:
            return self.home_network_ranges

        return list(map(ipaddress.ip_network, home_nets))

    def store_a_copy_of_zeek_files(self):
        store_a_copy_of_zeek_files = self.read_configuration(
            'parameters', 'store_a_copy_of_zeek_files', 'no'
        )
        return (
            False
            if 'no' in store_a_copy_of_zeek_files.lower()
            else True
        )

    def create_log_files(self):
        do_logs = self.read_configuration(
            'parameters', 'create_log_files', 'no'
        )
        return True if 'yes' in do_logs else False

    def whitelist_path(self):
        return self.read_configuration(
            'parameters', 'whitelist_path', 'whitelist.conf'
        )

    def delete_zeek_files(self):
        delete = self.read_configuration(
            'parameters', 'delete_zeek_files', 'no'
        )
        return (
            False if 'no' in delete.lower() else True
        )

    def get_tw_width(self, ):
        twid_width = self.read_configuration(
            'parameters', 'time_window_width', 3600
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

    def enable_metadata(self):
        enable_metadata = self.read_configuration(
                                                'parameters',
                                                'metadata_dir',
                                                'no'
                                                )
        return (
            False if 'no' in enable_metadata.lower() else True
        )

    def use_p2p(self):
        use_p2p = self.read_configuration(
            'P2P', 'use_p2p', 'no'
        )
        return (
            False if 'no' in use_p2p.lower() else True
        )

    def send_to_warden(self):
        send_to_warden = self.read_configuration(
            'CESNET', 'send_alerts', 'no'
        ).lower()
        return (
            False if 'no' in send_to_warden.lower() else True
        )

    def receive_from_warden(self):
        receive_from_warden = self.read_configuration(
            'CESNET', 'receive_alerts', 'no'
        ).lower()
        return (
            False if 'no' in receive_from_warden.lower() else True
        )

    def verbose(self):
        verbose = self.read_configuration(
          'parameters', 'verbose', 1
        )
        try:
            verbose = int(verbose)
            if verbose < 1:
                verbose = 1
            return verbose
        except ValueError:
            return 1

    def debug(self):
        debug = self.read_configuration(
          'parameters', 'debug', 0
        )
        try:
            debug = int(debug)
            if debug < 0:
                debug = 0
            return debug
        except ValueError:
            return 0

    def get_disabled_modules(self, input_type) -> list:
        to_ignore = self.read_configuration(
            'modules', 'disable', False
        )
        use_p2p = self.use_p2p()

        # Convert string to list
        to_ignore = (
            to_ignore.replace('[', '')
                .replace(']', '')
                .replace(' ', '')
                .split(',')
        )

        # Ignore exporting alerts module if export_to is empty
        export_to = (
            self.read_configuration('exporting_alerts', 'export_to', '[]')
                .rstrip('][')
                .replace(' ', '')
                .lower()
        )
        if (
                'stix' not in export_to
                and 'slack' not in export_to
        ):
            to_ignore.append('exporting_alerts')

        if (
                not use_p2p
                or '-i' not in sys.argv
        ):
            to_ignore.append('p2ptrust')

        # ignore CESNET sharing module if send and receive are disabled in slips.conf
        send_to_warden = self.send_to_warden()
        receive_from_warden = self.receive_from_warden()

        if not send_to_warden and not receive_from_warden:
            to_ignore.append('CESNET')

        # don't run blocking module unless specified
        if not (
                 '-cb' in sys.argv
                or '-p' in sys.argv
        ):
            to_ignore.append('blocking')

        # leak detector only works on pcap files
        if input_type != 'pcap':
            to_ignore.append('leak_detector')

        return to_ignore


conf = ConfigParser()

