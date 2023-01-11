from datetime import timedelta
import sys
import ipaddress
import configparser
from slips_files.common.argparse import ArgumentParser
from slips_files.common.slips_utils import utils


class ConfigParser(object):
    name = 'ConfigParser'
    description = 'Parse and sanitize slips.conf values. used by all modules'
    authors = ['Alya Gomaa']

    def __init__(self):
        # self.args = self.get_args()
        self.configfile = self.get_config_file()
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
        config = configparser.ConfigParser(interpolation=None, comment_prefixes='#')
        try:
            with open(self.configfile) as source:
                config.read_file(source)
        except (IOError, TypeError):
            pass
        return config

    def get_config_file(self):
        parser = self.get_parser()
        return parser.get_configfile()

    def get_parser(self, help=False):
        parser = ArgumentParser(
            usage='./slips.py -c <configfile> [options] [file]', add_help=help
        )
        return parser



    def get_args(self):
        """
        Returns the args given to slips parsed by ArgumentParser
        """
        parser = self.get_parser()
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

    def get_entropy_threshold(self):
        """
        gets the shannon entropy used in detecting C&C over DNS TXT records from slips.conf
        """
        threshold = self.read_configuration(
            'flowalerts', 'entropy_threshold', 5
        )

        try:
            return float(threshold)
        except:
            return 5


    def get_pastebin_download_threshold(self):

        threshold = self.read_configuration(
            'flowalerts', 'pastebin_download_threshold', 700
        )

        try:
            return int(threshold)
        except:
            return 700


    def get_all_homenet_ranges(self):
        return self.home_network_ranges

    def get_home_network(self):
        """
        Returns a list of network objects if defined in slips.conf. or False
        """
        home_net = self.read_configuration(
            'parameters', 'home_network', False
        )

        if home_net:
            # we have home_network param set in slips.conf
            home_nets = home_net.replace(']','').replace('[','').split(',')
            home_nets = [network.strip() for network in home_nets]
            return list(map(ipaddress.ip_network, home_nets))
        else:
            # return self.home_network_ranges
            return False



    def evidence_detection_threshold(self):
        threshold = self.read_configuration(
            'detection', 'evidence_detection_threshold', 2
        )
        try:
            threshold = float(threshold)
        except ValueError:
            threshold = 2
        return threshold


    def packet_filter(self):
        pcapfilter = self.read_configuration(
            'parameters', 'pcapfilter', 'no'
        )
        if pcapfilter in ('no'):
            return False
        return pcapfilter

    def online_whitelist(self):
        return self.read_configuration(
            'threatintelligence', 'online_whitelist',  False
        )


    def tcp_inactivity_timeout(self):
        timeout = self.read_configuration(
            'parameters', 'tcp_inactivity_timeout',  '5'
        )
        try:
            timeout = int(timeout)
        except ValueError:
            timeout = 5
        return timeout

    def online_whitelist_update_period(self):
        update_period = self.read_configuration(
            'threatintelligence', 'online_whitelist_update_period', 604800
        )
        try:
            update_period = int(update_period)
        except ValueError:
            update_period = 604800
        return update_period


    def popup_alerts(self):
        popups = self.read_configuration(
            'detection', 'popup_alerts', 'False'
        )
        return  'yes' in popups.lower() 

    def rotation(self):
        rotation = self.read_configuration(
            'parameters', 'rotation', 'yes'
        )
        return  'yes' in rotation.lower() 

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
        return  'yes' in do_logs 

    def whitelist_path(self):
        return self.read_configuration(
            'parameters', 'whitelist_path', 'whitelist.conf'
        )

    def logsfile(self):
        return self.read_configuration(
            'modes', 'logsfile', 'slips.log'
        )

    def stdout(self):
        return self.read_configuration(
            'modes', 'stdout', 'slips.log'
        )

    def stderr(self):
        return self.read_configuration(
            'modes', 'stderr', 'errors.log'
        )


    def create_p2p_logfile(self):
        create_p2p_logfile = self.read_configuration(
            'P2P', 'create_p2p_logfile', 'no'
        )
        return 'yes' in create_p2p_logfile.lower()


    def ts_format(self):
        return self.read_configuration(
            'timestamp', 'format', None
        )


    def log_report_time(self):
        time = self.read_configuration(
            'parameters', 'log_report_time', 5
        )
        try:
            time = int(time)
        except ValueError:
            time = 5
        return time

    def delete_zeek_files(self):
        delete = self.read_configuration(
            'parameters', 'delete_zeek_files', 'no'
        )
        return (
            False if 'no' in delete.lower() else True
        )

    def store_zeek_files_copy(self):
        store_copy = self.read_configuration(
                'parameters', 'store_a_copy_of_zeek_files', 'yes'
            )
        return (
            False if 'no' in store_copy.lower() else True
        )

    def get_tw_width_as_float(self):
        try:
            twid_width = self.config.get('parameters', 'time_window_width')
        except (
            configparser.NoOptionError,
            configparser.NoSectionError,
            NameError,
            ValueError
        ):
            # There is a conf, but there is no option,
            # or no section or no configuration file specified
            twid_width = 3600

        try:
            twid_width = float(twid_width)
        except ValueError:
            # Its not a float
            if 'only_one_tw' in twid_width:
                # Only one tw. Width is 10 9s, wich is ~11,500 days, ~311 years
                twid_width = 9999999999
        return twid_width

    def disabled_detections(self):
        disabled_detections = self.read_configuration(
                'DisabledAlerts', 'disabled_detections', []
            )
        if disabled_detections:
            disabled_detections = (
                disabled_detections.replace('[', '')
                .replace(']', '')
                .replace(',', '')
                .split()
            )
        return disabled_detections

    def get_tw_width(self):
        twid_width = self.get_tw_width_as_float()
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


    def cesnet_conf_file(self):
        file = self.read_configuration(
            'CESNET', 'configuration_file', False
        )
        return file

    def poll_delay(self):
        poll_delay = self.read_configuration(
            'CESNET', 'receive_delay', 86400
        )
        try:
            poll_delay = int(poll_delay)
        except ValueError:
            # By default push every 1 day
            poll_delay = 86400

        return poll_delay

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
        except ValueError:
            debug = 0
        return debug

    def export_to(self):
        export_to = self.read_configuration(
            'exporting_alerts', 'export_to', '[]'
        )\
            .replace(']','')\
            .replace('[','')\
            .replace(' ', '')\
            .lower().split(',')
        return export_to

    def slack_token_filepath(self):
        file = self.read_configuration(
            'exporting_alerts', 'slack_api_path', False
        )
        return file

    def slack_channel_name(self):
        channel = self.read_configuration(
            'exporting_alerts', 'slack_channel_name', False
        )
        return channel

    def sensor_name(self):
        sensor = self.read_configuration(
            'exporting_alerts', 'sensor_name', False
        )
        return sensor


    def taxii_server(self):
        taxii_server =  self.read_configuration(
            'exporting_alerts', 'TAXII_server', False
        )
        return taxii_server.replace('www.','')


    def taxii_port(self):
        return self.read_configuration(
            'exporting_alerts', 'port', False
        )

    def use_https(self):
        use_https = self.read_configuration(
            'exporting_alerts', 'use_https', 'false'
        )
        return use_https.lower() == 'true'

    def discovery_path(self):
        return self.read_configuration(
            'exporting_alerts', 'discovery_path', False
        )

    def inbox_path(self):
        return self.read_configuration(
            'exporting_alerts', 'inbox_path', False
        )

    def push_delay(self):
        # 3600 = 1h
        delay = self.read_configuration(
            'exporting_alerts', 'push_delay', 3600
        )
        try:
            delay = float(delay)
        except ValueError:
            delay = 3600
        return delay

    def collection_name(self):
        return self.read_configuration(
            'exporting_alerts', 'collection_name', False
        )

    def taxii_username(self):
        return self.read_configuration(
            'exporting_alerts', 'taxii_username', False
        )

    def taxii_password(self):
        return self.read_configuration(
            'exporting_alerts', 'taxii_password', False
        )

    def jwt_auth_path(self):
        return self.read_configuration(
            'exporting_alerts', 'jwt_auth_path', False
        )


    def long_connection_threshold(self):
        """
        returns threshold in seconds
        """
        # 1500 is in seconds, =25 mins
        threshold = self.read_configuration(
            'flowalerts', 'long_connection_threshold', 1500
        )
        try:
            threshold = int(threshold)
        except ValueError:
            threshold = 1500
        return threshold

    def ssh_succesful_detection_threshold(self):
        """
        returns threshold in seconds
        """
        threshold =  self.read_configuration(
            'flowalerts', 'ssh_succesful_detection_threshold', 4290
        )
        try:
            threshold = int(threshold)
        except ValueError:
            threshold = 4290

        return threshold

    def data_exfiltration_threshold(self):
        """
        returns threshold in MBs
        """
        # threshold in MBs
        threshold =  self.read_configuration(
        'flowalerts', 'data_exfiltration_threshold', 500
        )
        try:
            threshold = int(threshold)
        except ValueError:
            threshold = 500
        return threshold

    def get_ml_mode(self):
        return self.read_configuration(
            'flowmldetection', 'mode', 'test'
        )

    def RiskIQ_credentials_path(self):
        return self.read_configuration(
            'threatintelligence', 'RiskIQ_credentials_path', ''
        )

    def local_ti_data_path(self):
        return self.read_configuration(
            'threatintelligence',
            'local_threat_intelligence_files',
            'modules/threat_intelligence/local_data_files/'
        )


    def remote_ti_data_path(self):
        path = self.read_configuration(
            'threatintelligence',
            'download_path_for_remote_threat_intelligence',
            'modules/threat_intelligence/remote_data_files/'
        )
        return utils.sanitize(path)

    def ti_files(self):
        feeds = self.read_configuration(
            'threatintelligence',
            'ti_files',
            False
        )
        if feeds:
            return feeds.split('\n')
        return {}

    def ja3_feeds(self):
        feeds = self.read_configuration(
            'threatintelligence',
            'ja3_feeds',
            False
        )
        if feeds:
            return feeds.split('\n')
        return {}

    def ssl_feeds(self):
        feeds = self.read_configuration(
            'threatintelligence',
            'ssl_feeds',
            False
        )
        if feeds:
            return feeds.split('\n')
        return {}

    def timeline_human_timestamp(self):
        return self.read_configuration(
            'modules', 'timeline_human_timestamp', False
        )

    def analysis_direction(self):
        return self.read_configuration(
             'parameters', 'analysis_direction', False
        )

    def update_period(self):
        update_period =  self.read_configuration(
             'threatintelligence', 'TI_files_update_period', 86400
        )
        try:
            update_period = float(update_period)
        except ValueError:
            update_period = 86400   # 1 day
        return update_period

    def vt_api_key_file(self):
        return self.read_configuration(
             'virustotal', 'api_key_file', None
        )

    def virustotal_update_period(self):
        update_period =  self.read_configuration(
             'virustotal', 'virustotal_update_period', 259200
        )
        try:
            update_period = int(update_period)
        except ValueError:
            update_period = 259200
        return update_period


    def riskiq_update_period(self):
        update_period =  self.read_configuration(
             'threatintelligence', 'update_period', 604800
        )
        try:
            update_period = float(update_period)
        except ValueError:
            update_period = 604800   # 1 week
        return update_period

    def mac_db_update_period(self):
        update_period =  self.read_configuration(
             'threatintelligence', 'mac_db_update', 1209600
        )
        try:
            update_period = float(update_period)
        except ValueError:
            update_period = 1209600   # 2 weeks
        return update_period

    def deletePrevdb(self):
        delete = self.read_configuration(
             'parameters', 'deletePrevdb', True
        )
        return False if delete == 'False' else True

    def rotation_period(self):
        rotation_period = self.read_configuration(
             'parameters', 'rotation_period', '1 day'
        )
        return utils.sanitize(rotation_period)

    def keep_rotated_files_for(self) -> int:
        """ returns period in seconds"""
        keep_rotated_files_for = self.read_configuration(
             'parameters', 'keep_rotated_files_for', '1 day'
        )
        try:
            period = utils.sanitize(keep_rotated_files_for)
            period = period.replace('day', '').replace(' ','').replace('s','')
            period = int(period)
        except ValueError:
            period = 1

        return period *24*60*60

    def wait_for_modules_to_finish(self) -> int:
        """ returns period in mins"""
        wait_for_modules_to_finish = self.read_configuration(
             'parameters', 'wait_for_modules_to_finish', '15 mins'
        )
        try:
            period = utils.sanitize(wait_for_modules_to_finish)
            period = period\
                .replace('mins', '')\
                .replace(' ','')\
                .replace('s','')
            period = float(period)
        except ValueError:
            period = 15

        return period

    def mac_db_link(self):
        return utils.sanitize(self.read_configuration(
             'threatintelligence', 'mac_db', ''
        ))

    def store_zeek_files_in_the_output_dir(self):
        store_in_output = self.read_configuration(
         'parameters', 'store_zeek_files_in_the_output_dir', 'no'
        )
        return 'yes' in store_in_output


    def label(self):
        return self.read_configuration(
             'parameters', 'label', 'unknown'
        )

    def get_disabled_modules(self, input_type) -> list:
        """
        Uses input type to enable leak detector only on pcaps
        """
        to_ignore = self.read_configuration(
            'modules', 'disable', '[template , ensembling]'
        )
        # Convert string to list
        to_ignore = (
            to_ignore.replace('[', '')
                .replace(']', '')
                .split(',')
        )
        # strip each one of them
        to_ignore = [mod.strip() for mod in to_ignore]
        use_p2p = self.use_p2p()

        # Ignore exporting alerts module if export_to is empty
        export_to = self.export_to()
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

        # ignore CESNET sharing module if send and receive are
        # disabled in slips.conf
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




