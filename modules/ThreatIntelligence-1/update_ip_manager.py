import configparser
import time
import urllib.request
from log_file_manager import __log_file_manager__
from progress_bar import ProgressBar


class UpdateIPManager:

    def __init__(self, outputqueue):
        self.outputqueue = outputqueue
        # For now, read the malicious IPs from here
        self.name = 'UpdateManager'
        self.url_to_malicious_ips = 'https://raw.githubusercontent.com/frenky-strasak/StratosphereLinuxIPS/frenky_develop/modules/ThreatIntelligence/malicious_ips_files/malicious_ips.txt'
        #self.path_to_thret_intelligence_data = 'modules/ThreatIntelligence/malicious_ips_files/malicious_ips.txt'
        #self.section_name = 'threat_inteligence_module'
        #self.e_tag_var = 'e_tag_of_last_malicious_ip_file'
        #self.last_update_var = 'threat_intelligence_ips_last_update'
        self.set_last_update = None
        self.set_e_tag = None
        self.new_update_time = None
        self.read_configuration()

    def read_configuration(self):
        """ Read the configuration file for what we need """
        try:
            self.update_period = ipaddress.ip_network(self.config.get('modules', 'malicious_ips_update_period'))
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.update_period = 86400

    def print(self, text, verbose=1, debug=0):
        """ 
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by taking all the prcocesses into account

        Input
         verbose: is the minimum verbosity level required for this text to be printed
         debug: is the minimum debugging level required for this text to be printed
         text: text to print. Can include format like 'Test {}'.format('here')
        
        If not specified, the minimum verbosity level required is 1, and the minimum debugging level is 0
        """

        vd_text = str(int(verbose) * 10 + int(debug))
        self.outputqueue.put(vd_text + '|' + self.name + '|[' + self.name + '] ' + str(text))

    def __check_if_update(self, update_period: float) -> bool:
        """
        Check if user wants to update.
        """
        """
        # Log file exists from last running of slips.
        try:
            last_update = float(__log_file_manager__.read_data(self.section_name, self.last_update_var))
        except TypeError:
            last_update = None
        """
        # Read the last update time from the db
        last_update = __database__.get_last_update_time_malicious_file()
        try:
            last_update = float(last_update)
        except ValueError:
            last_update = float('-inf')

        now = time.time()

        if last_update is None:
            # We have no information about last update. Try to update.
            self.set_last_update = now
            return True
        el
        
        if last_update + self.update_period < now:
            # Update.
            return True
        return False


    def __check_conn(self, host: str) -> bool:
        try:
            urllib.request.urlopen(host)
            return True
        except:
            return False

    def __get_e_tag_from_web(self) -> str:
        try:
            request = urllib.request.Request(self.url_to_malicious_ips)
            res = urllib.request.urlopen(request)
            e_tag = res.info().get('Etag', None)
            self.set_e_tag = e_tag
        except:
            e_tag = None
        return e_tag

    def __download_file(self, url: str, path: str) -> bool:
        # Download file from github
        try:
            urllib.request.urlretrieve(url, path)
        except:
            self.outputqueue.put('01|ThreadInteligence|[ThreadIntelligence] An error occurred during updating Threat intelligence module.')
            return False
        return True

    def __download_malicious_ips(self) -> bool:
        # check internet connection.
        # tested_url = 'https://github.com/'
        #internet_conn = self.__check_conn(tested_url)

        #if internet_conn is False:
        #    self.outputqueue.put('01|ThreadIntelligence|[ThreadIntelligence] We can not connect to {}. Check your connection. Downloading of data for Threat intelligence module is aborted.'
        #                         ''.format(tested_url))
        #    return False

        # Take last e-tag of our maliciou ips file.
        old_e_tag = __log_file_manager__.read_data(self.section_name, self.e_tag_var)
        # Check now if E-TAG of file in github is same as downloaded file here.
        new_e_tag = self.__get_e_tag_from_web()
        if old_e_tag is not None and new_e_tag is not None:
            if old_e_tag != new_e_tag:
                # Our malicious file is old. Download new one.
                self.__download_file(self.url_to_malicious_ips, self.path_to_thret_intelligence_data)

        if old_e_tag is None and new_e_tag is not None:
            # We have no information about last e-tag. Download new one.
            self.__download_file(self.url_to_malicious_ips, self.path_to_thret_intelligence_data)

        if new_e_tag is None:
            # We can not get information about e-tag. Abort downloading.
            self.outputqueue.put(
                '01|ThreadIntelligence|[ThreadIntelligence] Downloading of data for Threat intelligence module is aborted. We do not have access to {}.'
                ''.format(self.url_to_malicious_ips))
            return False
        return True

    def __set_log_file(self, variable_name: str, value: str):
        """
        Set data in slips_log.conf file.
        """
        __log_file_manager__.set_data(self.section_name, variable_name, value)


    def update(self, update_period) -> bool:
        """
        Main function. It tries to update the malicious file from a remote server
        """
        try:
            update_period = float(update_period)
        except (TypeError, ValueError):
            # User does not want to update the malicious IP list.
            self.print('\t\tNot Updating the remote file of maliciuos IPs.', 0, 1)
            return False

        if update_period <= 0:
            # User does not want to update the malicious IP list.
            self.print('\t\tNot Updating the remote file of maliciuos IPs.', 0, 1)
            return False

        # Check if the remote file is newer than our own
        if self.__check_if_update(update_period):
            if self.__download_malicious_ips():
                self.print('\t\tSuccessful Update of remote maliciuos IP file.', 0, 1)
                # Read the last update time from the db
                __database__.set_last_update_time_malicious_file(self.new_update_time)
            else:
                self.print('An error occured during downloading data for Threat intelligence module. Updating was aborted.', 0, 1)


        else:
            self.print('\t\tMalicious IP is up to date. No downloading.', 0, 1)

        """
        # Save e-tag and lastUpdate to log file if they are not None.
        if self.set_e_tag:
            self.__set_log_file(self.e_tag_var, str(self.set_e_tag))
        if self.set_last_update:
            self.__set_log_file(self.last_update_var, str(self.set_last_update))
        """


