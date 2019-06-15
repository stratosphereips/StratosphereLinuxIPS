import configparser
import time
import urllib.request
from log_file_manager import __log_file_manager__
from progress_bar import ProgressBar
from slips.core.database import __database__


class UpdateIPManager:

    def __init__(self, outputqueue):
        self.outputqueue = outputqueue
        # For now, read the malicious IPs from here
        self.name = 'UpdateManager'
        self.url_to_malicious_ips = 'https://raw.githubusercontent.com/frenky-strasak/StratosphereLinuxIPS/frenky_develop/modules/ThreatIntelligence/malicious_ips_files/malicious_ips.txt'
        # This is where we are going to store it
        self.path_to_thret_intelligence_data = 'modules/ThreatIntelligence1/malicious_ips_files/malicious_ips.txt'
        #self.section_name = 'threat_inteligence_module'
        #self.e_tag_var = 'e_tag_of_last_malicious_ip_file'
        #self.last_update_var = 'threat_intelligence_ips_last_update'
        self.set_last_update = None
        self.set_e_tag = None
        self.old_e_tag = ''
        self.new_e_tag = ''
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
        except (ValueError, TypeError):
            last_update = float('-inf')

        now = time.time()

        if last_update is None:
            # We have no information about last update. Try to update.
            self.set_last_update = now
            return True
        
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
            # Get the time of update
            self.new_update_time = time.time()
        except:
            self.outputqueue.put('01|ThreadInteligence|[ThreadIntelligence] An error occurred during updating Threat intelligence module.')
            return False
        return True

    def __download_malicious_ips(self) -> bool:
        # Take last e-tag of our maliciou ips file.
        try:
            with open('modules/ThreatIntelligence1/malicious_ips_files/malicious_ips.etag', 'r') as f:
                self.old_e_tag = f.readlines()[0]
        except FileNotFoundError: 
            # The file is not there
            pass

        # Check now if E-TAG of file in github is same as downloaded file here.
        self.new_e_tag = self.__get_e_tag_from_web()

        if self.new_e_tag and self.old_e_tag != self.new_e_tag:
            # Our malicious file is old. Download new one.
            self.print('Trying to download the file')
            self.__download_file(self.url_to_malicious_ips, self.path_to_thret_intelligence_data)
            # Store the new etag in the file
            # Take last e-tag of our maliciou ips file.
            with open('modules/ThreatIntelligence1/malicious_ips_files/malicious_ips.etag', 'w+') as f:
                f.write(self.new_e_tag)
            return True
        elif self.new_e_tag and self.old_e_tag == self.new_e_tag:
            self.print('File is still the same. Not downloading the file', 3, 0)
            # Store the update time like we downloaded it anyway
            self.new_update_time = time.time()
            return True
        elif not self.new_e_tag:
            # Something failed. Do not download
            self.print('Not downloading the file', 3, 0)
            return False

    def update(self, update_period) -> bool:
        """
        Main function. It tries to update the malicious file from a remote server
        """
        try:
            update_period = float(update_period)
        except (TypeError, ValueError):
            # User does not want to update the malicious IP list.
            self.print('\t\tNot Updating the remote file of maliciuos IPs.')
            return False

        if update_period <= 0:
            # User does not want to update the malicious IP list.
            self.print('\t\tNot Updating the remote file of maliciuos IPs.')
            return False

        # Check if the remote file is newer than our own
        if self.__check_if_update(update_period):
            self.print('We should update the remote file')
            if self.__download_malicious_ips():
                self.print('\t\tSuccessful Update of remote maliciuos IP file.')
                # Read the last update time from the db
                __database__.set_last_update_time_malicious_file(self.new_update_time)
            else:
                self.print('An error occured during downloading data for Threat intelligence module. Updating was aborted.', 0, 1)
                return False
        else:
            self.print('\t\tMalicious IP is up to date. No downloading.')
            return False
