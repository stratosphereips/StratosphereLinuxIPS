import configparser
import time
from log_file_manager import __log_file_manager__
from slips.core.database import __database__
import os


class UpdateIPManager:

    def __init__(self, outputqueue, config):
        self.outputqueue = outputqueue
        self.config = config
        # For now, read the malicious IPs from here
        self.name = 'UpdateManager'
        self.new_update_time = float('-inf')
        # Read the conf
        self.read_configuration()

    def read_configuration(self):
        """ Read the configuration file for what we need """
        try:
            # update period
            self.update_period = self.config.get('threatintelligence', 'malicious_ips_update_period')
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.update_period = 86400
        try:
            # Read the path to where to store and read the malicious files
            self.path_to_thret_intelligence_data = self.config.get('threatintelligence', 'malicious_ip_file_path')
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.path_to_thret_intelligence_data = 'modules/ThreatIntelligence1/malicious_ips_files/'
        try:
            # Read the list of URLs to download. Convert to list
            self.list_of_urls = self.config.get('threatintelligence', 'ti_files').split(',')
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.list_of_urls = []

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

    def __check_if_update(self, file_to_download: str) -> bool:
        """
        Check if user wants to update.
        """
        file_name_to_download = file_to_download.split('/')[-1]
        try:
            with open(self.path_to_thret_intelligence_data + file_name_to_download + '.time', 'r') as f:
                last_update = f.readlines()[0]
            last_update = float(last_update)
        except (ValueError, TypeError, FileNotFoundError, IndexError):
            last_update = float('-inf')

        now = time.time()

        if last_update + self.update_period < now:
            # Update
            return True
        return False

    def __get_e_tag_from_web(self, file_to_download) -> str:
        try:
            # We use a command in os because if we use urllib or requests the process complains!:w
            command = "curl --insecure -s -I " + file_to_download + " | grep -i etag"
            temp = os.popen(command).read()
            try:
                new_e_tag = temp.split()[1].split('\n')[0].replace("\"",'')
            except IndexError:
                new_e_tag = ''
            return new_e_tag
        except Exception as inst:
            self.print('Error with __get_e_tag_from_web()', 0, 1)
            self.print('{}'.format(type(inst)), 0, 1)
            self.print('{}'.format(inst), 0, 1)
            return ''

    def __download_file(self, url: str, path: str) -> bool:
        """
        Download file from the location specified in the url
        """
        try:
            # This replaces are to be sure that a user can not inject commands in curl
            path = path.replace(';', '')
            path = path.replace('\`', '')
            url = url.replace(';', '')
            url = url.replace('\`', '')
            command = 'curl --insecure -s ' + url + ' -o ' + path
            os.system(command)
            # Get the time of update
            self.new_update_time = time.time()
            return True
        except:
            self.print(f'An error occurred while downloading the file {url}.', 0, 1)
            return False

    def __download_malicious_ips(self, file_to_download: str) -> bool:
        try:
            file_name_to_download = file_to_download.split('/')[-1]
            # Take last e-tag of our maliciou ips file.
            try:
                with open(self.path_to_thret_intelligence_data + file_name_to_download + '.etag', 'r') as f:
                    old_e_tag = f.readlines()[0]
            except FileNotFoundError:
                # The file is not there
                old_e_tag = ''

            # Check now if E-TAG of file in github is same as downloaded
            # file here.
            new_e_tag = self.__get_e_tag_from_web(file_to_download)

            if new_e_tag and old_e_tag != new_e_tag:
                # Our malicious file is old. Download new one.
                self.print(f'Trying to download the file {file_name_to_download}', 3, 0)
                self.__download_file(file_to_download, self.path_to_thret_intelligence_data + file_name_to_download)
                # Store the new etag in the file
                # Take last e-tag of our maliciou ips file.
                with open(self.path_to_thret_intelligence_data + file_name_to_download + '.etag', 'w+') as f:
                    f.write(new_e_tag)
                # Write the last we checked the update time
                with open(self.path_to_thret_intelligence_data + file_name_to_download + '.time', 'w+') as f:
                    f.write(str(self.new_update_time))
                return True
            elif new_e_tag and old_e_tag == new_e_tag:
                self.print(f'File {file_to_download} is still the same. Not downloading the file', 3, 0)
                # Store the update time like we downloaded it anyway
                self.new_update_time = time.time()
                # Write the last we checked the update time
                with open(self.path_to_thret_intelligence_data + file_name_to_download + '.time', 'w+') as f:
                    f.write(str(self.new_update_time))
                return True
            elif not new_e_tag:
                # Something failed. Do not download
                self.print(f'Some error ocurred. Not downloading the file {file_to_download}', 0, 1)
                return False
        except Exception as inst:
            self.print('Problem on __download_malicious_ips()', 0, 0)
            self.print(str(type(inst)), 0, 0)
            self.print(str(inst.args), 0, 0)
            self.print(str(inst), 0, 0)

    def update(self) -> bool:
        """
        Main function. It tries to update the malicious file from a remote
        server
        """
        try:
            self.update_period = float(self.update_period)
        except (TypeError, ValueError):
            # User does not want to update the malicious IP list.
            self.print('Not Updating the remote file of maliciuos IPs because the user did not configure an update time.', 0, 1)
            return False

        if self.update_period <= 0:
            # User does not want to update the malicious IP list.
            self.print('Not Updating the remote file of maliciuos IPs because the update period is <= 0.', 0, 1)
            return False

        # Check if the remote file is newer than our own
        # For each file that we should update
        for file_to_download in self.list_of_urls:
            file_to_download = file_to_download.strip()
            if self.__check_if_update(file_to_download):
                self.print(f'We should update the remote file {file_to_download}', 3, 0)
                if self.__download_malicious_ips(file_to_download):
                    self.print(f'Successfully updated remote file {file_to_download}.', 3, 0)
                else:
                    self.print(f'An error occured during downloading file {file_to_download}. Updating was aborted.', 0, 1)
                    continue
            else:
                self.print(f'File {file_to_download} is up to date. No download.', 3, 0)
                continue
