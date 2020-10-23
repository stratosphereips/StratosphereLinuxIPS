import configparser
import time
import os
from slips.core.database import __database__
import json
import ipaddress
import validators
import traceback

class UpdateFileManager:

    def __init__(self, outputqueue, config):
        self.outputqueue = outputqueue
        self.config = config
        # For now, read the malicious IPs from here
        self.name = 'UpdateManager'
        self.new_update_time = float('-inf')
        # Start the database
        __database__.start(self.config)
        # Get a separator from the database
        self.separator = __database__.getFieldSeparator()
        # Read the conf
        self.read_configuration()

    def read_configuration(self):
        """ Read the configuration file for what we need """
        try:
            # update period
            self.update_period = self.config.get('threatintelligence', 'malicious_data_update_period')
            self.update_period = float(self.update_period)
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.update_period = 86400
        try:
            # Read the path to where to store and read the malicious files
            self.path_to_threat_intelligence_data = self.config.get('threatintelligence', 'malicious_ip_file_path')
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.path_to_threat_intelligence_data = 'modules/ThreatIntelligence1/malicious_data_files/'
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
        # Get last timeupdate of the file
        data = __database__.get_malicious_file_info(file_name_to_download)
        try:
            last_update = data['time']
            last_update = float(last_update)
        except TypeError:
            last_update = float('-inf')

        now = time.time()
        if last_update + self.update_period < now:
            # Update
            return True
        return False

    def __get_e_tag_from_web(self, file_to_download) -> str:
        try:
            # We use a command in os because if we use urllib or requests the process complains!:w
            # If the webpage does not answer in 10 seconds, continue
            command = "curl -m 10 --insecure -s -I " + file_to_download + " | grep -i etag"
            temp = os.popen(command).read()
            try:
                new_e_tag = temp.split()[1].split('\n')[0].replace("\"",'')
                return new_e_tag
            except IndexError:
                return False
        except Exception as inst:
            self.print('Error with __get_e_tag_from_web()', 0, 1)
            self.print('{}'.format(type(inst)), 0, 1)
            self.print('{}'.format(inst), 0, 1)
            return False

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
        except Exception as e:
            self.print(f'An error occurred while downloading the file {url}.', 0, 1)
            self.print(f'Error: {e}')
            return False

    def __download_malicious_file(self, file_to_download: str) -> bool:
        try:
            file_name_to_download = file_to_download.split('/')[-1]
            # Get what files are stored in cache db and their E-TAG to comapre with current files
            data = __database__.get_malicious_file_info(file_name_to_download)
            try:
                old_e_tag = data['e-tag']
            except TypeError:
                old_e_tag = ''
            # Check now if E-TAG of file in github is same as downloaded
            # file here.
            new_e_tag = self.__get_e_tag_from_web(file_to_download)
            if new_e_tag and old_e_tag != new_e_tag:
                # Our malicious file is old. Download new one.
                self.print(f'Trying to download the file {file_name_to_download}', 3, 0)
                self.__download_file(file_to_download, self.path_to_threat_intelligence_data + file_name_to_download)

                if old_e_tag:
                    # File is updated and was in database. Delete previous IPs of this file.
                    self.__delete_old_source_data_from_database(file_name_to_download)
                # Load updated IPs to the database
                self.__load_malicious_datafile(self.path_to_threat_intelligence_data + '/' + file_name_to_download, file_name_to_download)
                # Store the new etag and time of file in the database
                malicious_file_info = {}
                malicious_file_info['e-tag'] = new_e_tag
                malicious_file_info['time'] = self.new_update_time
                __database__.set_malicious_file_info(file_name_to_download, malicious_file_info)

                return True
            elif new_e_tag and old_e_tag == new_e_tag:
                self.print(f'File {file_to_download} is still the same. Not downloading the file', 3, 0)
                # Store the update time like we downloaded it anyway
                self.new_update_time = time.time()
                # Store the new etag and time of file in the database
                malicious_file_info = {}
                malicious_file_info['e-tag'] = new_e_tag
                malicious_file_info['time'] = self.new_update_time
                __database__.set_malicious_file_info(file_name_to_download, malicious_file_info)
                return False
            elif not new_e_tag:
                # Something failed. Do not download
                self.print(f'Some error ocurred. Not downloading the file {file_to_download}', 0, 1)
                return False

        except Exception as inst:
            self.print('Problem on __download_malicious_file()', 0, 0)
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
            self.print('Not Updating the remote file of maliciuos IPs and domains because the user did not configure an update time.', 0, 1)
            return False

        if self.update_period <= 0:
            # User does not want to update the malicious IP list.
            self.print('Not Updating the remote file of maliciuos IPs and domains because the update period is <= 0.', 0, 1)
            return False

        # Check if the remote file is newer than our own
        # For each file that we should update
        for file_to_download in self.list_of_urls:
            file_to_download = file_to_download.strip()
            if self.__check_if_update(file_to_download):
                self.print(f'We should update the remote file {file_to_download}', 3, 0)
                if self.__download_malicious_file(file_to_download):
                    self.print(f'Successfully updated remote file {file_to_download}.', 3, 0)
                else:
                    self.print(f'An error occured during downloading file {file_to_download}. Updating was aborted.', 0, 1)
                    continue
            else:
                self.print(f'File {file_to_download} is up to date. No download.', 3, 0)
                continue


    def __delete_old_source_IPs(self, file):
        """
        When file is updated, delete the old IPs in the cache
        """
        all_data = __database__.get_IPs_in_IoC()
        old_data = []
        for ip_data in all_data.items():
            ip = ip_data[0]
            data = json.loads(ip_data[1])
            if data["source"] == file:
                old_data.append(ip)
        if old_data:
            __database__.delete_ips_from_IoC_ips(old_data)

    def __delete_old_source_Domains(self, file):
        """
        When file is updated, delete the old Domains in the cache
        """
        all_data = __database__.get_Domains_in_IoC()
        old_data = []
        for ip_data in all_data.items():
            ip = ip_data[0]
            data = json.loads(ip_data[1])
            if data["source"] == file:
                old_data.append(ip)
        if old_data:
            __database__.delete_domains_from_IoC_ips(old_data)

    def __delete_old_source_data_from_database(self, data_file):
        '''
        Delete old IPs of the source from the database.
        :param data_file: the name of source to delete old IPs from.
        '''
        # Only read the files with .txt or .csv
        self.__delete_old_source_IPs(data_file)
        self.__delete_old_source_Domains(data_file)

    def __load_malicious_datafile(self, malicious_data_path: str, data_file_name) -> None:
        """
        Read all the files holding IP addresses and a description and put the
        info in a large dict.
        This also helps in having unique ioc accross files
        Returns nothing, but the dictionary should be filled
        """
        try:
            malicious_ips_dict = {}
            malicious_domains_dict = {}
            with open(malicious_data_path) as malicious_file:

                self.print('Reading next lines in the file {} for IoC'.format(malicious_data_path), 3, 0)

                # Remove comments
                while True:
                    line = malicious_file.readline()
                    # break while statement if it is not a comment line
                    # i.e. does not startwith #
                    if not line.startswith('#'):
                        break

                for line in malicious_file:
                    # The format of the file should be
                    # "0", "103.15.53.231","90", "Karel from our village. He is bad guy."
                    # So the second column will be used as important data with
                    # an IP or domain
                    # In the case of domains can be
                    # domain,www.netspy.net,NetSpy

                    # Separate the lines like CSV
                    # In the new format the ip is in the second position.
                    # And surronded by "
                    data = line.replace("\n","").replace("\"","").split(",")[1].strip()

                    try:
                        # In the new format the description is position 4
                        description = line.replace("\n","").replace("\"","").split(",")[3].strip()
                    except IndexError:
                        description = ''
                    self.print('\tRead Data {}: {}'.format(data, description), 6, 0)

                    # Check if ip is valid.
                    try:
                        ip_address = ipaddress.IPv4Address(data)
                        # Is IPv4!
                        # Store the ip in our local dict
                        malicious_ips_dict[str(ip_address)] = json.dumps({'description': description, 'source':data_file_name})
                    except ipaddress.AddressValueError:
                        # Is it ipv6?
                        try:
                            ip_address = ipaddress.IPv6Address(data)
                            # Is IPv6!
                            # Store the ip in our local dict
                            malicious_ips_dict[str(ip_address)] = json.dumps({'description': description, 'source':data_file_name})
                        except ipaddress.AddressValueError:
                            # It does not look as IP address.
                            # So it should be a domain
                            if validators.domain(data):
                                domain = data
                                # Store the ip in our local dict
                                malicious_domains_dict[str(domain)] = json.dumps({'description': description, 'source':data_file_name})
                            else:
                                self.print('The data {} is not valid. It was found in {}.'.format(data, malicious_data_path), 1, 1)
                                continue
            # Add all loaded malicious ips to the database
            __database__.add_ips_to_IoC(malicious_ips_dict)
            # Add all loaded malicious domains to the database
            __database__.add_domains_to_IoC(malicious_domains_dict)
        except KeyboardInterrupt:
            return True
        except Exception as inst:
            self.print('Problem on the __load_malicious_datafile()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            print(traceback.format_exc())
            return True
