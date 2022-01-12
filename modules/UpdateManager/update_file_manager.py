import configparser
import re
import time
import os
from slips_files.core.database import __database__
import json
import ipaddress
import validators
import traceback
import requests
import datetime
import sys

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
        # this will store the number of loaded ti files
        self.loaded_ti_files = 0

    def read_configuration(self):
        """ Read the configuration file for what we need """
        try:
            # update period
            self.update_period = self.config.get('threatintelligence', 'malicious_data_update_period')
            self.update_period = float(self.update_period)
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.update_period = 86400 # 1 day
        try:
            # Read the path to where to store and read the malicious files
            self.path_to_threat_intelligence_data = self.config.get('threatintelligence', 'download_path_for_remote_threat_intelligence')
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.path_to_threat_intelligence_data = 'modules/ThreatIntelligence1/remote_data_files/'
        try:
            # Read the list of URLs to download. Convert to list
            self.ti_feed_tuples = self.config.get('threatintelligence', 'ti_files').split(', ')
            # this dict will contain every link and its threat_level
            self.url_feeds = {}
            # Empty the variables so we know which ones we read already
            url, threat_level, tags= '', '', ''
            # Each tuple_ is in turn a url, threat_level and tags
            for tuple_ in self.ti_feed_tuples:
                if not url:
                    url = tuple_.replace('\n','')
                elif url.startswith(';'):
                    # remove commented lines from the cache db
                    feed = url.split('/')[-1]
                    __database__.delete_feed(feed)
                    # to avoid calling delete_feed again with the same feed
                    url = ''
                elif not threat_level:
                    threat_level = tuple_.replace('threat_level=','')
                    # make sure threat level is a valid value
                    if threat_level.lower() not in ('info', 'low', 'medium', 'high', 'critical'):
                        # not a valid threat_level
                        self.print(f"Invalid threat level found in slips.conf: {threat_level} for TI feed: {url}. Using 'low' instead.", 0,1)
                        threat_level = 'low'
                elif not tags:
                    if '\n' in tuple_:
                        # Is a combined tags+url.
                        # This is an issue with the library
                        tags = tuple_.split('\n')[0].replace('tags=','')
                        self.url_feeds[url] =  {'threat_level': threat_level, 'tags':tags[:30]}
                        url = tuple_.split('\n')[1]
                        threat_level = ''
                        tags = ''
                    else:
                        # The first line is not combined tag+url
                        tags = tuple_.replace('tags=','')
                        self.url_feeds[url] =  {'threat_level': threat_level, 'tags':tags[:30]}
            #self.print(f'Final: {self.url_feeds}')
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.url_feeds = {}

        try:
            # Read the list of ja3 feeds to download. Convert to list
            self.ja3_feed_tuples = self.config.get('threatintelligence', 'ja3_feeds').split(', ')
            self.ja3_feeds = {}
            url, threat_level, tags= '', '', ''
            for tuple_ in self.ja3_feed_tuples:
                if not url:
                    url = tuple_.replace('\n','')
                elif not threat_level:
                    threat_level = tuple_.replace('threat_level=','')
                    if threat_level.lower() not in ('info', 'low', 'medium', 'high', 'critical'):
                        # not a valid threat_level
                        self.print(f"Invalid threat level found in slips.conf: {threat_level} for TI feed: {url}. Using 'low' instead.", 0,1)
                        threat_level = 'low'
                elif not tags:
                    if '\n' in tuple_:
                        # Is a combined tags+url.
                        # This is an issue with the library
                        tags = tuple_.split('\n')[0].replace('tags=','')
                        self.ja3_feeds[url] =  {'threat_level': threat_level, 'tags':tags[:30]}
                        url = tuple_.split('\n')[0]
                        threat_level = ''
                        tags = ''
                    else:
                        # The first line is not combined tag+url
                        tags = tuple_.replace('tags=','')
                        self.ja3_feeds[url] =  {'threat_level': threat_level, 'tags':tags[:30]}
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.ja3_feeds = {}

        try:
            # Read the riskiq api key
            RiskIQ_credentials_path = self.config.get('threatintelligence', 'RiskIQ_credentials_path')
            with open(RiskIQ_credentials_path,'r') as f:
                self.riskiq_email = f.readline().replace('\n','')
                self.riskiq_key = f.readline().replace('\n','')
                if len(self.riskiq_key) != 64:
                    raise NameError
        except (configparser.NoOptionError, configparser.NoSectionError, NameError, FileNotFoundError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.riskiq_email = None
            self.riskiq_key = None

        try:
            # riskiq update period
            self.riskiq_update_period = self.config.get('threatintelligence', 'update_period')
            self.riskiq_update_period = float(self.riskiq_update_period)
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.riskiq_update_period = 604800 # 1 week

    def print(self, text, verbose=1, debug=0):
        """
        Function to use to print text using the outputqueue of slips.
        Slips then decides how, when and where to print this text by taking all the processes into account
        :param verbose:
            0 - don't print
            1 - basic operation/proof of work
            2 - log I/O operations and filenames
            3 - log database/profile/timewindow changes
        :param debug:
            0 - don't print
            1 - print exceptions
            2 - unsupported and unhandled types (cases that may cause errors)
            3 - red warnings that needs examination - developer warnings
        :param text: text to print. Can include format like 'Test {}'.format('here')
        """

        levels = f'{verbose}{debug}'
        self.outputqueue.put(f"{levels}|{self.name}|{text}")

    def __check_if_update(self, file_to_download: str) -> bool:
        """
        Check if user wants to update.
        """
        file_name_to_download = file_to_download.split('/')[-1]
        # Get last timeupdate of the file
        data = __database__.get_TI_file_info(file_name_to_download)
        try:
            last_update = data['time']
            last_update = float(last_update)
        except (TypeError,KeyError):
            last_update = float('-inf')

        now = time.time()

        # check which update period to use based on the file
        if 'risk' in file_to_download:
            update_period = self.riskiq_update_period
        else:
            update_period = self.update_period

        if last_update + update_period < now:
            # Update
            return True
        return False

    def get_e_tag_from_web(self, file_to_download):
        try:
            # We use a command in os because if we use urllib or requests the process complains!:w
            # If the webpage does not answer in 10 seconds, continue
            command = "curl -m 10 --insecure -s -I " + file_to_download + " | grep -i etag"
            temp = os.popen(command).read()
            try:
                new_e_tag = temp.split()[1].split('\n')[0].replace("\"",'')
                return new_e_tag
            except IndexError:
                self.print(f"File {file_to_download} doesn't have an e-tag")
                return False
        except Exception as inst:
            self.print('Error with get_e_tag_from_web()', 0, 1)
            self.print('{}'.format(type(inst)), 0, 1)
            self.print('{}'.format(inst), 0, 1)
            return False

    def download_file(self, url: str, filepath: str) -> bool:
        """
        Download file from the url and save to filepath
        """
        try:
            # This replaces are to be sure that a user can not inject commands in curl
            filepath = filepath.replace(';', '')
            filepath = filepath.replace('\`', '')
            filepath = filepath.replace('&', '')
            filepath = filepath.replace('|', '')
            filepath = filepath.replace('$(', '')
            filepath = filepath.replace('\n', '')
            url = url.replace(';', '')
            url = url.replace('\`', '')
            url = url.replace('&', '')
            url = url.replace('|', '')
            url = url.replace('$(', '')
            url = url.replace('\n', '')
            command = 'curl -m 10 --insecure -s ' + url + ' -o ' + filepath
            self.print(f'Downloading with curl command: {command}', 0, 3)
            # If the command is successful
            if os.system(command) == 0:
                # Get the time of update
                self.new_update_time = time.time()
                return True
            else:
                self.print(f'An error occurred while downloading the file {url}.', 0, 1)
                return False
        except Exception as e:
            self.print(f'An error occurred while downloading the file {url}.', 0, 1)
            self.print(f'Error: {e}', 0, 1)
            return False

    def download_malicious_file(self, link_to_download: str) -> bool:
        """
        Compare the e-tag of link_to_download in our database with the e-tag of this file and download if they're different
        Doesn't matter if it's a ti_feed or JA3 feed
        """
        try:
            # Check that the folder exist
            if not os.path.isdir(self.path_to_threat_intelligence_data):
                os.mkdir(self.path_to_threat_intelligence_data)

            file_name_to_download = link_to_download.split('/')[-1]
            # Get what files are stored in cache db and their E-TAG to compare with current files
            data = __database__.get_TI_file_info(file_name_to_download)
            old_e_tag = data.get('e-tag', '')
            # Check now if E-TAG of file in github is same as downloaded
            # file here.
            new_e_tag = self.get_e_tag_from_web(link_to_download)
            if new_e_tag and old_e_tag != new_e_tag:
                # Our malicious file is old. Download new one.
                self.print(f'Trying to download the file {file_name_to_download}', 3, 0)
                if not self.download_file(link_to_download, self.path_to_threat_intelligence_data + '/' + file_name_to_download):
                    return False
                if old_e_tag:
                    # File is updated and was in database. Delete previous IPs of this file.
                    self.__delete_old_source_data_from_database(file_name_to_download)

                # ja3 files and ti_files are parsed differently, check which file is this
                path = f'{self.path_to_threat_intelligence_data}/{file_name_to_download}'
                # is it ja3 feed?
                # Not sure if this is working with the new dict format. check
                if link_to_download in self.ja3_feeds \
                        and not self.parse_ja3_feed(link_to_download, path):
                    return False

                # is it a ti_file? load updated IPs to the database
                # Not sure if this is working with the new dict format. check
                if link_to_download in self.url_feeds \
                        and not self.parse_ti_feed(link_to_download, path):
                    # an error occured
                    return False

                # Store the new etag and time of file in the database
                malicious_file_info = {}
                malicious_file_info['e-tag'] = new_e_tag
                malicious_file_info['time'] = self.new_update_time
                __database__.set_TI_file_info(file_name_to_download, malicious_file_info)
                return True
            elif new_e_tag and old_e_tag == new_e_tag:
                self.print(f'File {link_to_download} is still the same. Not downloading the file', 3, 0)
                # Store the update time like we downloaded it anyway
                self.new_update_time = time.time()
                # Store the new etag and time of file in the database
                malicious_file_info = {}
                malicious_file_info['e-tag'] = new_e_tag
                malicious_file_info['time'] = self.new_update_time
                __database__.set_TI_file_info(file_name_to_download, malicious_file_info)
                return True
            elif not new_e_tag:
                # Something failed. Do not download
                self.print(f'Some error ocurred. Not downloading the file {link_to_download}', 0, 1)
                return False

        except Exception as inst:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(f'Problem on download_malicious_file() line {exception_line}', 0, 0)
            self.print(str(type(inst)), 0, 0)
            self.print(str(inst.args), 0, 0)
            self.print(str(inst), 0, 0)

    def update_riskiq_feed(self):
        """ Get and parse RiskIQ feed """
        try:
            base_url = 'https://api.riskiq.net/pt'
            path = '/v2/articles/indicators'
            url = base_url + path
            auth = (self.riskiq_email, self.riskiq_key)
            today = datetime.date.today()
            days_ago = datetime.timedelta(7)
            a_week_ago = today - days_ago
            data = {'startDateInclusive': a_week_ago.strftime("%Y-%m-%d"),
                    'endDateExclusive': today.strftime("%Y-%m-%d")}
            # Specifying json= here instead of data= ensures that the
            # Content-Type header is application/json, which is necessary.
            response = requests.get(url, auth=auth ,json=data).json()
            # extract domains only from the response
            try:
                response = response['indicators']
                for indicator in response:
                    # each indicator is a dict
                    malicious_domains_dict = {}
                    if indicator.get('type','') == 'domain':
                        domain = indicator['value']
                        malicious_domains_dict[domain] = json.dumps({'description': 'malicious domain detected by RiskIQ', 'source':url})
                        __database__.add_domains_to_IoC(malicious_domains_dict)
            except KeyError:
                self.print(f'RiskIQ returned: {response["message"]}. Update Cancelled.')
                return False

            # update the timestamp in the db
            malicious_file_info = {'time': time.time()}
            __database__.set_TI_file_info('riskiq_domains', malicious_file_info)
            return True
        except Exception as e:
            self.print(f'An error occurred while updating RiskIQ feed.', 0, 1)
            self.print(f'Error: {e}', 0, 1)
            return False

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

        self.print('Checking if we need to download TI files.')
        # Check if the remote file is newer than our own
        # For each file that we should update
        files_to_download_dics = {}
        files_to_download_dics.update(self.url_feeds)
        files_to_download_dics.update(self.ja3_feeds)
        for file_to_download in files_to_download_dics.keys():
            file_to_download = file_to_download.strip()
            if self.__check_if_update(file_to_download):
                self.print(f'We should update the remote file {file_to_download}', 1, 0)
                if self.download_malicious_file(file_to_download):
                    self.print(f'Successfully updated remote file {file_to_download}.', 1, 0)
                    self.loaded_ti_files +=1
                else:
                    self.print(f'An error occurred during downloading file {file_to_download}. Updating was aborted.', 0, 1)
                    continue
            else:
                self.print(f'File {file_to_download} is up to date. No download.', 3, 0)
                self.loaded_ti_files +=1
                continue
        self.print(f'{self.loaded_ti_files} TI files successfully loaded.')
        # in case of riskiq files, we don't have a link for them in ti_files, We update these files using their API
        # check if we have a username and api key and a week has passed since we last updated
        if self.riskiq_email and self.riskiq_key and self.__check_if_update('riskiq_domains'):
            self.print(f'We should update RiskIQ domains', 1, 0)
            if self.update_riskiq_feed():
                self.print('Successfully updated RiskIQ domains.', 1, 0)
            else:
                self.print(f'An error occurred while updating RiskIQ domains. Updating was aborted.', 0, 1)
        time.sleep(0.5)
        print('-'*27)

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
        for domain_data in all_data.items():
            domain = domain_data[0]
            data = json.loads(domain_data[1])
            if data["source"] == file:
                old_data.append(domain)
        if old_data:
            __database__.delete_domains_from_IoC_domains(old_data)

    def __delete_old_source_data_from_database(self, data_file):
        '''
        Delete old IPs of the source from the database.
        :param data_file: the name of source to delete old IPs from.
        '''
        # Only read the files with .txt or .csv
        self.__delete_old_source_IPs(data_file)
        self.__delete_old_source_Domains(data_file)

    def parse_ja3_feed(self, url, ja3_feed_path: str) -> bool:
        """
        Read all ja3 fingerprints in ja3_feed_path and store the info in our db
        :param url: this is the src feed
        :param ja3_feed_path: the file path where a ja3 feed is downloaded
        """

        try:
            malicious_ja3_dict = {}

            with open(ja3_feed_path) as ja3_feed:
                # Ignore comments and find the description column if possible
                description_column = None
                while True:
                    line = ja3_feed.readline()
                    if line.startswith('# ja3_md5') :
                        # looks like the line that contains column names, search where is the description column
                        for column in line.split(','):
                            # Listingreason is the description column in  abuse.ch Suricata JA3 Fingerprint Blacklist
                            if 'Listingreason' in column.lower():
                                description_column = line.split(',').index(column)
                    if not line.startswith('#'):
                        # break while statement if it is not a comment (i.e. does not startwith #) or a header line
                        break

                # Find in which column is the ja3 fingerprint in this file

                # Store the current position of the TI file
                current_file_position = ja3_feed.tell()
                if ',' in line:
                    data = line.replace("\n","").replace("\"","").split(",")
                    amount_of_columns = len(line.split(","))

                if description_column is None:
                    # assume it's the last column
                    description_column = amount_of_columns - 1

                # Search the first column that is an IPv4, IPv6 or domain
                for column in range(amount_of_columns):
                    # Check if the ja3 fingerprint is valid.
                    # assume this column is the ja3 field
                    ja3 = data[column]
                    # verify
                    if len(ja3) != 32:
                        ja3_column = None
                    else:
                        # we found the column that has ja3 info
                        ja3_column = column
                        break

                if ja3_column is None:
                    # can't find a column that contains an ioc
                    self.print(f'Error while reading the ja3 file {ja3_feed_path}. Could not find a column with JA3 info', 1, 1)
                    return False

                # Now that we read the first line, go back so we can process it
                ja3_feed.seek(current_file_position)

                for line in ja3_feed:
                    # The format of the file should be
                    # 8f52d1ce303fb4a6515836aec3cc16b1,2017-07-15 19:05:11,2019-07-27 20:00:57,TrickBot

                    # skip comment lines
                    if line.startswith('#'): continue

                    # Separate the lines like CSV, either by commas or tabs
                    # In the new format the ip is in the second position.
                    # And surronded by "

                    # get the ja3 to store in our db
                    if ',' in line:
                        ja3 = line.replace("\n", "").replace("\"", "").split(",")[ja3_column].strip()

                    # get the description of this ja3 to store in our db
                    try:
                        if ',' in line:
                            description = line.replace("\n", "").replace("\"", "").split(",")[description_column].strip()
                        else:
                            description = line.replace("\n", "").replace("\"", "").split("\t")[description_column].strip()
                    except IndexError:
                        self.print(f'IndexError Description column: {description_column}. Line: {line}')

                    # self.print('\tRead Data {}: {}'.format(ja3, description))

                    filename = ja3_feed_path.split('/')[-1]

                    # Check if the data is a valid IPv4, IPv6 or domain
                    if len(ja3) == 32:
                        # Store the ja3 in our local dict
                        malicious_ja3_dict[ja3] = json.dumps({'description': description, 'source':filename,
                                                              'threat_level': self.ja3_feeds[url]['threat_level'],
                                                              'tags': self.ja3_feeds[url]['tags'] })
                    else:
                        self.print('The data {} is not valid. It was found in {}.'.format(data, filename), 3, 3)
                        continue

            # Add all loaded malicious ja3 to the database
            __database__.add_ja3_to_IoC(malicious_ja3_dict)
            return True

        except KeyboardInterrupt:
            return False
        except Exception as inst:
            self.print('Problem in parse_ja3_feed()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            print(traceback.format_exc())
            return False

    def detect_data_type(self, data):
        """ Detects if incoming data is ipv4, ipv6 or domain """
        # Check if the data is a valid IPv4, IPv6 or domain
        try:
            ip_address = ipaddress.IPv4Address(data)
            # Is IPv4!
            return ip_address
        except ipaddress.AddressValueError:
            # Is it ipv6?
            try:
                ip_address = ipaddress.IPv6Address(data)
                # Is IPv6!
                return ip_address
            except ipaddress.AddressValueError:
                # It does not look as IP address.
                # So it should be a domain
                if validators.domain(data):
                    domain = data
                    return 'domain'
                else:
                    # unknown
                    return None
                    # self.print('The data {} is not valid. It was found in {}.'.format(data, malicious_data_path), 3, 3)

    def parse_ti_feed(self, link_to_download, malicious_data_path: str) -> bool:
        """
        Read all the files holding IP addresses and a description and put the
        info in a large dict.
        This also helps in having unique ioc across files
        :param link_to_download: this link that has the IOCs we're currently parsing, used for getting the threat_level
        :param malicious_data_path: this is the path where the saved file from the link is downloaded
        """

        try:

            # Check if the file has any content
            filesize = os.path.getsize(malicious_data_path)
            if filesize == 0:
                return False

            malicious_ips_dict = {}
            malicious_domains_dict = {}
            with open(malicious_data_path) as malicious_file:
                self.print('Reading next lines in the file {} for IoC'.format(malicious_data_path), 3, 0)
                # to support nsec/full-results-2019-05-15.json
                if 'json' in malicious_data_path:
                    filename= malicious_data_path.split('/')[-1]
                    try:
                        file = json.loads(malicious_file.read())
                        for description,iocs in file.items():
                            # iocs is a list of dicts
                            for ioc in iocs:
                                # ioc is a dict with keys 'IP', 'ports', 'domains'
                                # process IPs
                                ip = ioc.get('IP','')
                                # verify its a valid ip
                                try:
                                    ip_address = ipaddress.IPv4Address(ip.strip())
                                except ipaddress.AddressValueError:
                                    # Is it ipv6?
                                    try:
                                        ip_address = ipaddress.IPv6Address(ip.strip())
                                    except ipaddress.AddressValueError:
                                        # not a valid IP
                                        continue
                                malicious_ips_dict[ip] = json.dumps({'description': description, 'source':filename})
                                # process domains
                                domains = ioc.get('domains',[])
                                for domain in domains:
                                    if validators.domain(domain.strip()):
                                        # this is a valid domain
                                        malicious_domains_dict[domain] = json.dumps({'description': description, 'source':filename})
                        # Add all loaded malicious ips to the database
                        __database__.add_ips_to_IoC(malicious_ips_dict)
                        # Add all loaded malicious domains to the database
                        __database__.add_domains_to_IoC(malicious_domains_dict)
                        return True
                    except json.decoder.JSONDecodeError:
                        # not a json file??
                        return False

                # Remove comments and find the description column if possible
                description_column = None
                # if any keyword of the following is present in a line
                # then this line should be ignored by slips
                # either a not supported ioc type or a header line etc.
                # make sure the header keywords are lowercase because
                # we convert lines to lowercase when comparing
                header_keywords = ('type', 'first_seen_utc', 'ip_v4','"domain"','#"type"','#fields', "number")
                ignored_IoCs = ('email', 'url', 'file_hash')

                while True:
                    line = malicious_file.readline()
                    if not line:
                        break
                    # Try to find the line that has column names
                    for keyword in header_keywords:
                        if line.startswith(keyword):
                            # looks like the column names, search where is the description column
                            for column in line.split(','):
                                if column.lower().startswith('desc') \
                                        or 'malware' in column \
                                        or 'tags_str' in column \
                                        or 'collect' in column:
                                    description_column = line.split(',').index(column)
                                    break

                    # make sure the next line is not a header, a comment or an unsupported IoC type
                    process_line = True
                    if line.startswith('#') or line.isspace() or len(line) < 3: continue
                    for keyword in header_keywords + ignored_IoCs:
                        if keyword in line.lower():
                            # we should ignore this line
                            process_line = False
                            break

                    if process_line:
                        break

                # Find in which column is the important info in this TI file (domain or ip)
                # Store the current position of the TI file
                current_file_position = malicious_file.tell()
                # temp_line = malicious_file.readline()
                if '#' in line:
                    # some files like alienvault.com/reputation.generic have comments next to ioc
                    data = line.replace("\n","").replace("\"","").split("#")
                    amount_of_columns =  len(line.split("#"))
                elif ',' in line:
                    data = line.replace("\n","").replace("\"","").split(",")
                    amount_of_columns = len(line.split(","))
                elif '0.0.0.0 ' in line:
                    # anudeepND/blacklist file
                    data = [line[line.index(' ')+1:].replace("\n","")]
                    amount_of_columns = 1
                else:
                    data = line.replace("\n","").replace("\"","").split("\t")
                    # lines are not comma separated like ipsum files, try tabs
                    amount_of_columns = len(line.split('\t'))

                if description_column is None:
                    # assume it's the last column
                    description_column = amount_of_columns - 1

                # Search the first column that is an IPv4, IPv6 or domain
                for column in range(amount_of_columns):
                    # Check if ip is valid.
                    try:
                        ip_address = ipaddress.IPv4Address(data[column].strip())
                        # Is IPv4! let go
                        data_column = column
                        self.print(f'The data is on column {column} and is ipv4: {ip_address}', 2, 0)
                        break
                    except ipaddress.AddressValueError:
                        # Is it ipv6?
                        try:
                            ip_address = ipaddress.IPv6Address(data[column].strip())
                            # Is IPv6! let go
                            data_column = column
                            self.print(f'The data is on column {column} and is ipv6: {ip_address}', 0, 2)
                            break
                        except ipaddress.AddressValueError:
                            # It does not look like an IP address.
                            # So it should be a domain
                            # some ti files have / at the end of domains, remove it
                            if data[column].endswith('/'):
                                data[column] = data[column][:-1]
                            domain =  data[column]
                            if domain.startswith('http://'): data[column]= data[column][7:]
                            if domain.startswith('https://'): data[column]= data[column][8:]

                            if validators.domain(data[column].strip()):
                                data_column = column
                                self.print(f'The data is on column {column} and is domain: {data[column]}', 0, 6)
                                break
                            elif "/" in data[column]:
                                # this file contains one column that has network ranges and ips
                                data_column = column
                            else:
                                # Some string that is not a domain
                                data_column = None

                if data_column is None:
                    # can't find a column that contains an ioc
                    self.print(f'Error while reading the TI file {malicious_data_path}. Could not find a column with an IP or domain', 0, 1)
                    return False

                # Now that we read the first line, go back so we can process it
                malicious_file.seek(current_file_position)

                for line in malicious_file:
                    # The format of the file should be
                    # "0", "103.15.53.231","90", "Karel from our village. He is bad guy."
                    # So the second column will be used as important data with
                    # an IP or domain
                    # In the case of domains can be
                    # domain,www.netspy.net,NetSpy

                    # skip comment lines
                    if line.startswith('#')\
                            or 'FILE_HASH' in line\
                            or 'EMAIL' in line or 'URL' in line:
                        continue

                    # Separate the lines like CSV, either by commas or tabs
                    # In the new format the ip is in the second position.
                    # And surronded by "
                    if '#' in line:
                        data = line.replace("\n", "").replace("\"", "").split("#")[data_column].strip()
                    elif ',' in line:
                        data = line.replace("\n", "").replace("\"", "").split(",")[data_column].strip()
                    elif '0.0.0.0 ' in line:
                        # anudeepND/blacklist file
                        data = line[line.index(' ')+1:].replace("\n","")
                    else:
                        data = line.replace("\n", "").replace("\"", "").split("\t")[data_column].strip()

                    if '/' in data or data in ('','\n'):
                        # this is probably a range of ips (subnet) or a new line, we don't support that. read the next line
                        continue

                    # get the description of this line
                    try:
                        if '#' in line:
                            description = line.replace("\n", "").replace("\"", "").split("#")[description_column].strip()
                        elif ',' in line:
                            description = line.replace("\n", "").replace("\"", "").split(",")[description_column].strip()
                        else:
                            description = line.replace("\n", "").replace("\"", "").split("\t")[description_column].strip()
                    except IndexError:
                        self.print(f'IndexError Description column: {description_column}. Line: {line}',0,1)

                    self.print('\tRead Data {}: {}'.format(data, description), 3, 0)

                    data_file_name = malicious_data_path.split('/')[-1]

                    # if we have info about data, append to it, if we don't add a new entry in the correct dict
                    data_type = self.detect_data_type(data)
                    if data_type == None:
                        self.print('The data {} is not valid. It was found in {}.'.format(data, malicious_data_path), 0, 1)
                        continue
                    if data_type == 'domain':
                        try:
                            # we already have info about this domain?
                            old_domain_info = json.loads(malicious_domains_dict[str(data)] )
                            # if the domain appeared twice in the same blacklist, don't add the blacklist name twice
                            # or calculate the max threat_level
                            if data_file_name not in old_domain_info['source']:
                                # append the new blacklist name to the current one
                                source = f'{old_domain_info["source"]}, {data_file_name}'
                                # append the new tag to the current tag
                                tags = f'{old_domain_info["tags"]}, {self.url_feeds[link_to_download]["tags"]}'
                                # the new threat_level is the maximum threat_level
                                threat_level = str(max(float(old_domain_info['threat_level']), float(self.url_feeds[link_to_download]['threat_level'])))
                                # Store the ip in our local dict
                                malicious_domains_dict[str(data)] = json.dumps({'description': old_domain_info['description'],
                                                                                'source':source,
                                                                                'threat_level':threat_level,
                                                                                'tags':tags })
                        except KeyError:
                            # We don't have info about this domain, Store the ip in our local dict
                            malicious_domains_dict[str(data)] = json.dumps({'description': description,
                                                                                  'source':data_file_name,
                                                                                  'threat_level':self.url_feeds[link_to_download]['threat_level'],
                                                                                'tags': self.url_feeds[link_to_download]['tags']})
                    else:
                        try:
                            # we already have info about this ip?
                            old_ip_info = json.loads(malicious_ips_dict[str(data)])
                            # if the IP appeared twice in the same blacklist, don't add the blacklist name twice
                            # or calculate the max threat_level
                            if data_file_name not in old_ip_info['source']:
                                # append the new blacklist name to the current one
                                source = f'{old_ip_info["source"]}, {data_file_name}'
                                # append the new tag to the old tag
                                tags = f'{old_ip_info["tags"]}, {self.url_feeds[link_to_download]["tags"]}'
                                # the new threat_level is the max of the 2
                                threat_level = str(max(int(old_ip_info['threat_level']), int(self.url_feeds[link_to_download]['threat_level'])))
                                malicious_ips_dict[str(data)] = json.dumps({'description': old_ip_info['description'],
                                                                                'source':source,
                                                                                'threat_level':threat_level,
                                                                                'tags': tags})
                                # print(f'Dulicate ip {data} found in sources: {source} old threat_level: {ip_info["threat_level"]}

                        except KeyError:
                            # We don't have info about this IP, Store the ip in our local dict
                            malicious_ips_dict[str(data)] = json.dumps({'description': description,
                                                                          'source':data_file_name,
                                                                          'threat_level':self.url_feeds[link_to_download]['threat_level'],
                                                                        'tags': self.url_feeds[link_to_download]['tags']})
            # Add all loaded malicious ips to the database
            __database__.add_ips_to_IoC(malicious_ips_dict)
            # Add all loaded malicious domains to the database
            __database__.add_domains_to_IoC(malicious_domains_dict)
            return True
        except KeyboardInterrupt:
            return False
        except Exception as inst:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(f'Problem on the __load_malicious_datafile() line {exception_line}', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            print(traceback.format_exc())
            return False
