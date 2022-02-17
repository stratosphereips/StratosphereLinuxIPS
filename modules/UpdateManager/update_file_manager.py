import configparser
import time
import os
from slips_files.core.database import __database__
from slips_files.common.slips_utils import utils
import json
import ipaddress
import validators
import traceback
import requests
import datetime
import sys
import asyncio

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
            self.path_to_threat_intelligence_data = self.sanitize(self.path_to_threat_intelligence_data)
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.path_to_threat_intelligence_data = 'modules/ThreatIntelligence1/remote_data_files/'
        if not os.path.exists(self.path_to_threat_intelligence_data):
            os.mkdir(self.path_to_threat_intelligence_data)

        try:
            # Read the list of URLs to download. Convert to list
            self.ti_feed_tuples = self.config.get('threatintelligence', 'ti_files').split(', ')
            self.url_feeds = self.get_feed_properties(self.ti_feed_tuples)
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.url_feeds = {}

        try:
            # Read the list of ja3 feeds to download. Convert to list
            self.ja3_feed_tuples = self.config.get('threatintelligence', 'ja3_feeds').split(', ')
            self.ja3_feeds = self.get_feed_properties(self.ja3_feed_tuples)
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.ja3_feeds = {}

        try:
            # Read the list of ja3 feeds to download. Convert to list
            self.ssl_feed_tuples = self.config.get('threatintelligence', 'ssl_feeds').split(', ')
            self.ssl_feeds = self.get_feed_properties(self.ssl_feed_tuples)
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.ssl_feeds = {}

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

    def get_feed_properties(self, feeds):
        """
        Parse links, threat level and tags from slips.conf
        """
        # this dict will contain every link and its threat_level
        url_feeds = {}
        # Empty the variables so we know which ones we read already
        url, threat_level, tags= '', '', ''
        # Each tuple_ is in turn a url, threat_level and tags
        for tuple_ in feeds:
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
                    url_feeds[url] =  {'threat_level': threat_level, 'tags':tags[:30]}
                    url = tuple_.split('\n')[1]
                    threat_level = ''
                    tags = ''
                else:
                    # The first line is not combined tag+url
                    tags = tuple_.replace('tags=','')
                    url_feeds[url] = {'threat_level': threat_level, 'tags':tags[:30]}
        return url_feeds

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

    def read_ports_info(self, ports_info_filepath):
        """
        Reads port info from slips_files/ports_info/ports_used_by_specific_orgs.csv
        and store it in the db
        """

        # there are ports that are by default considered unknown to slips,
        # but if it's known to be used by a specific organization, slips won't consider it 'unknown'.
        # in ports_info_filepath  we have a list of organizations range/ip and the port it's known to use

        with open(ports_info_filepath,'r') as f:
            line_number = 0
            while True:
                line = f.readline()
                line_number +=1
                # reached the end of file
                if not line: break
                # skip the header and the comments at the begining
                if line.startswith('#') or line.startswith('"Organization"'):
                    continue
                line = line.split(',')
                try:
                    organization, ip = line[0], line[1]
                    portproto = f'{line[2]}/{line[3].lower().strip()}'
                    __database__.set_organization_of_port(organization, ip, portproto)
                except IndexError:
                    self.print(f"Invalid line: {line} line number: {line_number} in {ports_info_filepath}. Skipping.",0,1)
                    continue

    def update_local_file(self, file_path) -> bool:
        """
        Return True if update was successfull
        """
        try:
            # each file is updated differently

            if 'ports_used_by_specific_orgs.csv' in file_path:
                self.read_ports_info(file_path)

            elif 'services.csv' in file_path:
                with open(file_path, 'r') as f:
                    for line in f:
                        name = line.split(',')[0]
                        port = line.split(',')[1]
                        proto = line.split(',')[2]
                        # descr = line.split(',')[3]
                        __database__.set_port_info(str(port)+'/'+proto, name)

            # Store the new hash of file in the database
            file_info = { 'hash': self.new_hash }
            __database__.set_TI_file_info(file_path, file_info)
            return True

        except OSError:
            return False

    def __check_if_update_local_file(self, file_path: str) -> bool:
        """
        Decides whether to update or not based on the file hash.
        Used for local files that are updated if the contents of the file hash changed
        """

        # compute file sha256 hash
        new_hash = utils.get_hash_from_file(file_path)

        # Get last hash of the file stored in the database
        file_info = __database__.get_TI_file_info(file_path)
        old_hash = file_info.get('hash', False)

        if not old_hash:
            # the file is not in our db, first time seeing it, we should update
            self.new_hash = new_hash
            return True

        elif old_hash == new_hash:
            # The 2 hashes are identical. File is up to date.
            return False

        elif old_hash != new_hash:
            # File was changed. Load the new one
            # this will be used for storing the new hash
            # in the db once the update is done
            self.new_hash =  new_hash
            return True

    def download_file(self, file_to_download):

        # Retry 3 times to get the TI file if an error occured
        for _try in range(3):
            try:
                response = requests.get(file_to_download,  timeout=10)
                if response.status_code != 200:
                    error = f'An error occurred while downloading the file {file_to_download}. Aborting'
                else:
                    return response
            except requests.exceptions.ReadTimeout:
                error = f'Timeout reached while downloading the file {file_to_download}. Aborting.'

            except requests.exceptions.ConnectionError:
                error = f'Connection error while downloading the file {file_to_download}. Aborting.'

        if error:
            self.print(error, 0, 1)
            return False

    def get_last_modified(self, response) -> str:
        """
        returns Last-Modified field of TI file.
        Called when the file doesn't have an e-tag
        :param response: the output of a request done with requests library
        """
        last_modified = response.headers.get('Last-Modified', False)
        return last_modified

    def __check_if_update(self, file_to_download: str) :
        """
        Decides whether to update or not based on the update period and e-tag.
        Used for remote files that are updated periodically

        Returns the response if the file is old and needs to be updated
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

        update_period = self.riskiq_update_period if 'risk' in file_to_download else self.update_period

        # we have 2 types of remote files, JA3 feeds and TI feeds
        ################### Checking JA3 feeds ######################
        # did update_period pass since last time we updated?
        if 'risk' in file_to_download and last_update + update_period < now:
            return True
        ################### Checkign TI feeds ######################
        if last_update + update_period < now:
            # Update only if the e-tag is different
            try:
                file_name_to_download = file_to_download.split('/')[-1]

                # response will be used to get e-tag, and if the file was updated
                # the same response will be used to update the content in our db
                response = self.download_file(file_to_download)

                # Get what files are stored in cache db and their E-TAG to compare with current files
                data = __database__.get_TI_file_info(file_name_to_download)
                old_e_tag = data.get('e-tag', '')
                # Check now if E-TAG of file in github is same as downloaded
                # file here.
                if not response:
                    return False

                new_e_tag = self.get_e_tag_from_web(response)
                if not new_e_tag:
                    # use last modified instead
                    last_modified = self.get_last_modified(response)
                    if not last_modified:
                        self.print(f"Error updating {file_to_download}. Doesn't have an e-tag or Last-Modified field.")
                        return False
                    # use last modified date instead of e-tag
                    new_e_tag = last_modified

                if old_e_tag != new_e_tag:
                    # Our TI file is old. Download the new one.
                    # we'll be storing this e-tag in our database
                    self.new_e_tag = new_e_tag
                    return response

                elif old_e_tag == new_e_tag:
                    self.print(f'File {file_to_download} is up to date. No download.', 3, 0)
                    # Store the update time like we downloaded it anyway
                    self.new_update_time = time.time()
                    # Store the new etag and time of file in the database
                    malicious_file_info = {}
                    malicious_file_info['e-tag'] = new_e_tag
                    malicious_file_info['time'] = self.new_update_time
                    __database__.set_TI_file_info(file_name_to_download, malicious_file_info)
                    return False

            except Exception as inst:
                exception_line = sys.exc_info()[2].tb_lineno
                self.print(f'Problem on update_TI_file() line {exception_line}', 0, 1)
                self.print(str(type(inst)), 0, 1)
                self.print(str(inst.args), 0, 1)
                self.print(str(inst), 0, 1)
        else:
            # Update period hasn't passed yet, but the file is in our db
            self.loaded_ti_files += 1
        return False

    def get_e_tag_from_web(self, response) :
        """
        :param response: the output of a request done with requests library
        """
        e_tag = response.headers.get('ETag', False)
        return e_tag

    def sanitize(self, string):
        """
        Sanitize strings taken from the user
        """
        string = string.replace(';', '')
        string = string.replace('\`', '')
        string = string.replace('&', '')
        string = string.replace('|', '')
        string = string.replace('$(', '')
        string = string.replace('\n', '')
        return string

    def write_file_to_disk(self, response, full_path):

        with open(full_path, 'w') as f:
            f.write(response.text)

    def parse_ssl_feed(self, url, full_path):
        """
        Read all ssl fingerprints in full_path and store the info in our db
        :param url: the src feed
        :param full_path: the file path where the SSL feed is downloaded
        """

        malicious_ssl_certs = {}

        with open(full_path) as ssl_feed:
            # Ignore comments and find the description column if possible
            description_column = None
            while True:
                line = ssl_feed.readline()
                if line.startswith('# Listingdate') :
                    # looks like the line that contains column names, search where is the description column
                    for column in line.split(','):
                        # Listingreason is the description column in  abuse.ch Suricata SSL Fingerprint Blacklist
                        if 'Listingreason' in column.lower():
                            description_column = line.split(',').index(column)
                if not line.startswith('#'):
                    # break while statement if it is not a comment (i.e. does not start with #) or a header line
                    break

            # Find in which column is the ssl fingerprint in this file

            # Store the current position of the TI file
            current_file_position = ssl_feed.tell()
            if ',' in line:
                data = line.replace("\n","").replace("\"","").split(",")
                amount_of_columns = len(line.split(","))

            if description_column is None:
                # assume it's the last column
                description_column = amount_of_columns - 1

            # Search the first column that contains a sha1 hash
            for column in range(amount_of_columns):
                # Check if the ssl fingerprint is valid.
                # assume this column is the sha1 field
                sha1 = data[column]
                # verify
                if len(sha1) != 40:
                    sha1_column = None
                else:
                    # we found the column that has sha1 info
                    sha1_column = column
                    break

            if sha1_column is None:
                # can't find a column that contains an ioc
                self.print(f'Error while reading the ssl file {full_path}. Could not find a column with sha1 info', 0, 1)
                return False

            # Now that we read the first line, go back so we can process it
            ssl_feed.seek(current_file_position)

            for line in ssl_feed:
                # The format of the file should be
                # 2022-02-06 07:58:29,6cec09bcb575352785d313c7e978f26bfbd528ab,AsyncRAT C&C

                # skip comment lines
                if line.startswith('#'): continue

                # Separate the lines like CSV, either by commas or tabs
                # In the new format the ip is in the second position.
                # And surrounded by "

                # get the hash to store in our db
                if ',' in line:
                    sha1 = line.replace("\n", "").replace("\"", "").split(",")[sha1_column].strip()

                # get the description of this ssl to store in our db
                try:
                    separator = ',' if ',' in line else '\t'
                    description = line.replace("\n", "").replace("\"", "").split(separator)[description_column].strip()
                except IndexError:
                    self.print(f'IndexError Description column: {description_column}. Line: {line}')

                # self.print('\tRead Data {}: {}'.format(sha1, description))

                filename = full_path.split('/')[-1]

                if len(sha1) == 40:
                    # Store the sha1 in our local dict
                    malicious_ssl_certs[sha1] = json.dumps({'description': description, 'source':filename,
                                                          'threat_level': self.ssl_feeds[url]['threat_level'],
                                                          'tags': self.ssl_feeds[url]['tags']})
                else:
                    self.print('The data {} is not valid. It was found in {}.'.format(data, filename), 3, 3)
                    continue
        # Add all loaded malicious sha1 to the database
        __database__.add_ssl_sha1_to_IoC(malicious_ssl_certs)
        return True

    async def update_TI_file(self, link_to_download: str, response) -> bool:
        """
        Update remote TI files and JA3 feeds by downloading and parsing them

        :param response: the output of a request done with requests library
        """
        try:
            file_name_to_download = link_to_download.split('/')[-1]

            # first download the file and save it locally
            full_path = f'{self.path_to_threat_intelligence_data}/{file_name_to_download}'
            self.write_file_to_disk(response, full_path)

            # File is updated in the server and was in our database.
            # Delete previous IPs of this file.
            self.__delete_old_source_data_from_database(file_name_to_download)

            # ja3 files and ti_files are parsed differently, check which file is this
            # is it ja3 feed?
            if link_to_download in self.ja3_feeds and not self.parse_ja3_feed(link_to_download, full_path):
                self.print(f"Error parsing JA3 feed {link_to_download}. Updating was aborted.", 0, 1)
                return False

            # is it a ti_file? load updated IPs/domains to the database
            elif link_to_download in self.url_feeds \
                    and not self.parse_ti_feed(link_to_download, full_path):
                self.print(f"Error parsing feed {link_to_download}. Updating was aborted.", 0, 1)
                return False
            elif link_to_download in self.ssl_feeds \
                    and not self.parse_ssl_feed(link_to_download, full_path):
                self.print(f"Error parsing feed {link_to_download}. Updating was aborted.", 0, 1)
                return False
            # Store the new etag and time of file in the database
            self.new_update_time = time.time()
            file_info = {}
            file_info['e-tag'] = self.new_e_tag
            file_info['time'] = self.new_update_time
            __database__.set_TI_file_info(file_name_to_download, file_info)

            self.print(f'Successfully updated remote file {link_to_download}')
            self.loaded_ti_files += 1
            return True

        except Exception as inst:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(f'Problem on update_TI_file() line {exception_line}', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)

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

        except Exception as inst:
            self.print('Problem in parse_ja3_feed()', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            print(traceback.format_exc())
            return False

    def detect_data_type(self, data):
        """ Detects if incoming data is ipv4, ipv6, domain or ip range """

        data = data.strip()
        try:
            ipaddress.IPv4Address(data)
            # Is IPv4!
            return 'ip'
        except ipaddress.AddressValueError:
            pass
        # Is it ipv6?
        try:
            ipaddress.IPv6Address(data)
            # Is IPv6!
            return 'ip'
        except ipaddress.AddressValueError:
            # It does not look as IP address.
            pass

        try:
            ipaddress.ip_network(data)
            return 'ip_range'
        except ValueError:
            pass

        if validators.domain(data):
            return 'domain'
        else:
            # some ti files have / at the end of domains, remove it
            if data.endswith('/'):
                data = data[:-1]
            domain =  data
            if domain.startswith('http://'): data= data[7:]
            if domain.startswith('https://'): data= data[8:]
            if validators.domain(data):
                return 'domain'

    def parse_json_ti_feed(self, link_to_download, ti_file_path: str) -> bool:
        # to support nsec/full-results-2019-05-15.json
        tags = self.url_feeds[link_to_download]["tags"]
        # the new threat_level is the max of the 2
        threat_level = self.url_feeds[link_to_download]['threat_level']

        filename= ti_file_path.split('/')[-1]
        malicious_ips_dict = {}
        malicious_domains_dict = {}
        with open(ti_file_path) as feed:
            self.print('Reading next lines in the file {} for IoC'.format(ti_file_path), 3, 0)
            try:
                file = json.loads(feed.read())
            except json.decoder.JSONDecodeError:
                # not a json file??
                return False

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
                    malicious_ips_dict[ip] = json.dumps({{'description': description,
                                                        'source': filename,
                                                        'threat_level':threat_level,
                                                        'tags':tags }})
                    # process domains
                    domains = ioc.get('domains',[])
                    for domain in domains:
                        if validators.domain(domain.strip()):
                            # this is a valid domain
                            malicious_domains_dict[domain] = json.dumps({{'description': description,
                                                        'source': filename,
                                                        'threat_level':threat_level,
                                                        'tags':tags }})
            # Add all loaded malicious ips to the database
            __database__.add_ips_to_IoC(malicious_ips_dict)
            # Add all loaded malicious domains to the database
            __database__.add_domains_to_IoC(malicious_domains_dict)
            return True

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
            malicious_ip_ranges = {}
            with open(malicious_data_path) as feed:
                self.print('Reading next lines in the file {} for IoC'.format(malicious_data_path), 3, 0)
                # to support nsec/full-results-2019-05-15.json
                if 'json' in malicious_data_path:
                    self.parse_json_ti_feed(link_to_download, malicious_data_path)
                    return True

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
                    line = feed.readline()
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
                    if line.startswith('#') or line.startswith(';') or line.isspace() or len(line) < 3: continue
                    for keyword in header_keywords + ignored_IoCs:
                        if keyword in line.lower():
                            # we should ignore this line
                            process_line = False
                            break

                    if process_line:
                        break

                # Find in which column is the important info in this TI file (domain or ip)
                # Store the current position of the TI file
                current_file_position = feed.tell()
                line = line.replace("\n","").replace("\"","")

                # Separate the lines like CSV, either by commas or tabs
                separators = ('#', ',', ';','\t')
                for separator in separators:
                    if separator in line:
                        # get a list of every field in the line e.g [ioc, description, date]
                        line_fields = line.split(separator)
                        amount_of_columns =  len(line_fields)
                        break
                else:
                    # no separator of the above was found
                    if '0.0.0.0 ' in line:
                        # anudeepND/blacklist file
                        line_fields = [line[line.index(' ')+1:].replace("\n","")]
                        amount_of_columns = 1
                    else:
                        separator = '\t'
                        line_fields = line.split(separator)
                        amount_of_columns =  len(line_fields)



                if description_column is None:
                        # assume it's the last column
                        description_column = amount_of_columns - 1

                data_column = None
                # Search the first column that is an IPv4, IPv6 or domain
                for column_idx in range(amount_of_columns):
                    # Check if we support this type.
                    data_type = self.detect_data_type(line_fields[column_idx])
                    # found a supported type
                    if data_type:
                        data_column = column_idx
                        break
                # don't use if not data_column, it may be 0
                if data_column==None:
                    # Some unknown string and we cant detect the type of it
                    # can't find a column that contains an ioc
                    self.print(f'Error while reading the TI file {malicious_data_path}.'
                               f' Could not find a column with an IP or domain', 0, 1)
                    return False
                # Now that we read the first line, go back so we can process it
                feed.seek(current_file_position)

                for line in feed:
                    # The format of the file should be
                    # "0", "103.15.53.231","90", "Karel from our village. He is bad guy."
                    # So the second column will be used as important data with
                    # an IP or domain
                    # In the case of domains can be
                    # domain,www.netspy.net,NetSpy

                    # skip comments and headers
                    if line.startswith('#') or line.startswith(';')\
                            or 'FILE_HASH' in line\
                            or 'EMAIL' in line or 'URL' in line:
                        continue

                    line = line.replace("\n", "").replace("\"", "")

                    if '0.0.0.0 ' in line:
                        # anudeepND/blacklist file
                        data = line[line.index(' ')+1:].replace("\n","")
                    else:
                        line_fields = line.split(separator)
                        # get the ioc
                        data = line_fields[data_column].strip()


                    # some ti files have new lines in the middle of the file, ignore them
                    if len(data) < 3: continue

                    # get the description of this line
                    try:
                        description = line_fields[description_column].strip()
                    except (IndexError, UnboundLocalError):
                        description = ''
                        self.print(f'IndexError Description column: {description_column}. Line: {line}',0,1)

                    self.print('\tRead Data {}: {}'.format(data, description), 3, 0)

                    data_file_name = malicious_data_path.split('/')[-1]

                    # if we have info about the ioc, append to it, if we don't add a new entry in the correct dict
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
                            if data_file_name in old_domain_info['source']: continue
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
                    elif data_type == 'ip':
                        # make sure we're not blacklisting a private ip
                        if ipaddress.ip_address(data).is_private or ipaddress.ip_address(data).is_multicast:
                            continue

                        try:
                            # we already have info about this ip?
                            old_ip_info = json.loads(malicious_ips_dict[str(data)])
                            # if the IP appeared twice in the same blacklist, don't add the blacklist name twice
                            # or calculate the max threat_level
                            if data_file_name in old_ip_info['source']: continue
                            # append the new blacklist name to the current one
                            source = f'{old_ip_info["source"]}, {data_file_name}'
                            # append the new tag to the old tag
                            tags = f'{old_ip_info["tags"]}, {self.url_feeds[link_to_download]["tags"]}'
                            # the new threat_level is the max of the 2
                            threat_level = str(max(int(old_ip_info['threat_level']),
                                                   int(self.url_feeds[link_to_download]['threat_level'])))
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
                    elif data_type == 'ip_range':
                        # make sure we're not blacklisting a private ip range
                        # get network address from range
                        net_addr = data[:data.index('/')]
                        if net_addr in utils.home_networks or '224.0.0.0' in net_addr:
                            continue

                        try:
                            # we already have info about this range?
                            old_range_info = json.loads(malicious_ip_ranges[data])
                            # if the Range appeared twice in the same blacklist, don't add the blacklist name twice
                            # or calculate the max threat_level
                            if data_file_name in old_range_info['source']: continue
                            # append the new blacklist name to the current one
                            source = f'{old_range_info["source"]}, {data_file_name}'
                            # append the new tag to the old tag
                            tags = f'{old_range_info["tags"]}, {self.url_feeds[link_to_download]["tags"]}'
                            # the new threat_level is the max of the 2
                            threat_level = str(max(int(old_range_info['threat_level']),
                                                   int(self.url_feeds[link_to_download]['threat_level'])))
                            malicious_ips_dict[str(data)] = json.dumps({'description': old_range_info['description'],
                                                                        'source':source,
                                                                        'threat_level':threat_level,
                                                                        'tags': tags})
                            # print(f'Dulicate up range {data} found in sources: {source} old threat_level: {ip_info["threat_level"]}

                        except KeyError:
                            # We don't have info about this range, Store the ip in our local dict
                            malicious_ip_ranges[data] = json.dumps({'description': description,
                                                                    'source':data_file_name,
                                                                    'threat_level':self.url_feeds[link_to_download]['threat_level'],
                                                                    'tags': self.url_feeds[link_to_download]['tags']})
            # Add all loaded malicious ips to the database
            __database__.add_ips_to_IoC(malicious_ips_dict)
            # Add all loaded malicious domains to the database
            __database__.add_domains_to_IoC(malicious_domains_dict)
            __database__.add_ip_range_to_IoC(malicious_ip_ranges)
            return True

        except Exception as inst:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(f'Problem while updating {link_to_download} line {exception_line}', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            self.print(traceback.format_exc(), 0, 1)
            return False

    async def update(self) -> bool:
        """
        Main function. It tries to update the TI files from a remote server
        """
        try:
            self.update_period = float(self.update_period)
        except (TypeError, ValueError):
            # User does not want to update the malicious IP list.
            self.print('Not Updating the remote file of maliciuos IPs and domains because the user did not configure an update time.', 0, 1)
            return False

        if self.update_period <= 0:
            # User does not want to update the malicious IP list.
            self.print('Not Updating the remote file of malicious IPs and domains because the update period is <= 0.', 0, 1)
            return False

        self.print('Checking if we need to download TI files.')
        # we update different types of files
        # remote TI files, remote JA3 feeds, RiskIQ domains and local slips files

        ############### Update remote TI files ################
        # Check if the remote file is newer than our own
        # For each file that we should update
        files_to_download_dics = {}
        files_to_download_dics.update(self.url_feeds)
        files_to_download_dics.update(self.ja3_feeds)
        files_to_download_dics.update(self.ssl_feeds)
        for file_to_download in files_to_download_dics.keys():
            file_to_download = file_to_download.strip()
            file_to_download = self.sanitize(file_to_download)

            response = self.__check_if_update(file_to_download)
            if not response:
                # failed to get the response, either a server problem
                # or the the file is up to date so the response isn't needed
                # either way __check_if_update handles the error printing
                continue

            self.print(f'Updating the remote file {file_to_download}', 1, 0)
            # every function call to update_TI_file is now running concurrently instead of serially
            # so when a server's taking a while to give us the TI feed, we proceed
            # to download to next file instead of being idle
            task = asyncio.create_task(self.update_TI_file(file_to_download, response))

        # wait for all TI files to update
        try:
            await task
        except UnboundLocalError:
            # in case all our files are updated, we don't have task defined, skip
            pass
        self.print(f'{self.loaded_ti_files} TI files successfully loaded.')


        ############### Update RiskIQ domains ################
        # in case of riskiq files, we don't have a link for them in ti_files, We update these files using their API
        # check if we have a username and api key and a week has passed since we last updated
        if self.riskiq_email and self.riskiq_key and self.__check_if_update('riskiq_domains'):
            self.print(f'Updating RiskIQ domains', 1, 0)
            if self.update_riskiq_feed():
                self.print('Successfully updated RiskIQ domains.', 1, 0)
            else:
                self.print(f'An error occurred while updating RiskIQ domains. Updating was aborted.', 0, 1)

        ############### Update slips local files ################
        for file in os.listdir('slips_files/ports_info'):
            file = os.path.join('slips_files/ports_info', file)
            if self.__check_if_update_local_file(file):
                if not self.update_local_file(file):
                    # update failed
                    self.print(f'An error occurred while updating {file}. Updating was aborted.', 0, 1)
        time.sleep(0.5)
        print('-'*27)