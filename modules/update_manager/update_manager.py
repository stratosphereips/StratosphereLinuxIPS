from exclusiveprocess import Lock, CannotAcquireLock
from modules.update_manager.timer_manager import InfiniteTimer
# from modules.update_manager.update_file_manager import UpdateFileManager
from slips_files.common.imports import *
from slips_files.core.helpers.whitelist import Whitelist
import time
import os
import json
import ipaddress
import validators
import traceback
import requests
import sys
import asyncio
import datetime


class UpdateManager(Module, multiprocessing.Process):
    # Name: short name of the module. Do not use spaces
    name = 'Update Manager'
    description = 'Update Threat Intelligence files'
    authors = ['Kamila Babayeva', 'Alya Gomaa']

    def init(self):
        self.read_configuration()
        # Update file manager
        # Timer to update the ThreatIntelligence files
        self.timer_manager = InfiniteTimer(
            self.update_period, self.update_ti_files
        )
        # Timer to update the MAC db
        # when update_ti_files is called, it decides what exactly to update, the mac db,
        # online whitelist OT online ti files.
        self.mac_db_update_manager = InfiniteTimer(
            self.mac_db_update_period, self.update_ti_files
        )
        self.online_whitelist_update_timer = InfiniteTimer(
            self.online_whitelist_update_period, self.update_ti_files
        )
        self.separator = self.db.get_field_separator()
        self.read_configuration()
        # this will store the number of loaded ti files
        self.loaded_ti_files = 0
        # don't store iocs older than 1 week
        self.interval = 7
        self.whitelist = Whitelist(self.output_queue, self.db)
        self.slips_logfile = self.db.get_stdfile("stdout")
        self.org_info_path = 'slips_files/organizations_info/'
        # if any keyword of the following is present in a line
        # then this line should be ignored by slips
        # either a not supported ioc type or a header line etc.
        # make sure the header keywords are lowercase because
        # we convert lines to lowercase when comparing
        self.header_keywords = (
            'type',
            'first_seen_utc',
            'ip_v4',
            '"domain"',
            '#"type"',
            '#fields',
            'number',
            'atom_type',
            'attacker'
        )
        self.ignored_IoCs = ('email', 'url', 'file_hash', 'file')
        # to track how many times an ip is present in different blacklists
        self.ips_ctr = {}
        self.first_time_reading_files = False
        # store the responses of the files that should be updated when their update period passed
        self.responses = {}

    def read_configuration(self):
        def read_riskiq_creds(RiskIQ_credentials_path):
            self.riskiq_email = None
            self.riskiq_key = None

            if not RiskIQ_credentials_path:
                return

            RiskIQ_credentials_path  = os.path.join(os.getcwd(),
                                                    RiskIQ_credentials_path)
            if not os.path.exists(RiskIQ_credentials_path):
                return

            with open(RiskIQ_credentials_path, 'r') as f:
                self.riskiq_email = f.readline().replace('\n', '')
                self.riskiq_key = f.readline().replace('\n', '')

        conf = ConfigParser()

        self.update_period = conf.update_period()

        self.path_to_remote_ti_files = conf.remote_ti_data_path()
        if not os.path.exists(self.path_to_remote_ti_files):
            os.mkdir(self.path_to_remote_ti_files)

        self.ti_feeds_path = conf.ti_files()
        self.url_feeds = self.get_feed_details(self.ti_feeds_path)
        self.ja3_feeds_path = conf.ja3_feeds()
        self.ja3_feeds = self.get_feed_details(self.ja3_feeds_path)

        self.ssl_feeds_path = conf.ssl_feeds()
        self.ssl_feeds = self.get_feed_details(self.ssl_feeds_path)

        RiskIQ_credentials_path = conf.RiskIQ_credentials_path()
        read_riskiq_creds(RiskIQ_credentials_path)
        self.riskiq_update_period = conf.riskiq_update_period()

        self.mac_db_update_period = conf.mac_db_update_period()
        self.mac_db_link = conf.mac_db_link()

        self.online_whitelist_update_period = conf.online_whitelist_update_period()
        self.online_whitelist = conf.online_whitelist()


    def get_feed_details(self, feeds_path):
        """
        Parse links, threat level and tags from the feeds_path file and return a dict with feed info
        """
        try:
            with open(feeds_path, 'r') as feeds_file:
                feeds = feeds_file.read()
        except FileNotFoundError:
            self.print(f"Error finding {feeds_path}. Feed won't be added to slips.")
            return {}

        # this dict will contain every link and its threat_level
        parsed_feeds = {}

        for line in feeds.splitlines():
            if line.startswith("#"):
                continue
            # remove all spaces
            line = line.strip().replace(" ",'')
            # each line is https://abc.d/e,medium,['tag1','tag2']
            line = line.split(',')
            url, threat_level = line[0], line[1]
            tags: str = " ".join(line[2:])
            tags = tags.replace('[','').replace(']','').replace('\'',"").replace('\"',"").split(',')
            url = utils.sanitize(url.strip())

            threat_level = threat_level.lower()
            # remove commented lines from the cache db
            if url.startswith(';'):
                feed = url.split('/')[-1]
                if self.db.get_TI_file_info(feed):
                    self.db.delete_feed(feed)
                    # to avoid calling delete_feed again with the same feed
                    self.db.delete_file_info(feed)
                continue

            # make sure the given tl is valid
            if not utils.is_valid_threat_level(threat_level):
                # not a valid threat_level
                self.print(
                            f'Invalid threat level found in slips.conf: {threat_level} '
                            f"for TI feed: {url}. Using 'low' instead.", 0, 1
                )
                threat_level = 'low'

            parsed_feeds[url] = {
                'threat_level': threat_level,
                'tags': tags
            }
        return parsed_feeds

    def log(self, text):
        """
        sends the text to output process to log it to slips.log without outputting to the terminal
        """
        self.output_queue.put(f'01|{self.name}|{text}log-only')

    def read_ports_info(self, ports_info_filepath) -> int:
        """
        Reads port info from slips_files/ports_info/ports_used_by_specific_orgs.csv
        and store it in the db
        """

        # there are ports that are by default considered unknown to slips,
        # but if it's known to be used by a specific organization, slips won't consider it 'unknown'.
        # in ports_info_filepath  we have a list of organizations range/ip and the port it's known to use
        with open(ports_info_filepath, 'r') as f:
            line_number = 0
            while True:
                line = f.readline()
                line_number += 1
                # reached the end of file
                if not line:
                    break
                # skip the header and the comments at the begining
                if line.startswith('#') or line.startswith('"Organization"'):
                    continue

                line = line.split(',')
                try:
                    organization, ip = line[0], line[1]
                    ports_range = line[2]
                    proto = line[3].lower().strip()

                    # is it a range of ports or a single port
                    if '-' in ports_range:
                        # it's a range of ports
                        first_port, last_port = ports_range.split('-')
                        first_port = int(first_port)
                        last_port = int(last_port)

                        for port in range(first_port, last_port+1):
                            portproto = f'{port}/{proto}'
                            self.db.set_organization_of_port(
                                organization, ip, portproto
                            )
                    else:
                        # it's a single port
                        portproto = f'{ports_range}/{proto}'
                        self.db.set_organization_of_port(
                            organization, ip, portproto
                        )

                except IndexError:
                    self.print(
                        f'Invalid line: {line} line number: {line_number} in {ports_info_filepath}. Skipping.', 0, 1,
                    )
                    continue
        return line_number

    def update_local_file(self, file_path) -> bool:
        """
        Returns True if update was successful
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
                        self.db.set_port_info(
                            f'{str(port)}/{proto}', name
                        )

            # Store the new hash of file in the database
            file_info = {'hash': self.new_hash}
            self.db.set_TI_file_info(file_path, file_info)
            return True

        except OSError:
            return False

    def check_if_update_local_file(self, file_path: str) -> bool:
        """
        Decides whether to update or not based on the file hash.
        Used for local files that are updated if the contents of the file hash changed
        for example: files in slips_files/ports_info
        """

        # compute file sha256 hash
        new_hash = utils.get_hash_from_file(file_path)

        # Get last hash of the file stored in the database
        file_info = self.db.get_TI_file_info(file_path)
        old_hash = file_info.get('hash', False)

        if not old_hash or old_hash != new_hash:
            # first time seeing the file, OR we should update it
            self.new_hash = new_hash
            return True

        else:
            # The 2 hashes are identical. File is up to date.
            return False

    def check_if_update_online_whitelist(self) -> bool:
        """
        Decides whether to update or not based on the update period
        Used for online whitelist specified in slips.conf
        """
        # Get the last time this file was updated
        ti_file_info = self.db.get_TI_file_info('tranco_whitelist')
        last_update = ti_file_info.get('time', float('-inf'))

        now = time.time()
        if last_update + self.online_whitelist_update_period > now:
            # update period hasnt passed yet
            return False

        # update period passed
        # response will be used to get e-tag, and if the file was updated
        # the same response will be used to update the content in our db
        response = self.download_file(self.online_whitelist)
        if not response:
            return False

        # update the timestamp in the db
        self.db.set_TI_file_info(
            'tranco_whitelist',
            {'time': time.time()}
        )
        self.responses['tranco_whitelist'] = response
        return True


    def download_file(self, file_to_download):
        # Retry 3 times to get the TI file if an error occured
        for _try in range(5):
            try:
                response = requests.get(file_to_download, timeout=5)
                if response.status_code != 200:
                    error = f'An error occurred while downloading the file {file_to_download}.' \
                            f'status code: {response.status_code}. Aborting'
                else:
                    return response
            except requests.exceptions.ReadTimeout:
                error = f'Timeout reached while downloading the file {file_to_download}. Aborting.'

            except (requests.exceptions.ConnectionError, requests.exceptions.ChunkedEncodingError):
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
        return response.headers.get('Last-Modified', False)

    def check_if_update(self, file_to_download: str, update_period) -> bool:
        """
        Decides whether to update or not based on the update period and e-tag.
        Used for remote files that are updated periodically
        :param file_to_download: url that contains the file to download
        """
        # the response will be stored in self.responses if the file is old and needs to be updated
        # Get the last time this file was updated
        ti_file_info: dict = self.db.get_TI_file_info(file_to_download)
        last_update = ti_file_info.get('time', float('-inf'))
        if last_update + update_period > time.time():
            # Update period hasn't passed yet, but the file is in our db
            self.loaded_ti_files += 1
            return False

        # update period passed
        if 'risk' in file_to_download:
            # updating riskiq TI data does not depend on an e-tag
            return True

        # Update only if the e-tag is different
        try:
            # response will be used to get e-tag, and if the file was updated
            # the same response will be used to update the content in our db
            response = self.download_file(file_to_download)
            if not response:
                return False

            if 'maclookup' in file_to_download:
                # no need to check the e-tag
                # we always need to download this file for slips to get info about MACs
                self.responses['mac_db'] = response
                return True

            # Get the E-TAG of this file to compare with current files
            ti_file_info: dict = self.db.get_TI_file_info(file_to_download)
            old_e_tag = ti_file_info.get('e-tag', '')
            # Check now if E-TAG of file in github is same as downloaded
            # file here.
            new_e_tag = self.get_e_tag(response)
            if not new_e_tag:
                # use last modified instead
                cached_last_modified = ti_file_info.get('Last-Modified', '')
                new_last_modified = self.get_last_modified(response)

                if not new_last_modified:
                    self.log(f"Error updating {file_to_download}. Doesn't have an e-tag or Last-Modified field.")
                    return False

                # use last modified date instead of e-tag
                if new_last_modified != cached_last_modified:
                    self.responses[file_to_download] = response
                    return True
                else:
                    # update the time we last checked this file for update
                    self.db.set_last_update_time(file_to_download, time.time())
                    self.loaded_ti_files += 1
                    return False

            if old_e_tag != new_e_tag:
                # Our TI file is old. Download the new one.
                # we'll be storing this e-tag in our database
                self.responses[file_to_download] = response
                return True

            else:
                # old_e_tag == new_e_tag
                # update period passed but the file hasnt changed on the server, no need to update
                # Store the update time like we downloaded it anyway
                # Store the new etag and time of file in the database
                self.db.set_last_update_time(file_to_download, time.time())
                self.loaded_ti_files += 1
                return False

        except Exception:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(
                f'Problem on update_TI_file() line {exception_line}', 0, 1
            )
            self.print(traceback.format_exc(), 0, 1)
        return False

    def get_e_tag(self, response):
        """
        :param response: the output of a request done with requests library
        """
        return response.headers.get('ETag', False)


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
                if line.startswith('# Listingdate'):
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
                data = line.replace('\n', '').replace('"', '').split(',')
                amount_of_columns = len(line.split(','))

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
                self.print(
                    f'Error while reading the ssl file {full_path}. Could not find a column with sha1 info', 0, 1,
                )
                return False

            # Now that we read the first line, go back so we can process it
            ssl_feed.seek(current_file_position)

            for line in ssl_feed:
                # The format of the file should be
                # 2022-02-06 07:58:29,6cec09bcb575352785d313c7e978f26bfbd528ab,AsyncRAT C&C

                # skip comment lines
                if line.startswith('#'):
                    continue

                # Separate the lines like CSV, either by commas or tabs
                # In the new format the ip is in the second position.
                # And surrounded by "

                # get the hash to store in our db
                if ',' in line:
                    sha1 = (
                        line.replace('\n', '')
                        .replace('"', '')
                        .split(',')[sha1_column]
                        .strip()
                    )

                # get the description of this ssl to store in our db
                try:
                    separator = ',' if ',' in line else '\t'
                    description = (
                        line.replace('\n', '')
                        .replace('"', '')
                        .split(separator)[description_column]
                        .strip()
                    )
                except IndexError:
                    self.print(
                        f'IndexError Description column: {description_column}. Line: {line}'
                    )

                # self.print('\tRead Data {}: {}'.format(sha1, description))

                filename = full_path.split('/')[-1]

                if len(sha1) == 40:
                    # Store the sha1 in our local dict
                    malicious_ssl_certs[sha1] = json.dumps(
                        {
                            'description': description,
                            'source': filename,
                            'threat_level': self.ssl_feeds[url][
                                'threat_level'
                            ],
                            'tags': self.ssl_feeds[url]['tags'],
                        }
                    )
                else:
                    self.log(
                        f'The data {data} is not valid. It was found in {filename}.'
                    )
                    continue
        # Add all loaded malicious sha1 to the database
        self.db.add_ssl_sha1_to_IoC(malicious_ssl_certs)
        return True

    async def update_TI_file(self, link_to_download: str) -> bool:
        """
        Update remote TI files, JA3 feeds and SSL feeds by writing them to disk and parsing them
        """
        try:
            self.log(f'Updating the remote file {link_to_download}')
            response = self.responses[link_to_download]
            file_name_to_download = link_to_download.split('/')[-1]

            # first download the file and save it locally
            full_path = os.path.join(self.path_to_remote_ti_files, file_name_to_download)
            self.write_file_to_disk(response, full_path)

            # File is updated in the server and was in our database.
            # Delete previous IPs of this file.
            self.delete_old_source_data_from_database(file_name_to_download)

            # ja3 files and ti_files are parsed differently, check which file is this
            # is it ja3 feed?
            if link_to_download in self.ja3_feeds and not self.parse_ja3_feed(
                link_to_download, full_path
            ):
                self.print(
                    f'Error parsing JA3 feed {link_to_download}. '
                    f'Updating was aborted.', 0, 1,
                )
                return False

            # is it a ti_file? load updated IPs/domains to the database
            elif link_to_download in self.url_feeds and not self.parse_ti_feed(
                link_to_download, full_path
            ):
                self.print(
                    f'Error parsing feed {link_to_download}. '
                    f'Updating was aborted.', 0, 1,
                )
                return False
            elif (
                    link_to_download in self.ssl_feeds
                    and not self.parse_ssl_feed(link_to_download, full_path)
            ):
                self.print(
                    f'Error parsing feed {link_to_download}. '
                    f'Updating was aborted.', 0, 1,
                )
                return False

            # Store the new etag and time of file in the database
            file_info = {
                'e-tag': self.get_e_tag(response),
                'time': time.time(),
                'Last-Modified': self.get_last_modified(response)
            }
            self.db.set_TI_file_info(link_to_download, file_info)

            self.log(f'Successfully updated in DB the remote file {link_to_download}')
            self.loaded_ti_files += 1

            # done parsing the file, delete it from disk
            try:
                os.remove(full_path)
            except FileNotFoundError:
                # this happens in integration tests, when another test deletes
                # the file while this one is updating it, ignore it
                pass

            return True

        except Exception:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(
                f'Problem on update_TI_file() line {exception_line}', 0, 1
            )
            self.print(traceback.print_exc(),0,1)
            return False

    def update_riskiq_feed(self):
        """Get and parse RiskIQ feed"""
        if not (
                self.riskiq_email
                and self.riskiq_key
        ):
            return False
        try:
            self.log('Updating RiskIQ domains')
            url = 'https://api.riskiq.net/pt/v2/articles/indicators'
            auth = (self.riskiq_email, self.riskiq_key)
            today = datetime.date.today()
            days_ago = datetime.timedelta(7)
            a_week_ago = today - days_ago
            data = {
                'startDateInclusive': a_week_ago.strftime('%Y-%m-%d'),
                'endDateExclusive': today.strftime('%Y-%m-%d'),
            }
            # Specifying json= here instead of data= ensures that the
            # Content-Type header is application/json, which is necessary.
            response = requests.get(url, timeout=5, auth=auth, json=data).json()
            # extract domains only from the response
            try:
                response = response['indicators']
                for indicator in response:
                    # each indicator is a dict
                    malicious_domains_dict = {}
                    if indicator.get('type', '') == 'domain':
                        domain = indicator['value']
                        malicious_domains_dict[domain] = json.dumps(
                            {
                                'description': 'malicious domain detected by RiskIQ',
                                'source': url,
                            }
                        )
                        self.db.add_domains_to_IoC(malicious_domains_dict)
            except KeyError:
                self.print(
                    f'RiskIQ returned: {response["message"]}. Update Cancelled.', 0, 1,
                )
                return False

            # update the timestamp in the db
            malicious_file_info = {'time': time.time()}
            self.db.set_TI_file_info(
                'riskiq_domains', malicious_file_info
            )
            self.log('Successfully updated RiskIQ domains.')
            return True
        except Exception as e:
            self.log('An error occurred while updating RiskIQ domains. Updating was aborted.')
            self.print('An error occurred while updating RiskIQ feed.', 0, 1)
            self.print(f'Error: {e}', 0, 1)
            return False

    def delete_old_source_IPs(self, file):
        """
        When file is updated, delete the old IPs in the cache
        """
        all_data = self.db.get_IPs_in_IoC()
        old_data = []
        for ip_data in all_data.items():
            ip = ip_data[0]
            data = json.loads(ip_data[1])
            if data['source'] == file:
                old_data.append(ip)
        if old_data:
            self.db.delete_ips_from_IoC_ips(old_data)

    def delete_old_source_Domains(self, file):
        """
        When file is updated, delete the old Domains in the cache
        """
        all_data = self.db.get_Domains_in_IoC()
        old_data = []
        for domain_data in all_data.items():
            domain = domain_data[0]
            data = json.loads(domain_data[1])
            if data['source'] == file:
                old_data.append(domain)
        if old_data:
            self.db.delete_domains_from_IoC_domains(old_data)

    def delete_old_source_data_from_database(self, data_file):
        """
        Delete old IPs of the source from the database.
        :param data_file: the name of source to delete old IPs from.
        """
        # Only read the files with .txt or .csv
        self.delete_old_source_IPs(data_file)
        self.delete_old_source_Domains(data_file)

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
                    if line.startswith('# ja3_md5'):
                        # looks like the line that contains column names, search where is the description column
                        for column in line.split(','):
                            # Listingreason is the description column in  abuse.ch Suricata JA3 Fingerprint Blacklist
                            if 'Listingreason' in column.lower():
                                description_column = line.split(',').index(
                                    column
                                )
                    if not line.startswith('#'):
                        # break while statement if it is not a comment (i.e. does not startwith #) or a header line
                        break

                # Find in which column is the ja3 fingerprint in this file

                # Store the current position of the TI file
                current_file_position = ja3_feed.tell()
                if ',' in line:
                    data = line.replace('\n', '').replace('"', '').split(',')
                    amount_of_columns = len(line.split(','))

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
                    self.print(
                        f'Error while reading the ja3 file {ja3_feed_path}. '
                        f'Could not find a column with JA3 info', 1, 1
                    )
                    return False

                # Now that we read the first line, go back so we can process it
                ja3_feed.seek(current_file_position)

                for line in ja3_feed:
                    # The format of the file should be
                    # 8f52d1ce303fb4a6515836aec3cc16b1,2017-07-15 19:05:11,2019-07-27 20:00:57,TrickBot

                    # skip comment lines
                    if line.startswith('#'):
                        continue

                    # Separate the lines like CSV, either by commas or tabs
                    # In the new format the ip is in the second position.
                    # And surronded by "

                    # get the ja3 to store in our db
                    if ',' in line:
                        ja3 = (
                            line.replace('\n', '')
                            .replace('"', '')
                            .split(',')[ja3_column]
                            .strip()
                        )

                    # get the description of this ja3 to store in our db
                    try:
                        if ',' in line:
                            description = (
                                line.replace('\n', '')
                                .replace('"', '')
                                .split(',')[description_column]
                                .strip()
                            )
                        else:
                            description = (
                                line.replace('\n', '')
                                .replace('"', '')
                                .split('\t')[description_column]
                                .strip()
                            )
                    except IndexError:
                        self.print(
                            f'IndexError Description column: {description_column}. Line: {line}',
                            0,
                            1,
                        )

                    # self.print('\tRead Data {}: {}'.format(ja3, description))

                    filename = ja3_feed_path.split('/')[-1]

                    # Check if the data is a valid IPv4, IPv6 or domain
                    if len(ja3) == 32:
                        # Store the ja3 in our local dict
                        malicious_ja3_dict[ja3] = json.dumps(
                            {
                                'description': description,
                                'source': filename,
                                'threat_level': self.ja3_feeds[url][
                                    'threat_level'
                                ],
                                'tags': self.ja3_feeds[url]['tags'],
                            }
                        )
                    else:
                        self.print(
                            f'The data {data} is not valid. It was found in {filename}.', 3, 3,
                        )
                        continue

            # Add all loaded malicious ja3 to the database
            self.db.add_ja3_to_IoC(malicious_ja3_dict)
            return True

        except Exception:
            self.print('Problem in parse_ja3_feed()', 0, 1)
            print(traceback.format_exc())
            return False

    def parse_json_ti_feed(self, link_to_download, ti_file_path: str) -> bool:
        """
        Slips has 2 json TI feeds that are parsed differently. hole.cert.pl and rstcloud
        """
        # to support https://hole.cert.pl/domains/domains.json
        tags = self.url_feeds[link_to_download]['tags']
        # the new threat_level is the max of the 2
        threat_level = self.url_feeds[link_to_download]['threat_level']
        filename = ti_file_path.split('/')[-1]

        if 'rstcloud' in link_to_download:
            malicious_ips_dict = {}
            with open(ti_file_path) as feed:
                self.print(
                    f'Reading next lines in the file {ti_file_path} for IoC', 3, 0
                )
                for line in feed.read().splitlines():
                    try:
                        line: dict = json.loads(line)
                    except json.decoder.JSONDecodeError:
                        # invalid json line
                        continue
                    # each ip in this file has it's own source and tag
                    src = line["src"]["name"][0]
                    malicious_ips_dict[line['ip']['v4']] = json.dumps(
                        {
                            'description': '',
                            'source': f'{filename}, {src}',
                            'threat_level': threat_level,
                            'tags': f'{line["tags"]["str"]}, {tags}',
                        }
                    )

            self.db.add_ips_to_IoC(malicious_ips_dict)
            return True


        if 'hole.cert.pl' in link_to_download:
            malicious_domains_dict = {}
            with open(ti_file_path) as feed:
                self.print(
                    f'Reading next lines in the file {ti_file_path} for IoC', 3, 0
                )
                try:
                    file = json.loads(feed.read())
                except json.decoder.JSONDecodeError:
                    # not a json file??
                    return False

                for ioc in file:
                    date = ioc['InsertDate']
                    diff = utils.get_time_diff(
                        date,
                        time.time(),
                        return_type='days'
                    )

                    if diff > self.interval:
                        continue
                    domain = ioc['DomainAddress']
                    if not validators.domain(domain):
                        continue
                    malicious_domains_dict[domain] = json.dumps(
                        {
                            'description': '',
                            'source': filename,
                            'threat_level': threat_level,
                            'tags': tags,
                        }
                    )
            self.db.add_domains_to_IoC(malicious_domains_dict)
            return True

    def get_description_column(self, header):
        """
        Given the first line of a TI file (header line), try to get the index of the description column
        """
        description_keywords = ('desc', 'collect', 'malware', 'tags_str', 'source' )
        for column in header.split(','):
            for keyword in description_keywords:
                if keyword in column:
                    return header.split(',').index(column)

    def is_ignored_line(self, line) -> bool:
        """
        Returns True if a comment, a blank line, or an unsupported IoC
        """
        if (
            line.startswith('#')
            or line.startswith(';')
            or line.isspace()
            or len(line) < 3
        ):
            return True

        for keyword in self.header_keywords + self.ignored_IoCs:
            if keyword in line.lower():
                # we should ignore this line
                return True

    def parse_line(self, line, file_path) -> tuple:
        """
        :param file_path: path of the ti file that contains the given line
        Parse the given line and return the amount of columns it has,
        a list of the line fields, and the separator it's using
        """
        # Separate the lines like CSV, either by commas or tabs
        separators = ('#', ',', ';', '\t')
        for separator in separators:
            if separator in line:
                # lines and descriptions in this feed are separated with ',' , so we get
                # an invalid number of columns
                if 'OCD-Datalak' in file_path:
                    # the valid line
                    new_line = line.split('Z,')[0]
                    # replace every ',' from the description
                    description = line.split('Z,', 1)[1].replace(
                        ', ', ''
                    )
                    line = f'{new_line},{description}'

                # get a list of every field in the line e.g [ioc, description, date]
                line_fields = line.split(separator)
                amount_of_columns = len(line_fields)
                sep = separator
                break
        else:
            # no separator of the above was found
            if '0.0.0.0 ' in line:
                sep = ' '
                # anudeepND/blacklist file
                line_fields = [
                    line[line.index(' ') + 1 :].replace('\n', '')
                ]
                amount_of_columns = 1
            else:
                sep = '\t'
                line_fields = line.split(sep)
                amount_of_columns = len(line_fields)

        return amount_of_columns, line_fields, sep


    def get_data_column(self, amount_of_columns, line_fields, file_path):
        """
        Get the first column that is an IPv4, IPv6 or domain
        :param file_path: path of the ti file that contains the given fields
        """
        for column_idx in range(amount_of_columns):
            if utils.detect_data_type(line_fields[column_idx]):
                return column_idx
        # Some unknown string and we cant detect the type of it
        # can't find a column that contains an ioc
        self.print(
            f'Error while reading the TI file {file_path}.'
            f' Could not find a column with an IP or domain',
            0, 1,
        )
        return 'Error'

    def extract_ioc_from_line(self, line, line_fields, separator, data_column, description_column, file_path) -> tuple:
        """
        Returns the ip/ip range/domain and it's description from the given line
        """
        if '0.0.0.0 ' in line:
            # anudeepND/blacklist file
            data = line[line.index(' ') + 1 :].replace('\n', '')
        else:
            line_fields = line.split(separator)
            # get the ioc
            data = line_fields[data_column].strip()

        # get the description of this line
        try:
            description = line_fields[description_column].strip()
        except (IndexError, UnboundLocalError):
            self.print(
                f'IndexError Description column: '
                f'{description_column}. Line: {line} in '
                f'{file_path}', 0, 1,
            )
            return False, False

        self.print(f'\tRead Data {data}: {description}', 3, 0)
        return data, description

    def add_to_ip_ctr(self, ip, blacklist):
        """
        keep track of how many times an ip was there in all blacklists
        :param blacklist: t make sure we don't count the ip twice in the same blacklist
        """
        blacklist =  os.path.basename(blacklist)
        if (
            ip in self.ips_ctr
            and
            blacklist not in self.ips_ctr['blacklists']
        ):
            self.ips_ctr[ip]['times_found'] += 1
            self.ips_ctr[ip]['blacklists'].append(blacklist)
        else:
            self.ips_ctr[ip] = {
                'times_found': 1,
                'blacklists': [blacklist]
            }


    def parse_ti_feed(
            self, link_to_download, ti_file_path: str
    ) -> bool:
        """
        Read all the files holding IP addresses and a description and put the
        info in a large dict.
        This also helps in having unique ioc across files
        :param link_to_download: this link that has the IOCs we're currently parsing, used for getting the threat_level
        :param ti_file_path: this is the path where the saved file from the link is downloaded
        """
        try:
            # Check if the file has any content
            try:
                filesize = os.path.getsize(ti_file_path)
            except FileNotFoundError:
                # happens in integration tests, another instance of slips deleted the file
                return False

            if filesize == 0:
                return False

            malicious_ips_dict = {}
            malicious_domains_dict = {}
            malicious_ip_ranges = {}
            if 'json' in ti_file_path:
                return self.parse_json_ti_feed(
                    link_to_download, ti_file_path
                )


            with open(ti_file_path) as feed:
                self.print(
                    f'Reading next lines in the file {ti_file_path} '
                    f'for IoC', 3, 0,
                )

                # Remove comments and find the description column if possible
                description_column = None

                while line := feed.readline():
                    # Try to find the line that has column names
                    for keyword in self.header_keywords:
                        if line.startswith(keyword):
                            # looks like the column names, search where is the description column
                            description_column = self.get_description_column(line)
                            break

                    if not self.is_ignored_line(line):
                        break

                # Store the current position of the TI file
                current_file_position = feed.tell()
                line = line.replace('\n', '').replace('"', '')

                amount_of_columns, line_fields, separator = self.parse_line(line, ti_file_path)
                if description_column is None:
                    # assume it's the last column
                    description_column = amount_of_columns - 1
                data_column = self.get_data_column(amount_of_columns, line_fields, ti_file_path)
                if data_column == 'Error':  # don't use 'if not' because it may be 0
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
                    if self.is_ignored_line(line):
                        continue

                    if 'OCD-Datalak' in ti_file_path:
                        # the valid line
                        new_line = line.split('Z,')[0]
                        # replace every ',' from the description
                        description = line.split('Z,', 1)[1].replace(', ', '')
                        line = f'{new_line},{description}'

                    line = line.replace('\n', '').replace('"', '')
                    data, description = self.extract_ioc_from_line(line,
                                                                   line_fields,
                                                                   separator,
                                                                   data_column,
                                                                   description_column,
                                                                   ti_file_path)
                    if not data and not description:
                        return False

                    # some ti files have new lines in the middle of the file, ignore them
                    if len(data) < 3:
                        continue

                    data_file_name = ti_file_path.split('/')[-1]

                    data_type = utils.detect_data_type(data)
                    if data_type is None:
                        self.print(
                            f'The data {data} is not valid. It was found in {ti_file_path}.',
                            0,
                            1,
                        )
                        continue

                    if data_type == 'domain':
                        # if we have info about the ioc, append to it, if we don't add a new entry in the correct dict
                        try:
                            # we already have info about this domain?
                            old_domain_info = json.loads(
                                malicious_domains_dict[str(data)]
                            )
                            # if the domain appeared twice in the same blacklist,  skip it
                            if data_file_name in old_domain_info['source']:
                                continue
                            # append the new blacklist name to the current one
                            source = f'{old_domain_info["source"]}, {data_file_name}'
                            # append the new tag to the current tag
                            tags = f'{old_domain_info["tags"]}, {self.url_feeds[link_to_download]["tags"]}'
                            # the new threat_level is the maximum threat_level
                            threat_level = str(
                                max(
                                    float(old_domain_info['threat_level']),
                                    float(
                                        self.url_feeds[link_to_download][
                                            'threat_level'
                                        ]
                                    ),
                                )
                            )
                            # Store the ip in our local dict
                            malicious_domains_dict[str(data)] = json.dumps(
                                {
                                    'description': old_domain_info[
                                        'description'
                                    ],
                                    'source': source,
                                    'threat_level': threat_level,
                                    'tags': tags,
                                }
                            )
                        except KeyError:
                            # We don't have info about this domain, Store the ip in our local dict
                            malicious_domains_dict[str(data)] = json.dumps(
                                {
                                    'description': description,
                                    'source': data_file_name,
                                    'threat_level': self.url_feeds[
                                        link_to_download
                                    ]['threat_level'],
                                    'tags': self.url_feeds[link_to_download][
                                        'tags'
                                    ],
                                }
                            )
                    elif data_type == 'ip':
                        # make sure we're not blacklisting a private ip
                        ip_obj = ipaddress.ip_address(data)
                        if (
                            ip_obj.is_private
                            or ip_obj.is_multicast
                            or ip_obj.is_link_local
                        ):
                            continue

                        try:
                            self.add_to_ip_ctr(data, ti_file_path)
                            # we already have info about this ip?
                            old_ip_info = json.loads(
                                malicious_ips_dict[str(data)]
                            )
                            # if the IP appeared twice in the same blacklist, don't add the blacklist name twice
                            # or calculate the max threat_level
                            if data_file_name in old_ip_info['source']:
                                continue
                            # append the new blacklist name to the current one
                            source = (
                                f'{old_ip_info["source"]}, {data_file_name}'
                            )
                            # append the new tag to the old tag
                            tags = f'{old_ip_info["tags"]}, {self.url_feeds[link_to_download]["tags"]}'
                            # the new threat_level is the max of the 2
                            threat_level = str(
                                max(
                                    int(old_ip_info['threat_level']),
                                    int(
                                        self.url_feeds[link_to_download][
                                            'threat_level'
                                        ]
                                    ),
                                )
                            )
                            malicious_ips_dict[str(data)] = json.dumps(
                                {
                                    'description': old_ip_info['description'],
                                    'source': source,
                                    'threat_level': threat_level,
                                    'tags': tags,
                                }
                            )
                            # print(f'Dulicate ip {data} found in sources: {source} old threat_level: {ip_info["threat_level"]}
                        except KeyError:
                            threat_level = self.url_feeds[link_to_download][
                                'threat_level'
                            ]
                            # We don't have info about this IP, Store the ip in our local dict
                            malicious_ips_dict[str(data)] = json.dumps(
                                {
                                    'description': description,
                                    'source': data_file_name,
                                    'threat_level': threat_level,
                                    'tags': self.url_feeds[link_to_download][
                                        'tags'
                                    ],
                                }
                            )
                            # set the score and confidence of this ip in ipsinfo
                            # and the profile of this ip to the same as the ones given in slips.conf
                            # todo for now the confidence is 1
                            self.db.update_threat_level(
                                f'profile_{data}', threat_level, 1
                            )
                    elif data_type == 'ip_range':
                        # make sure we're not blacklisting a private or multicast ip range
                        # get network address from range
                        net_addr = data[: data.index('/')]
                        ip_obj = ipaddress.ip_address(net_addr)
                        if (
                            ip_obj.is_multicast
                            or ip_obj.is_private
                            or ip_obj.is_link_local
                            or net_addr in utils.home_networks
                        ):
                            continue

                        try:
                            # we already have info about this range?
                            old_range_info = json.loads(
                                malicious_ip_ranges[data]
                            )
                            # if the Range appeared twice in the same blacklist, don't add the blacklist name twice
                            # or calculate the max threat_level
                            if data_file_name in old_range_info['source']:
                                continue
                            # append the new blacklist name to the current one
                            source = (
                                f'{old_range_info["source"]}, {data_file_name}'
                            )
                            # append the new tag to the old tag
                            tags = f'{old_range_info["tags"]}, {self.url_feeds[link_to_download]["tags"]}'
                            # the new threat_level is the max of the 2
                            threat_level = str(
                                max(
                                    int(old_range_info['threat_level']),
                                    int(
                                        self.url_feeds[link_to_download][
                                            'threat_level'
                                        ]
                                    ),
                                )
                            )
                            malicious_ip_ranges[str(data)] = json.dumps(
                                {
                                    'description': old_range_info[
                                        'description'
                                    ],
                                    'source': source,
                                    'threat_level': threat_level,
                                    'tags': tags,
                                }
                            )
                            # print(f'Duplicate up range {data} found in
                            # sources: {source} old threat_level: {ip_info["threat_level"]}

                        except KeyError:
                            # We don't have info about this range, Store the ip in our local dict
                            malicious_ip_ranges[data] = json.dumps(
                                {
                                    'description': description,
                                    'source': data_file_name,
                                    'threat_level': self.url_feeds[
                                        link_to_download
                                    ]['threat_level'],
                                    'tags': self.url_feeds[link_to_download][
                                        'tags'
                                    ],
                                }
                            )

            self.db.add_ips_to_IoC(malicious_ips_dict)
            self.db.add_domains_to_IoC(malicious_domains_dict)
            self.db.add_ip_range_to_IoC(malicious_ip_ranges)
            return True

        except Exception:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(
                f'Problem while updating {link_to_download} line '
                f'{exception_line}', 0, 1,
            )
            self.print(traceback.format_exc(), 0, 1)
            return False

    def check_if_update_org(self, file):
        cached_hash = self.db.get_TI_file_info(file).get('hash','')
        if utils.get_hash_from_file(file) != cached_hash:
            return True


    def get_whitelisted_orgs(self) -> list:
        self.whitelist.read_whitelist()
        whitelisted_orgs: dict = self.db.get_whitelist('organizations')
        whitelisted_orgs: list = list(whitelisted_orgs.keys())
        return whitelisted_orgs


    def update_org_files(self):
        # update whitelisted orgs in whitelist.conf, we may not have info about all of them
        whitelisted_orgs: list = self.get_whitelisted_orgs()
        # remove the once we have info about
        not_supported_orgs = [org for org in whitelisted_orgs if org not in utils.supported_orgs]
        for org in not_supported_orgs:
            self.whitelist.load_org_IPs(org)

        # update org we have local into about
        for org in utils.supported_orgs:
            org_ips = os.path.join(self.org_info_path, org)
            org_asn = os.path.join(self.org_info_path, f'{org}_asn')
            org_domains = os.path.join(self.org_info_path, f'{org}_domains')
            if self.check_if_update_org(org_ips):
                self.whitelist.load_org_IPs(org)

            if self.check_if_update_org(org_domains):
                self.whitelist.load_org_domains(org)

            if self.check_if_update_org(org_asn):
                self.whitelist.load_org_asn(org)

            for file in (org_ips, org_domains, org_asn):
                info = {
                    'hash': utils.get_hash_from_file(file),
                }
                self.db.set_TI_file_info(file, info)

    def update_ports_info(self):
        for file in os.listdir('slips_files/ports_info'):
            file = os.path.join('slips_files/ports_info', file)
            if self.check_if_update_local_file(
                file
            ) and not self.update_local_file(file):
                # update failed
                self.print(
                    f'An error occurred while updating {file}. Updating '
                    f'was aborted.', 0, 1,
                )

    def print_duplicate_ip_summary(self):
        if not self.first_time_reading_files:
            # when we parse ti files for the first time, we have the info to print the summary
            # when the ti files are already updated, from a previous run, we don't
            return

        ips_in_1_bl = 0
        ips_in_2_bl = 0
        ips_in_3_bl = 0
        for ip, ip_info in self.ips_ctr.items():
            blacklists_ip_appeard_in = ip_info['times_found']
            if blacklists_ip_appeard_in == 1:
                ips_in_1_bl += 1
            elif blacklists_ip_appeard_in == 2:
                ips_in_2_bl += 1
            elif blacklists_ip_appeard_in == 3:
                ips_in_3_bl += 1
        self.print(f'Number of repeated IPs in 1 blacklist: {ips_in_1_bl}', 2, 0)
        self.print(f'Number of repeated IPs in 2 blacklists: {ips_in_2_bl}', 2, 0)
        self.print(f'Number of repeated IPs in 3 blacklists: {ips_in_3_bl}', 2, 0)

    def update_mac_db(self):
        """
        Updates the mac db using the response stored in self.response
        """
        response = self.responses['mac_db']
        if response.status_code != 200:
            return False

        self.log('Updating the MAC database.')
        path_to_mac_db = 'databases/macaddress-db.json'

        # write to file the info as 1 json per line
        mac_info = response.text.replace(']','').replace('[','').replace(',{','\n{')
        with open(path_to_mac_db, 'w') as mac_db:
            mac_db.write(mac_info)

        self.db.set_TI_file_info(
            self.mac_db_link,
            {'time': time.time()}
        )
        return True

    def update_online_whitelist(self):
        """
        Updates online tranco whitelist defined in slips.conf online_whitelist key
        """
        response = self.responses['tranco_whitelist']
        # write to the file so we don't store the 10k domains in memory
        online_whitelist_download_path = os.path.join(self.path_to_remote_ti_files, 'tranco-top-10000-whitelist')
        with open(online_whitelist_download_path, 'w') as f:
            f.write(response.text)

        # parse the downloaded file and store it in the db
        with open(online_whitelist_download_path, 'r') as f:
            while line := f.readline():
                domain = line.split(',')[1]
                self.db.store_tranco_whitelisted_domain(domain)

        os.remove(online_whitelist_download_path)

    async def update(self) -> bool:
        """
        Main function. It tries to update the TI files from a remote server
        we update different types of files remote TI files, remote JA3 feeds, RiskIQ domains and local slips files
        """
        if self.update_period <= 0:
            # User does not want to update the malicious IP list.
            self.print(
                'Not Updating the remote file of malicious IPs and domains. '
                'update period is <= 0.', 0, 1,
            )
            return False

        try:
            self.log('Checking if we need to download TI files.')

            if self.check_if_update(self.mac_db_link, self.mac_db_update_period):
                self.update_mac_db()

            if self.check_if_update_online_whitelist():
                self.update_online_whitelist()

            ############### Update remote TI files ################
            # Check if the remote file is newer than our own
            # For each file that we should update`
            files_to_download = {}
            files_to_download.update(self.url_feeds)
            files_to_download.update(self.ja3_feeds)
            files_to_download.update(self.ssl_feeds)

            for file_to_download in files_to_download:
                if self.check_if_update(file_to_download, self.update_period):
                    # failed to get the response, either a server problem
                    # or the file is up to date so the response isn't needed
                    # either way __check_if_update handles the error printing

                    # this run wasn't started with existing ti files in the db
                    self.first_time_reading_files = True

                    # every function call to update_TI_file is now running concurrently instead of serially
                    # so when a server's taking a while to give us the TI feed, we proceed
                    # to download the next file instead of being idle
                    task = asyncio.create_task(
                        self.update_TI_file(file_to_download)
                    )
            #######################################################
            # in case of riskiq files, we don't have a link for them in ti_files, We update these files using their API
            # check if we have a username and api key and a week has passed since we last updated
            if self.check_if_update('riskiq_domains', self.riskiq_update_period):
                self.update_riskiq_feed()

            # wait for all TI files to update
            try:
                await task
            except UnboundLocalError:
                # in case all our files are updated, we don't have task defined, skip
                pass

            self.db.set_loaded_ti_files(self.loaded_ti_files)
            self.print_duplicate_ip_summary()
            self.loaded_ti_files = 0
        except KeyboardInterrupt:
            return False


    async def update_ti_files(self):
        """
        Update TI files and store them in database before slips starts
        """
        # create_task is used to run update() function concurrently instead of serially
        self.update_finished = asyncio.create_task(self.update())
        await self.update_finished
        self.print(f'{self.db.get_loaded_ti_files()} TI files successfully loaded.')

    def shutdown_gracefully(self):
        # terminating the timer for the process to be killed
        self.timer_manager.cancel()
        self.mac_db_update_manager.cancel()
        self.online_whitelist_update_timer.cancel()
        return True

    def pre_main(self):
        """this method runs only once"""
        utils.drop_root_privs()
        try:
            # only one instance of slips should be able to update TI files at a time
            # so this function will only be allowed to run from 1 slips instance.
            with Lock(name="slips_macdb_and_whitelist_and_TI_files_update"):
                asyncio.run(self.update_ti_files())
                # Starting timer to update files
                self.timer_manager.start()
                self.mac_db_update_manager.start()
                self.online_whitelist_update_timer.start()
                # we have to return 1 for the process to terminate
                return True
        except CannotAcquireLock:
            # another instance of slips is updating TI files, tranco whitelists and mac db
            return 1

    def main(self):
        """
        nothing should run in a loop in this module
        """
        pass

