# Must imports
import configparser
from slips_files.common.abstracts import Module
import multiprocessing
from slips_files.core.database import __database__
from slips_files.common.slips_utils import utils
import platform
import sys

# Your imports
import json
import urllib3
import certifi
import time
import ipaddress
import threading
import validators

class Module(Module, multiprocessing.Process):
    name = 'virustotal'
    description = 'IP, domain and file hash lookup on VirusTotal'
    authors = ['Dita Hollmannova, Kamila Babayeva', 'Alya Gomaa', 'Sebastian Garcia']

    def __init__(self, outputqueue, config, testing=False):
        multiprocessing.Process.__init__(self)
        # All the printing output should be sent to the outputqueue, which is connected to OutputProcess
        self.outputqueue = outputqueue
        # In case you need to read the slips.conf configuration file for your own configurations
        self.config = config
        # Start the DB
        # This line might not be needed when running SLIPS, but when VT module is run standalone, it still uses the
        # database and this line is necessary. Do not delete it, instead move it to line 21.
        __database__.start(self.config)  # TODO: What does this line do? It changes nothing.
        self.c1 = __database__.subscribe('new_flow')
        self.c2 = __database__.subscribe('new_dns_flow')
        self.c3 = __database__.subscribe('new_url')
        self.c4 = __database__.subscribe('new_downloaded_file')

        # Read the conf file
        self.__read_configuration()
        self.key = None
        try:
            with open(self.key_file, "r") as f:
                self.key = f.read(64)
        except FileNotFoundError:
            self.print("The file with API key (" + self.key_file + ") could not be loaded. VT module is stopping.")

        # query counter for debugging purposes
        self.counter = 0
        # Queue of API calls
        self.api_call_queue = []
        # Pool manager to make HTTP requests with urllib3
        # The certificate provides a bundle of trusted CAs, the certificates are located in certifi.where()
        self.http = urllib3.PoolManager(cert_reqs="CERT_REQUIRED", ca_certs=certifi.where())
        self.timeout = 0.0000001
        self.counter = 0
        # create the queue thread
        self.api_calls_thread = threading.Thread(target=self.API_calls_thread, daemon=True)
        # this will be true when there's a problem with the API key, then the module will exit
        self.incorrect_API_key = False

    def __read_configuration(self) -> str:
        """ Read the configuration file for what we need """
        # Get the time of log report
        try:
            self.key_file = self.config.get("virustotal", "api_key_file")
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.key_file = None
        try:
            # update period
            self.update_period = self.config.get('virustotal', 'virustotal_update_period')
            self.update_period = float(self.update_period)
        except (configparser.NoOptionError, configparser.NoSectionError, NameError):
            # There is a conf, but there is no option, or no section or no configuration file specified
            self.update_period = 259200

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

    def count_positives(self, response: dict, response_key: str, positive_key, total_key):
        """
        Count positive checks and total checks in the response, for the given category. To compute ratio of downloaded
        samples, sum results for both detected and undetected dicts: "undetected_downloaded_samples" and
        "detected_downloaded_samples".
        :param response: json dictionary with response data
        :param response_key: category to count, eg "undetected_downloaded_samples"
        :param positive_key: key to use inside of the category for successful detections (usually its "positives")
        :param total_key: key to use inside of the category to sum all checks (usually its "total")
        :return: number of positive tests, number of total tests run
        """
        detections = 0
        total = 0
        if response_key in response.keys():
            for item in response[response_key]:
                detections += item[positive_key]
                total += item[total_key]
        return detections, total

    def set_vt_data_in_IPInfo(self, ip, cached_data):
        """
        Function to set VirusTotal data of the IP in the IPInfo.
        It also sets asn data if it is unknown or does not exist.
        It also set passive dns retrieved from VirusTotal.
        """
        vt_scores, passive_dns, as_owner = self.get_ip_vt_data(ip)
        ts = time.time()
        vtdata = {"URL": vt_scores[0],
                  "down_file": vt_scores[1],
                  "ref_file": vt_scores[2],
                  "com_file": vt_scores[3],
                  "timestamp": ts}
        data = {}
        data["VirusTotal"] = vtdata

        # Add asn if it is unknown or not in the IP info
        if cached_data and ('asn' not in cached_data or cached_data['asn']['asnorg'] == 'Unknown'):
            data['asn'] = {'asnorg': as_owner,
                           'timestamp': ts}

        __database__.setInfoForIPs(ip, data)
        __database__.set_passive_dns(ip, passive_dns)

    def get_url_vt_data(self,url):
        """
        Function to perform API call to VirusTotal and return the score for the URL.
        Response is cached in a dictionary.
        :param url: url to check
        :return: URL ratio
        """
        response = self.api_query_(url)
        # Can't get url report
        if type(response)== dict and response.get('response_code','') is -1:
            self.print(f"VT API returned an Error - {response['verbose_msg']}")
            return 0
        try:
            score = int(response['positives']) / int(response['total'])
        except:
            score = 0
        self.counter += 1
        return score

    def set_url_data_in_URLInfo(self,url,cached_data):
        """
        Function to set VirusTotal data of the URL in the URLInfo.
        """
        score = self.get_url_vt_data(url)
        # Score of this url didn't change
        vtdata = {"URL" : score,
                  "timestamp": time.time()}
        data = {"VirusTotal" : vtdata}
        __database__.setInfoForURLs(url, data)

    def set_domain_data_in_DomainInfo(self, domain, cached_data):
        """
        Function to set VirusTotal data of the domain in the DomainInfo.
        It also sets asn data if it is unknown or does not exist.
        """
        vt_scores, as_owner = self.get_domain_vt_data(domain)
        vtdata = {"URL": vt_scores[0],
                  "down_file": vt_scores[1],
                  "ref_file": vt_scores[2],
                  "com_file": vt_scores[3],
                  "timestamp": time.time()}
        data = {}
        data["VirusTotal"] = vtdata

        # Add asn (autonomous system number) if it is unknown or not in the Domain info
        if cached_data and ('asn' not in cached_data or cached_data['asn'] == 'Unknown'):
            data['asn'] = as_owner
        __database__.setInfoForDomains(domain, data)

    def scan_file(self, file_info: dict):
        """
        Function to scan the md5 of the file with vt and set evidence if malicious
        """
        uid = file_info['uid']
        daddr = file_info['daddr']
        saddr = file_info['saddr']
        size = file_info['size']
        profileid = file_info['profileid']
        twid = file_info['twid']
        md5 = file_info['md5']
        ts = file_info['ts']

        response = self.api_query_(md5)

        positives = int(response.get('positives','0'))
        total = response.get('total',0)
        score = f'{positives}/{total}'
        self.counter += 1
        if positives:
            # set the confidence based on the number of AVs marked this file as malicious
            if positives ==1: confidence =  0.1
            elif positives ==2: confidence =  0.5
            elif positives >= 3: confidence = 1

            # consider it malicious and alert
            type_detection = 'file'
            detection_info = md5
            type_evidence = 'MaliciousDownloadedFile'
            threat_level = 'critical'
            description =  f'Malicious downloaded file {md5} size: {size} from IP: {saddr} Score: {score}'
            category = 'Malware'
            if not twid:
                twid = ''
            __database__.setEvidence(type_evidence, type_detection, detection_info,
                                     threat_level, confidence, description,
                                     ts, category, profileid=profileid, twid=twid, uid=uid)
            return 'malicious'
        return 'benign'

    def API_calls_thread(self):
        """
         This thread starts if there's an API calls queue,
         it operates every minute, and executes 4 api calls
         from the queue then sleeps again.
        """

        while True:
            # do not attempt to make more api calls if we already know that the api key is incorrect
            if self.incorrect_API_key == True:
                return False
            # wait until the queue is populated
            if not self.api_call_queue: time.sleep(30)
            # wait the api limit
            time.sleep(60)
            while self.api_call_queue:
                # get the first element in the queue
                ioc = self.api_call_queue.pop(0)
                if type(ioc) == dict:
                    # this is a file
                    self.scan_file(self.file_info)
                    continue

                ioc_type = self.get_ioc_type(ioc)
                if ioc_type is 'ip':
                    cached_data = __database__.getIPData(ioc)
                    # return an IPv4Address or IPv6Address object depending on the IP address passed as argument.
                    ip_addr = ipaddress.ip_address(ioc)
                    # if VT data of this IP (not multicast) is not in the IPInfo, ask VT.
                    # if the IP is not a multicast and 'VirusTotal' key is not in the IPInfo, proceed.
                    if (not cached_data or 'VirusTotal' not in cached_data) and not ip_addr.is_multicast:
                        self.set_vt_data_in_IPInfo(ioc, cached_data)

                elif ioc_type is 'domain':
                    cached_data = __database__.getDomainData(ioc)
                    if not cached_data or 'VirusTotal' not in cached_data:
                        self.set_domain_data_in_DomainInfo(ioc, cached_data)


                elif ioc_type is 'url':
                    cached_data = __database__.getURLData(ioc)
                    # If VT data of this domain is not in the DomainInfo, ask VT
                    # If 'Virustotal' key is not in the DomainInfo
                    if not cached_data or 'VirusTotal' not in cached_data:
                        # cached data is either False or {}
                        self.set_url_data_in_URLInfo(ioc, cached_data)

    def get_file_score(self, md5):
        """ returns the vt scores for the specified md5 """
        vt_scores, passive_dns, as_owner = self.get_vt_data_of_file(md5)
        ts = time.time()
        data = {}
        data["VirusTotal"] = {"md5": vt_scores[0],
                  "down_file": vt_scores[1],
                  "ref_file": vt_scores[2],
                  "com_file": vt_scores[3],
                  "timestamp": ts}

        __database__.setInfoForFile(md5, data)
        pass

    def get_as_owner(self, response):
        """
        Get as (autonomous system) owner of the IP
        :param response: json dictionary with response data
        """
        response_key = 'as_owner'
        if response_key in response:
            return response[response_key]
        else:
            return ''

    def get_passive_dns(self,response):
        """
        Get passive dns from virustotal response
        :param response: json dictionary with response data
        """
        response_key = 'resolutions'
        if response_key in response:
            # return the first 10 entries only
            return response[response_key][:10]
        else:
            return ''

    def get_ip_vt_data(self, ip: str):
        """
        Function to perform API call to VirusTotal and return scores for each of
        the four processed categories. Response is cached in a dictionary. Private IPs always return (0, 0, 0, 0).
        :param ip: IP address to check
        :return: 4-tuple of floats: URL ratio, downloaded file ratio, referrer file ratio, communicating file ratio
        """

        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private:
                self.print("[" + ip + "] is private, skipping", 0, 2)
                scores = 0,0,0,0
                return scores, '', ''

            # for unknown address, do the query
            response = self.api_query_(ip)
            as_owner = self.get_as_owner(response)
            passive_dns = self.get_passive_dns(response)
            scores = self.interpret_response(response)
            self.counter += 1
            return scores, passive_dns, as_owner
        except Exception as inst:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(f'Problem in the get_ip_vt_data() line {exception_line}', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)

    def get_domain_vt_data(self, domain: str):
        """
        Function perform API call to VirusTotal and return scores for each of
        the four processed categories. Response is cached in a dictionary.
        :param domain: Domain address to check
        :return: 4-tuple of floats: URL ratio, downloaded file ratio, referrer file ratio, communicating file ratio
        """
        if 'arpa' in domain or '.local' in domain:
            # 'local' is a special-use domain name reserved by the Internet Engineering Task Force (IETF)
            return (0, 0, 0, 0), ''
        try:
            # for unknown address, do the query
            response = self.api_query_(domain)
            as_owner = self.get_as_owner(response)
            scores = self.interpret_response(response)
            self.counter += 1
            return scores, as_owner
        except Exception as inst:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(f'Problem in the get_domain_vt_data() line {exception_line}', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            return False

    def get_ioc_type(self, ioc):
        """ Check the type of ioc, returns url, ip, domain or hash type"""
        try:
            # Is IPv4
            ip_address = ipaddress.IPv4Address(ioc)
            return 'ip'
        except ipaddress.AddressValueError:
            # Is it ipv6?
            try:
                ip_address = ipaddress.IPv6Address(ioc)
                return 'ip'
            except ipaddress.AddressValueError:
                # It does not look as IP address.
                if validators.domain(ioc):
                    return 'domain'
                elif validators.url(ioc):
                    return 'url'
                elif len(ioc)==32:
                    return 'md5'
                else:
                    # 192.168.1.1/wpad.dat combinations like this are treated as a url
                    return 'url'

    def api_query_(self, ioc, save_data=False):
        """
        Create request and perform API call
        :param ioc: IP address, domain, or URL to check
        :param save_data: False by default. Set to True to save each request json in a file named ip.txt
        :return: Response object
        """
        if self.incorrect_API_key == True:
            return {}

        params = {'apikey': self.key}
        ioc_type = self.get_ioc_type(ioc)
        if ioc_type is 'ip':
            # VT api URL for querying IPs
            self.url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
            params.update({'ip': ioc})
        elif ioc_type is 'domain':
             # VT api URL for querying domains
            self.url = 'https://www.virustotal.com/vtapi/v2/domain/report'
            params.update({'domain': ioc})
        elif ioc_type is 'url':
             # VT api URL for querying URLS
            self.url = 'https://www.virustotal.com/vtapi/v2/url/report'
            params.update({'resource': ioc})
        elif ioc_type is 'md5':
            # VT api URL for querying files
            self.url = 'https://www.virustotal.com/vtapi/v2/file/report'
            params.update({'resource': ioc})

        # wait for network
        while True:
            try:
                response = self.http.request("GET", self.url, fields=params)
                break
            except urllib3.exceptions.MaxRetryError:
                self.print("Network is not available, waiting 10s")
                time.sleep(10)

        if response.status != 200:
            # 204 means Request rate limit exceeded. You are making more requests
            # than allowed. You have exceeded one of your quotas (minute, daily or monthly).
            if response.status == 204:
                # Add to the queue of api calls in case of api limit reached.
                if ioc_type == 'md5':
                    # we need to add the entire dict to the queue because we'll be using it to setEvidence later
                    self.api_call_queue.append(self.file_info)
                else: self.api_call_queue.append(ioc)
            # 403 means you don't have enough privileges to make the request or wrong API key
            elif response.status == 403:
                # don't add to the api call queue because the user will have to restart slips anyway
                # to add a correct API key and the queue wil be erased
                self.print("Please check that your API key is correct.", 0, 1)
                self.incorrect_API_key = True
            else:
                # if the query was unsuccessful but it is not caused by API limit, abort (this is some unknown error)
                # X-Api-Message is a comprehensive error description, but it is not always present
                if "X-Api-Message" in response.headers:
                    message = response.headers["X-Api-Message"]
                # Reason is a much shorter description ("Forbidden"), but it is always there
                else:
                    message = response.reason
                raise Exception("VT API returned unexpected code: " + str(response.status) + " - " + message)

            # report that API limit is reached, wait one minute and try again
            self.print("Status code is " + str(response.status) + " at " + str(time.asctime()) + ", query id: " + str(
                self.counter), 0, 2)
            # return empty dict because api call isn't successful
            data = {}
        else:
            # query successful
            data = json.loads(response.data)
            if type(data) == list:
                # this is an empty list, vt dometimes returns it with status code 200
                data = {}
            # optionally, save data to file
            if save_data and ioc_type is 'ip':
                filename = ioc + ".txt"
                if filename:
                    with open(filename, 'w') as f:
                        json.dump(data, f)

        return data

    def interpret_response(self, response: dict):
        """
        Read the dictionary and compute ratio for each category.

        The ratio is computed as follows:
        For each IP, VT API returns data about four categories: URLs that resolved to the IP, samples (files) downloaded
        from the IP, samples (files) that contain the given IP, and samples (programs) that contact the IP. The structure of
        the data is same for all four categories.

        For each sample in a category, VT asks the antivirus engines and counts how many of them find the sample malicious.
        For example, if VT asked 27 engines and four of them found the sample malicious, the sample would be given score
        4/27, where 4 is the number of successful detections, and 27 is the total number of engines used.

        The response has two fields for each category. These are the "detected_<category>" field, which contains list of
        samples that were found malicious by at least one engine, and the "undetected_<category>" field, which contains all
        the samples that none of the engines found malicious (all samples in undetected have score 0/x). This means that the
        response has 8 fields with scores - two (detected and undetected) for each of the four categories. Some fields may
        be missing if data for the category is not present.

        To compute the ratio for a category, scores across the two fields are summed together. A global number of detections
        is computed (sum of all positive detections across all samples in the detected field) and the global number of tests
        is computed (sum of all "total" values in both detected and undetected sample lists). Now we have detections for a
        category and total for a category. The ratio for a category is detections/total. If no tests were run (the field is
        empty and total=0), this would be undefined, so the ratio is set to 0.

        Ratio is computed separately for each category.

        :param response: dictionary (json data from the response)
        :return: four floats: url_ratio, down_file_ratio, ref_file_ratio, com_file_ratio
        """

        # compute how many tests were run on the undetected samples. This will return tuple (0, total)
        # the numbers 2 and 3 are keys to the dictionary, which is in this only case (probably by mistake) a list
        undetected_url_score = self.count_positives(response, "undetected_urls", 2, 3)

        # compute how many tests were run on the detected samples. This will return tuple (detections, total)
        detected_url_score = self.count_positives(response, "detected_urls", "positives", "total")

        # sum the previous results, to get the sum of detections and sum of total tests
        url_detections = undetected_url_score[0] + detected_url_score[0]
        url_total = undetected_url_score[1] + detected_url_score[1]

        # compute the score for the category
        if url_total:
            url_ratio = url_detections/url_total
        else:
            url_ratio = 0

        # following categories  are computed in the same way
        undetected_download_score = self.count_positives(response, "undetected_downloaded_samples", "positives", "total")
        detected_download_score = self.count_positives(response, "detected_downloaded_samples", "positives", "total")
        down_file_detections = undetected_download_score[0] + detected_download_score[0]
        down_file_total = undetected_download_score[1] + detected_download_score[1]

        if down_file_total:
            down_file_ratio = down_file_detections/down_file_total
        else:
            down_file_ratio = 0

        undetected_ref_score = self.count_positives(response, "undetected_referrer_samples", "positives", "total")
        detected_ref_score = self.count_positives(response, "detected_referrer_samples", "positives", "total")
        ref_file_detections = undetected_ref_score[0] + detected_ref_score[0]
        ref_file_total = undetected_ref_score[1] + detected_ref_score[1]

        if ref_file_total:
            ref_file_ratio = ref_file_detections/ref_file_total
        else:
            ref_file_ratio = 0

        undetected_com_score = self.count_positives(response, "undetected_communicating_samples", "positives", "total")
        detected_com_score = self.count_positives(response, "detected_communicating_samples", "positives", "total")
        com_file_detections = undetected_com_score[0] + detected_com_score[0]
        com_file_total = undetected_com_score[1] + detected_com_score[1]

        if com_file_total:
            com_file_ratio = com_file_detections/com_file_total
        else:
            com_file_ratio = 0

        # Convert the values into percentages before returning
        url_ratio = url_ratio * 100
        down_file_ratio = down_file_ratio * 100
        ref_file_ratio = ref_file_ratio * 100
        com_file_ratio = com_file_ratio * 100

        return url_ratio, down_file_ratio, ref_file_ratio, com_file_ratio


    def run(self):
        try:
            if self.key is None:
                # We don't have a virustotal key
                return
            self.api_calls_thread.start()
        except Exception as inst:
            exception_line = sys.exc_info()[2].tb_lineno
            self.print(f'Problem on the run() line {exception_line}', 0, 1)
            self.print(str(type(inst)), 0, 1)
            self.print(str(inst.args), 0, 1)
            self.print(str(inst), 0, 1)
            return True

        # Main loop function
        while True:
            try:
                message = self.c1.get_message(timeout=self.timeout)

                # if timewindows are not updated for a long time, Slips is stopped automatically.
                # exit module if there's a problem with the API key
                if (message and message['data'] == 'stop_process') or self.incorrect_API_key == True:
                    # Confirm that the module is done processing
                    __database__.publish('finished_modules', self.name)
                    return True

                if utils.is_msg_intended_for(message, 'new_flow'):
                    data = message["data"]
                    data = json.loads(data)
                    profileid = data['profileid']
                    twid = data['twid']
                    stime = data['stime']
                    flow = json.loads(data['flow']) # this is a dict {'uid':json flow data}
                    # there is only one pair key-value in the dictionary
                    for key, value in flow.items():
                        flow_data = json.loads(value)
                    ip = flow_data['daddr']
                    cached_data = __database__.getIPData(ip)
                    # return an IPv4Address or IPv6Address object depending on the IP address passed as argument.
                    ip_addr = ipaddress.ip_address(ip)
                    # if VT data of this IP (not multicast) is not in the IPInfo, ask VT.
                    # if the IP is not a multicast and 'VirusTotal' key is not in the IPInfo, proceed.
                    if (not cached_data or 'VirusTotal' not in cached_data) and not ip_addr.is_multicast:
                        self.set_vt_data_in_IPInfo(ip, cached_data)

                    # if VT data of this IP is in the IPInfo, check the timestamp.
                    elif cached_data and 'VirusTotal' in cached_data:
                        # If VT is in data, check timestamp. Take time difference, if not valid, update vt scores.
                        if (time.time() - cached_data["VirusTotal"]['timestamp']) > self.update_period:
                            self.set_vt_data_in_IPInfo(ip, cached_data)

                message = self.c2.get_message(timeout=self.timeout)
                if utils.is_msg_intended_for(message, 'new_dns_flow'):
                    data = message["data"]

                    data = json.loads(data)
                    profileid = data['profileid']
                    twid = data['twid']
                    uid = data['uid']
                    flow_data = json.loads(data['flow']) # this is a dict {'uid':json flow data}
                    domain = flow_data.get('query',False)


                    cached_data = __database__.getDomainData(domain)
                    # If VT data of this domain is not in the DomainInfo, ask VT
                    # If 'Virustotal' key is not in the DomainInfo
                    if domain and (not cached_data or 'VirusTotal' not in cached_data):
                        self.set_domain_data_in_DomainInfo(domain, cached_data)
                    elif domain and cached_data and 'VirusTotal' in cached_data:
                        # If VT is in data, check timestamp. Take time difference, if not valid, update vt scores.
                        if (time.time() - cached_data["VirusTotal"]['timestamp']) > self.update_period:
                            self.set_domain_data_in_DomainInfo(domain, cached_data)


                message = self.c3.get_message(timeout=self.timeout)
                if utils.is_msg_intended_for(message, 'new_url'):
                    data = message["data"]
                    data = json.loads(data)
                    profileid = data['profileid']
                    twid = data['twid']
                    flow_data = json.loads(data['flow'])
                    url = flow_data['host'] + flow_data.get('uri','')
                    cached_data = __database__.getURLData(url)
                    # If VT data of this domain is not in the DomainInfo, ask VT
                    # If 'Virustotal' key is not in the DomainInfo
                    if not cached_data or 'VirusTotal' not in cached_data:
                        # cached data is either False or {}
                        self.set_url_data_in_URLInfo(url,cached_data)
                    elif cached_data and 'VirusTotal' in cached_data:
                        # If VT is in data, check timestamp. Take time difference, if not valid, update vt scores.
                        if (time.time() - cached_data["VirusTotal"]['timestamp']) > self.update_period:
                            self.set_url_data_in_URLInfo(url, cached_data)

                message = self.c4.get_message(timeout=self.timeout)
                if utils.is_msg_intended_for(message, 'new_downloaded_file'):
                    self.file_info = json.loads(message['data'])
                    file_info = self.file_info.copy()
                    self.scan_file(file_info)

            except KeyboardInterrupt:
                # On KeyboardInterrupt, slips.py sends a stop_process msg to all modules, so continue to receive it
                continue
            except Exception as inst:
                exception_line = sys.exc_info()[2].tb_lineno
                self.print(f'Problem on the run() line {exception_line}', 0, 1)
                self.print(str(type(inst)), 0, 1)
                self.print(str(inst.args), 0, 1)
                self.print(str(inst), 0, 1)
                return True
