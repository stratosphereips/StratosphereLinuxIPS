# Must imports
from slips_files.common.imports import *

# Your imports
import json
import requests

URLHAUS_BASE_URL = 'https://urlhaus-api.abuse.ch/v1'

class URLhaus:
    name = 'URLhaus'
    description = 'URLhaus lookups of URLs and hashes'
    authors = ['Alya Gomaa']

    def __init__(self, db):
        self.db = db
        self.create_urlhaus_session()


    def create_urlhaus_session(self):
        self.urlhaus_session = requests.session()
        self.urlhaus_session.verify = True


    def make_urlhaus_request(self, to_lookup: dict):
        """
        :param to_lookup: dict with {ioc_type: ioc}
        supported ioc types are md5_hash and url
        """
        ioc_type = next(iter(to_lookup))
        uri = 'url' if ioc_type=='url' else 'payload'
        try:
            return self.urlhaus_session.post(
                f'{URLHAUS_BASE_URL}/{uri}/',
                to_lookup,
                headers=self.urlhaus_session.headers,
            )
        except requests.exceptions.ConnectionError:
            self.create_urlhaus_session()


    def parse_urlhaus_url_response(self, response, url):
        threat = response['threat']
        url_status = response['url_status']
        description = f"Connecting to a malicious URL {url}. Detected by: URLhaus " \
                          f"threat: {threat}, URL status: {url_status}"
        try:
            tags = " ".join(response['tags'])
            description += f', tags: {tags}'
        except TypeError:
            # no tags available
            tags = ''

        try:
            payloads: dict = response['payloads'][0]
            file_type = payloads.get("file_type", "")
            file_name = payloads.get("filename", "")
            md5 = payloads.get("response_md5", "")
            signature = payloads.get("signature", "")

            description += f', the file hosted in this url is of type: {file_type},' \
                               f' filename: {file_name} md5: {md5} signature: {signature}. '

            # if we dont have a percentage repprted by vt, we will set out own
            # tl in set_evidence_malicious_url() function
            threat_level = False
            if virustotal_info := payloads.get("virustotal", ""):
                virustotal_percent = virustotal_info.get("percent", "")
                threat_level = virustotal_percent
                # virustotal_result = virustotal_info.get("result", "")
                # virustotal_result.replace('\',''')
                description += f'and was marked by {virustotal_percent}% of virustotal\'s AVs as malicious'

        except (KeyError, IndexError):
            # no payloads available
            pass


        return {
            # get all the blacklists where this ioc is listed
            'source': 'URLhaus',
            'url': url,
            'description': description,
            'threat_level': threat_level,
            'tags': tags,
        }

    def parse_urlhaus_md5_response(self, response, md5):
        file_type = response.get("file_type", "")
        file_name = response.get("filename", "")
        # file_size = response.get("file_size", "")
        tags = response.get("signature", "")
        if virustotal_info := response.get("virustotal", ""):
            threat_level = virustotal_info.get("percent", "")
        else:
            threat_level = False
        return {
            # get all the blacklists where this ioc is listed
            'blacklist': 'URLhaus',
            'threat_level': threat_level,
            'tags': tags,
            'file_type': file_type,
            'file_name': file_name,
        }

    def urlhaus_lookup(self, ioc, type_of_ioc: str):
        """
        Supports URL lookups only
        :param ioc: can be domain or ip
        :param type_of_ioc: can be md5_hash, or url
        """

        # available types at urlhaus are url, md5
        urlhaus_data = {
            type_of_ioc: ioc
        }
        urlhaus_api_response = self.make_urlhaus_request(urlhaus_data)

        if not urlhaus_api_response:
            return

        if urlhaus_api_response.status_code != 200:
            return

        response: dict = json.loads(urlhaus_api_response.text)

        if response['query_status'] in ['no_results', 'invalid_url']:
            # no response or empty response
            return

        if type_of_ioc == 'md5_hash':
            return self.parse_urlhaus_md5_response(response, ioc)
        elif type_of_ioc == 'url':
            return self.parse_urlhaus_url_response(response, ioc)

    def set_evidence_malicious_hash(self, file_info: dict):
        attacker_direction = 'md5'
        category = 'Malware'
        evidence_type = 'MaliciousDownloadedFile'

        threat_level = file_info["threat_level"]
        flow = file_info['flow']
        attacker = flow["md5"]
        daddr = flow["daddr"]

        ip_identification = self.db.get_ip_identification(daddr)

        # add the following fields in the evidence description but only if we're sure they exist
        size = f" size: {flow['size']}." if flow.get('size', False) else ''
        file_name = f" file name: {flow['file_name']}." if flow.get('file_name', False) else ''
        file_type = f" file type: {flow['file_type']}." if flow.get('file_type', False) else ''
        tags = f" tags: {flow['tags']}." if flow.get('tags', False) else ''

        # we have more info about the downloaded file
        # so we need a more detailed description
        description = f"Malicious downloaded file: {flow['md5']}." \
                      f"{size}" \
                      f" from IP: {flow['daddr']} {ip_identification}." \
                      f"{file_name}" \
                      f"{file_type}" \
                      f"{tags}" \
                      f" by URLhaus." \

        if threat_level:
            # threat level here is the vt percentage from urlhaus
            description += f" virustotal score: {threat_level}% malicious"
            threat_level = float(threat_level)/100
        else:
            threat_level = 0.8

        confidence = 0.7

        self.db.setEvidence(evidence_type,
                                 attacker_direction,
                                 attacker,
                                 threat_level,
                                 confidence,
                                 description,
                                 flow["starttime"],
                                 category,
                                 profileid=file_info["profileid"],
                                 twid=file_info["twid"],
                                 uid=flow["uid"])

    def set_evidence_malicious_url(
            self,
            url_info,
            uid,
            timestamp,
            profileid,
            twid
    ):
        """
        :param url_info: dict with source, description, therat_level, and tags of url
        """
        threat_level = url_info['threat_level']
        attacker = url_info['url']
        description = url_info['description']

        confidence = 0.7

        if not threat_level:
            threat_level = 'medium'
        else:
            # convert percentage reported by urlhaus (virustotal) to
            # a valid slips confidence
            try:
                threat_level = int(threat_level)/100
                threat_level = utils.threat_level_to_string(threat_level)
            except ValueError:
                threat_level = 'medium'


        attacker_direction = 'url'
        category = 'Malware'
        evidence_type = 'MaliciousURL'

        self.db.setEvidence(evidence_type, attacker_direction, attacker, threat_level, confidence, description,
                                 timestamp, category, profileid=profileid, twid=twid, uid=uid)