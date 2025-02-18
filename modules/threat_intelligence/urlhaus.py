# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from typing import Dict, Any
import json
from uuid import uuid4

import requests

from slips_files.common.slips_utils import utils
from slips_files.core.structures.evidence import (
    Evidence,
    ProfileID,
    TimeWindow,
    Attacker,
    ThreatLevel,
    EvidenceType,
    IoCType,
    Direction,
)


class URLhaus:
    name = "URLhaus"
    description = "URLhaus lookups of URLs and hashes"
    authors = ["Alya Gomaa"]

    def __init__(self, db):
        self.db = db
        self.create_urlhaus_session()
        self.base_url = "https://urlhaus-api.abuse.ch/v1"

    def create_urlhaus_session(self):
        self.urlhaus_session = requests.session()
        self.urlhaus_session.verify = True

    def make_urlhaus_request(self, to_lookup: dict):
        """
        :param to_lookup: dict with {ioc_type: ioc}
        supported ioc types are md5_hash and url
        """
        ioc_type = next(iter(to_lookup))
        uri = "url" if ioc_type == "url" else "payload"
        try:
            return self.urlhaus_session.post(
                f"{self.base_url}/{uri}/",
                to_lookup,
                headers=self.urlhaus_session.headers,
            )
        except requests.exceptions.ConnectionError:
            self.create_urlhaus_session()

    def parse_urlhaus_url_response(self, response, url):
        threat = response["threat"]
        url_status = response["url_status"]
        description = (
            f"Connecting to a malicious URL {url}. Detected by: URLhaus "
            f"threat: {threat}, URL status: {url_status}"
        )
        try:
            tags = " ".join(response["tags"])
            description += f", tags: {tags}"
        except TypeError:
            # no tags available
            tags = ""

        try:
            payloads: dict = response["payloads"][0]
            file_type = payloads.get("file_type", "")
            file_name = payloads.get("filename", "")
            md5 = payloads.get("response_md5", "")
            signature = payloads.get("signature", "")

            description += (
                f", the file hosted in this url is of type: {file_type},"
                f" filename: {file_name} md5: {md5} signature: {signature}. "
            )

            # if we dont have a percentage repprted by vt, we will set out own
            # tl in set_evidence_malicious_url() function
            threat_level = False
            if virustotal_info := payloads.get("virustotal", ""):
                virustotal_percent = virustotal_info.get("percent", "")
                threat_level = virustotal_percent
                # virustotal_result = virustotal_info.get("result", "")
                # virustotal_result.replace('\',''')
                description += (
                    f"and was marked by {virustotal_percent}% "
                    f"of virustotal's AVs as malicious"
                )

        except (KeyError, IndexError):
            # no payloads available
            pass

        return {
            # get all the blacklists where this ioc is listed
            "source": "URLhaus",
            "url": url,
            "description": description,
            "threat_level": threat_level,
            "tags": tags,
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
            "blacklist": "URLhaus",
            "threat_level": threat_level,
            "tags": tags,
            "file_type": file_type,
            "file_name": file_name,
        }

    def lookup(self, ioc, type_of_ioc: str):
        """
        Supports URL lookups only
        :param ioc: can be domain or ip
        :param type_of_ioc: can be md5_hash, or url
        """

        # available types at urlhaus are url, md5
        urlhaus_data = {type_of_ioc: ioc}
        urlhaus_api_response = self.make_urlhaus_request(urlhaus_data)

        if not urlhaus_api_response:
            return

        if urlhaus_api_response.status_code != 200:
            return

        try:
            response: dict = json.loads(urlhaus_api_response.text)
        except json.decoder.JSONDecodeError:
            return

        if response["query_status"] in ["no_results", "invalid_url"]:
            # no response or empty response
            return

        if type_of_ioc == "md5_hash":
            return self.parse_urlhaus_md5_response(response, ioc)
        elif type_of_ioc == "url":
            return self.parse_urlhaus_url_response(response, ioc)

    def set_evidence_malicious_hash(self, file_info: Dict[str, Any]) -> None:
        flow: Dict[str, Any] = file_info["flow"]

        daddr: str = flow["daddr"]

        # Add the following fields in the evidence
        # description but only if we're sure they exist
        size: str = (
            f" size: {flow['size']}." if flow.get("size", False) else ""
        )
        file_name: str = (
            f" file name: {flow['file_name']}."
            if flow.get("file_name", False)
            else ""
        )
        file_type: str = (
            f" file type: {flow['file_type']}."
            if flow.get("file_type", False)
            else ""
        )
        tags: str = (
            f" tags: {flow['tags']}." if flow.get("tags", False) else ""
        )

        # We have more info about the downloaded file
        # so we need a more detailed description
        description: str = (
            f"Malicious downloaded file: {flow['md5']}."
            f"{size}  from IP: {daddr}. {file_name} {file_type} {tags} by "
            f"URLhaus."
        )

        threat_level: float = file_info.get("threat_level")
        if threat_level:
            # Threat level here is the VT percentage from URLhaus
            description += f" Virustotal score: {threat_level}% malicious"
            threat_level: str = utils.threat_level_to_string(
                float(threat_level) / 100
            )
            threat_level: ThreatLevel = ThreatLevel[threat_level.upper()]
        else:
            threat_level: ThreatLevel = ThreatLevel.HIGH

        confidence: float = 0.7
        saddr: str = file_info["profileid"].split("_")[-1]

        timestamp: str = flow["starttime"]
        twid_int = int(file_info["twid"].replace("timewindow", ""))
        # to add a correlation between the 2 evidence in alerts.json
        evidence_id_of_dstip_as_the_attacker = str(uuid4())
        evidence_id_of_srcip_as_the_attacker = str(uuid4())
        evidence = Evidence(
            id=evidence_id_of_srcip_as_the_attacker,
            rel_id=[evidence_id_of_dstip_as_the_attacker],
            evidence_type=EvidenceType.MALICIOUS_DOWNLOADED_FILE,
            attacker=Attacker(
                direction=Direction.SRC, ioc_type=IoCType.IP, value=saddr
            ),
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            timestamp=timestamp,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid_int),
            uid=[flow["uid"]],
        )

        self.db.set_evidence(evidence)

        evidence = Evidence(
            id=evidence_id_of_dstip_as_the_attacker,
            rel_id=[evidence_id_of_srcip_as_the_attacker],
            evidence_type=EvidenceType.MALICIOUS_DOWNLOADED_FILE,
            attacker=Attacker(
                direction=Direction.DST, ioc_type=IoCType.IP, value=daddr
            ),
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            timestamp=timestamp,
            profile=ProfileID(ip=daddr),
            timewindow=TimeWindow(number=twid_int),
            uid=[flow["uid"]],
        )

        self.db.set_evidence(evidence)

    def get_threat_level(self, url_info: dict) -> ThreatLevel:
        threat_level = url_info.get("threat_level", "")
        if not threat_level:
            return ThreatLevel.MEDIUM

        # Convert percentage reported by URLhaus (VirusTotal) to
        # a valid SLIPS confidence
        try:
            threat_level = int(threat_level) / 100
            threat_level: str = utils.threat_level_to_string(threat_level)
            return ThreatLevel[threat_level.upper()]
        except ValueError:
            return ThreatLevel.MEDIUM

    def set_evidence_malicious_url(
        self,
        daddr: str,
        url_info: Dict[str, Any],
        uid: str,
        timestamp: str,
        profileid: str,
        twid: str,
    ) -> None:
        """
        Set evidence for a malicious URL based on the provided URL info
        """
        threat_level: ThreatLevel = self.get_threat_level(url_info)
        description: str = url_info.get("description", "")
        saddr: str = profileid.split("_")[-1]
        twid_int = int(twid.replace("timewindow", ""))
        # to add a correlation between the 2 evidence in alerts.json
        evidence_id_of_dstip_as_the_attacker = str(uuid4())
        evidence_id_of_srcip_as_the_attacker = str(uuid4())
        evidence = Evidence(
            id=evidence_id_of_srcip_as_the_attacker,
            rel_id=[evidence_id_of_dstip_as_the_attacker],
            evidence_type=EvidenceType.THREAT_INTELLIGENCE_MALICIOUS_URL,
            attacker=Attacker(
                direction=Direction.SRC, ioc_type=IoCType.IP, value=saddr
            ),
            threat_level=threat_level,
            confidence=0.7,
            description=description,
            timestamp=timestamp,
            profile=ProfileID(ip=saddr),
            timewindow=TimeWindow(number=twid_int),
            uid=[uid],
        )
        self.db.set_evidence(evidence)

        evidence = Evidence(
            id=evidence_id_of_dstip_as_the_attacker,
            rel_id=[evidence_id_of_srcip_as_the_attacker],
            evidence_type=EvidenceType.THREAT_INTELLIGENCE_MALICIOUS_URL,
            attacker=Attacker(
                direction=Direction.DST, ioc_type=IoCType.IP, value=daddr
            ),
            threat_level=threat_level,
            confidence=0.7,
            description=description,
            timestamp=timestamp,
            profile=ProfileID(ip=daddr),
            timewindow=TimeWindow(number=twid_int),
            uid=[uid],
        )

        self.db.set_evidence(evidence)
