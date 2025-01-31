# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
from multiprocessing.queues import Queue
import requests


class Circllu:
    name = "Circl.lu"
    description = "Circl.lu lookups of IPs"
    authors = ["Alya Gomaa"]

    def __init__(self, db, pending_queries: Queue):
        self.db = db
        self.create_session()
        self.pending_queries = pending_queries

    @staticmethod
    def calculate_threat_level(circl_trust: str) -> float:
        """Converts a Circl.lu trust score into a threat level that slips
        can deal with.

        Parameters:
            - circl_trust (str): The trust level from Circl.lu, where 0
            indicates completely malicious and 100 completely benign.

        Returns:
            - A float representing the threat level, scaled from 0 (benign)
            to 1 (malicious).
        """
        # the lower the value, the more malicious the file is
        benign_percentage = float(circl_trust)
        malicious_percentage = 100 - benign_percentage
        # scale the benign percentage from 0 to 1
        threat_level = float(malicious_percentage) / 100
        return threat_level

    def create_session(self):
        """Creates a new session for making API requests to Circl.lu. This session is
        configured with SSL verification enabled and sets the `Accept` header to
        `application/json`, indicating that responses should be in JSON format.

        Side Effects:
            - Initializes the `circl_session` attribute with a new
            requests session configured for Circl.lu API calls.
        """
        self.circl_session = requests.session()
        self.circl_session.verify = True
        self.circl_session.headers = {"accept": "application/json"}

    @staticmethod
    def calculate_confidence(blacklists: str) -> float:
        """Calculates the confidence score based on the count of blacklists that
        marked the file as malicious.

        Parameters:
            - blacklists (str): A space-separated string of blacklists
            that flagged the file.

        Returns:
            - A confidence score as a float. A higher score indicates
            higher confidence in the file's maliciousness.
        """
        blacklists = len(blacklists.split(" "))
        if blacklists == 1:
            confidence = 0.5
        elif blacklists == 2:
            confidence = 0.7
        else:
            confidence = 1
        return confidence

    def lookup(self, flow_info: dict):
        """Queries the Circl.lu API to determine if an MD5 hash of a
        file is known to be malicious based on the file's hash.Utilizes
        internal helper functions to calculate a threat level and
        confidence score based on the Circl.lu API
        response.

        Parameters:
            - flow_info (dict): Information about the network flow including
             the MD5 hash of the file to be checked.

        Returns:
            - A dictionary containing the 'confidence' score, 'threat_level',
            and a list of 'blacklist' sources that flagged the file as
            malicious. If the API call fails, or the file is not known
             to be malicious,
            None is returned.

        Side Effects:
            - May enqueue the flow information into `circllu_queue`
            for later processing if the API call encounters an exception.
            - Makes a network request to the Circl.lu API.
        """
        md5 = flow_info["flow"]["md5"]
        circl_base_url = "https://hashlookup.circl.lu/lookup/"
        try:
            circl_api_response = self.circl_session.get(
                f"{circl_base_url}/md5/{md5}",
                headers=self.circl_session.headers,
            )
        except Exception:
            # add the hash to the cirllu queue and ask for it later
            self.pending_queries.put(flow_info)
            return

        if circl_api_response.status_code != 200:
            return
        response = json.loads(circl_api_response.text)
        # KnownMalicious: List of source considering the hashed file as
        # being malicious (CIRCL)
        if "KnownMalicious" not in response:
            return

        file_info = {
            "confidence": self.calculate_confidence(
                response["KnownMalicious"]
            ),
            "threat_level": self.calculate_threat_level(
                response["hashlookup:trust"]
            ),
            "blacklist": f'{response["KnownMalicious"]}, circl.lu',
        }
        return file_info
