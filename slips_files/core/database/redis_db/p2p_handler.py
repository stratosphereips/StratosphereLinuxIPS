import json
from typing import (
    Dict,
    List,
    Tuple,
    Union,
)


class P2PHandler:
    """
    Helper class for the Redis class in database.py
    Contains all the logic related to setting and retrieving evidence and
    alerts in the db
    """

    name = "TrustDB"

    def get_fides_ti(self, target: str):
        """
        returns the TI stored for specified target or None
        """
        return self.r.get(target) or None

    def store_connected_peers(self, peers: List[str]):
        self.r.set('connected_peers', json.dumps(peers))

    def get_connected_peers(self):
        json_list =  self.r.get('connected_peers') or None

        if json_list is None:
            return []
        else:
            json_peers= json.loads(json_list)
            return json_peers
