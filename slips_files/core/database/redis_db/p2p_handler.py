import json
from typing import (
    Dict,
    List,
    Tuple,
    Union,
)

trust = "peers_strust"
hash = "peer_info"

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

    def store_peer_td(self, peer_id, td:str):
        self.r.sadd(trust, peer_id)
        self.r.hset(hash, peer_id, td)

    def get_peer_td(self, peer_id: str):
        """
        Get peer trust data by peer_id.
        """
        return self.r.hget(hash, peer_id)

    def update_peer_td(self, peer_id: str, updated_td: str):
        """
        Update peer information.
        """
        if self.r.sismember(trust, peer_id):
            self.r.hset(hash, peer_id, updated_td)
        else:
            self.store_peer_td(peer_id, updated_td)

    def get_all_peers_td(self):
        """
        Get all connected peers trust data.
        """
        peer_ids = self.r.smembers(trust)
        peers = {peer_id: self.r.hget(hash, peer_id) for peer_id in peer_ids}
        return peers

    def remove_peer_td(self, peer_id: str):
        """
        Remove a peer trust data from the set and hash.
        """
        self.r.srem(trust, peer_id)
        self.r.hdel(hash, peer_id)
