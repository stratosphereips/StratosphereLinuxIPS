import json
from typing import (
    List,
)

trust = "peers_strust"
hash = "peer_info"
FIDES_CACHE_KEY = "fides_cache"


class P2PHandler:
    """
    Helper class for the Redis class in database.py
    Contains all the logic related Fides module
    """

    name = "P2PHandlerDB"

    def get_fides_ti(self, target: str):
        """
        returns the TI stored for specified target or None
        """
        return self.r.get(target) or None

    def save_fides_ti(self, target: str, data: str):
        """
        :param target: target is used as a key to store the data
        :param data: SlipsThreatIntelligence that is to be saved
        """
        self.r.set(target, data)

    def store_connected_peers(self, peers: List[str]):
        self.r.set("connected_peers", json.dumps(peers))

    def get_connected_peers(self):
        json_list = self.r.get("connected_peers") or None

        if json_list is None:
            return []
        else:
            json_peers = json.loads(json_list)
            return json_peers

    def store_peer_td(self, peer_id, td: str):
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

    def cache_network_opinion(self, target: str, opinion: dict, time: float):
        cache_key = f"{FIDES_CACHE_KEY}:{target}"

        cache_data = {"created_seconds": time, **opinion}
        self.r.hmset(cache_key, cache_data)

    def get_cached_network_opinion(
        self, target: str, cache_valid_seconds: int, current_time: float
    ):
        cache_key = f"{FIDES_CACHE_KEY}:{target}"
        cache_data = self.r.hgetall(cache_key)
        if not cache_data:
            return None

        cache_data = {k: v for k, v in cache_data.items()}

        # Get the time the opinion was cached
        created_seconds = float(cache_data.get("created_seconds", 0))
        # Check if the cached entry is still valid
        if current_time - created_seconds > cache_valid_seconds:
            # The cached opinion has expired, delete the entry
            self.r.delete(cache_key)
            return None

        # Return the opinion (excluding the created_seconds field)
        opinion = {
            k: v for k, v in cache_data.items() if k != "created_seconds"
        }
        return opinion
