import json
from typing import (
    List,
)


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
        self.r.set(self.constants.CONNECTED_PEERS, json.dumps(peers))

    def get_connected_peers(self):
        json_list = self.r.get(self.constants.CONNECTED_PEERS) or None

        if json_list is None:
            return []
        else:
            json_peers = json.loads(json_list)
            return json_peers

    def store_peer_td(self, peer_id, td: str):
        self.r.sadd(self.constants.P2P_TRUST_SET, peer_id)
        self.r.hset(self.constants.P2P_PEER_INFO_HASH, peer_id, td)

    def get_peer_td(self, peer_id: str):
        """
        Get peer trust data by peer_id.
        """
        return self.r.hget(self.constants.P2P_PEER_INFO_HASH, peer_id)

    def update_peer_td(self, peer_id: str, updated_td: str):
        """
        Update peer information.
        """
        if self.r.sismember(self.constants.P2P_TRUST_SET, peer_id):
            self.r.hset(self.constants.P2P_PEER_INFO_HASH, peer_id, updated_td)
        else:
            self.store_peer_td(peer_id, updated_td)

    def get_all_peers_td(self):
        """
        Get all connected peers trust data.
        """
        peer_ids = self.r.smembers(self.constants.P2P_TRUST_SET)
        peers = {
            peer_id: self.r.hget(self.constants.P2P_PEER_INFO_HASH, peer_id)
            for peer_id in peer_ids
        }
        return peers

    def remove_peer_td(self, peer_id: str):
        """
        Remove a peer trust data from the set and hash.
        """
        self.r.srem(self.constants.P2P_TRUST_SET, peer_id)
        self.r.hdel(self.constants.P2P_PEER_INFO_HASH, peer_id)

    def cache_network_opinion(self, target: str, opinion: dict, time: float):
        cache_key = f"{self.constants.FIDES_CACHE_KEY}:{target}"

        cache_data = {
            self.constants.FIDES_CACHE_CREATED_SECONDS: time,
            **opinion,
        }
        self.r.hmset(cache_key, cache_data)
        self.r.hexpire(cache_key, self.default_ttl, cache_data, nx=True)

    def get_cached_network_opinion(
        self, target: str, cache_valid_seconds: int, current_time: float
    ):
        cache_key = f"{self.constants.FIDES_CACHE_KEY}:{target}"
        cache_data = self.r.hgetall(cache_key)
        if not cache_data:
            return None

        cache_data = {k: v for k, v in cache_data.items()}

        # Get the time the opinion was cached
        created_seconds = float(
            cache_data.get(self.constants.FIDES_CACHE_CREATED_SECONDS, 0)
        )
        # Check if the cached entry is still valid
        if current_time - created_seconds > cache_valid_seconds:
            # The cached opinion has expired, delete the entry
            self.r.delete(cache_key)
            return None

        # Return the opinion (excluding the created_seconds field)
        opinion = {
            k: v
            for k, v in cache_data.items()
            if k != self.constants.FIDES_CACHE_CREATED_SECONDS
        }
        return opinion

    def get_p2p_reports_about_ip(self, ip) -> dict:
        """
        returns a dict of all p2p past reports about the given ip
        """
        # p2p_reports key is basically
        # { ip:  { reporter1: [report1, report2, report3]} }
        if reports := self.rcache.hget(self.constants.P2P_REPORTS, ip):
            return json.loads(reports)
        return {}

    def set_peer_trust(self, peer_ip, peer_trust):
        """
        Set the trust value for a peer in the database.
        :param peer_ip: IP address of the peer
        :param peer_trust: Trust value to be set as determined by the
        trust model
        For now, this is only for local peers
        """

        self.r.hset(self.constants.PEER_TRUST, peer_ip, peer_trust)

    def get_peer_trust(self, peer_ip):
        trust = self.r.hget(self.constants.PEER_TRUST, peer_ip)
        if trust:
            return float(trust)
        return None
