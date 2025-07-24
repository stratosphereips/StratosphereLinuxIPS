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
    Contains all the logic related to the Fides module
    """

    name = "P2PHandlerDB"

    async def get_fides_ti(self, target: str):
        """
        Returns the TI stored for the specified target or None
        """
        return await self.r.get(target) or None

    async def save_fides_ti(self, target: str, data: str):
        """
        :param target: target is used as a key to store the data
        :param data: SlipsThreatIntelligence that is to be saved
        """
        await self.r.set(target, data)

    async def store_connected_peers(self, peers: List[str]):
        await self.r.set("connected_peers", json.dumps(peers))

    async def get_connected_peers(self):
        json_list = await self.r.get("connected_peers") or None

        if json_list is None:
            return []
        else:
            json_peers = json.loads(json_list)
            return json_peers

    async def store_peer_td(self, peer_id, td: str):
        await self.r.sadd(trust, peer_id)
        await self.r.hset(hash, peer_id, td)

    async def get_peer_td(self, peer_id: str):
        """
        Get peer trust data by peer_id.
        """
        return await self.r.hget(hash, peer_id)

    async def update_peer_td(self, peer_id: str, updated_td: str):
        """
        Update peer information.
        """
        if await self.r.sismember(trust, peer_id):
            await self.r.hset(hash, peer_id, updated_td)
        else:
            await self.store_peer_td(peer_id, updated_td)

    async def get_all_peers_td(self):
        """
        Get all connected peers trust data.
        """
        peer_ids = await self.r.smembers(trust)
        peers = {
            peer_id: await self.r.hget(hash, peer_id) for peer_id in peer_ids
        }
        return peers

    async def remove_peer_td(self, peer_id: str):
        """
        Remove a peer trust data from the set and hash.
        """
        await self.r.srem(trust, peer_id)
        await self.r.hdel(hash, peer_id)

    async def cache_network_opinion(
        self, target: str, opinion: dict, time: float
    ):
        cache_key = f"{FIDES_CACHE_KEY}:{target}"

        cache_data = {"created_seconds": time, **opinion}
        await self.r.hmset(cache_key, cache_data)

    async def get_cached_network_opinion(
        self, target: str, cache_valid_seconds: int, current_time: float
    ):
        cache_key = f"{FIDES_CACHE_KEY}:{target}"
        cache_data = await self.r.hgetall(cache_key)
        if not cache_data:
            return None

        cache_data = {k: v for k, v in cache_data.items()}

        # Get the time the opinion was cached
        created_seconds = float(cache_data.get("created_seconds", 0))
        # Check if the cached entry is still valid
        if current_time - created_seconds > cache_valid_seconds:
            # The cached opinion has expired, delete the entry
            await self.r.delete(cache_key)
            return None

        # Return the opinion (excluding the created_seconds field)
        opinion = {
            k: v for k, v in cache_data.items() if k != "created_seconds"
        }
        return opinion

    async def get_p2p_reports_about_ip(self, ip) -> dict:
        """
        Returns a dict of all P2P past reports about the given IP
        """
        # p2p_reports key is basically
        # { ip:  { reporter1: [report1, report2, report3]} }
        if reports := await self.rcache.hget(self.constants.P2P_REPORTS, ip):
            return json.loads(reports)
        return {}

    async def set_peer_trust(self, peer_ip, peer_trust):
        """
        Set the trust value for a peer in the database.
        :param peer_ip: IP address of the peer
        :param peer_trust: Trust value to be set as determined by the
        trust model
        For now, this is only for local peers
        """
        await self.r.hset("peer_trust", peer_ip, peer_trust)

    async def get_peer_trust(self, peer_ip):
        trust = await self.r.hget("peer_trust", peer_ip)
        if trust:
            return float(trust)
        return None
