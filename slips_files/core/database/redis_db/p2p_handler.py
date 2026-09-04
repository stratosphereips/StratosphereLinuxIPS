import json
import time
from typing import (
    List,
    Any,
    Callable,
    Sequence,
    Tuple,
)


class P2PHandler:
    """
    Helper class for the Redis class in database.py
    Contains all the logic related Fides module
    """

    r: Any
    rcache: Any
    constants: Any
    default_ttl: int
    extended_ttl: int
    zadd_but_keep_n_entries: Callable[..., Any]

    name = "p2p_handler_db"

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

    def _store_peer_td(self, peer_id, td: str):
        self.zadd_but_keep_n_entries(
            self.constants.P2P_TRUST_SET,
            {peer_id: time.time()},
            max_entries=50,
        )
        self.r.hset(self.constants.P2P_PEER_INFO_HASH, peer_id, td)
        self.r.hexpire(
            self.constants.P2P_PEER_INFO_HASH,
            self.extended_ttl,
            peer_id,
            nx=True,
        )

    def get_peer_td(self, peer_id: str):
        """
        Get peer trust data by peer_id.
        """
        return self.r.hget(self.constants.P2P_PEER_INFO_HASH, peer_id)

    def store_peer_trust_data(self, peer_id: str, updated_td: str):
        """
        Update peer information.
        """
        if self.r.zscore(self.constants.P2P_TRUST_SET, peer_id) is not None:
            self.r.hset(self.constants.P2P_PEER_INFO_HASH, peer_id, updated_td)
            self.r.hexpire(
                self.constants.P2P_PEER_INFO_HASH,
                self.extended_ttl,
                peer_id,
                nx=True,
            )
        else:
            self._store_peer_td(peer_id, updated_td)

    def remove_peer_td(self, peer_id: str):
        """
        Remove a peer trust data from the set and hash.
        """
        self.r.zrem(self.constants.P2P_TRUST_SET, peer_id)
        self.r.hdel(self.constants.P2P_PEER_INFO_HASH, peer_id)

    def is_p2p_related_flow(self, srcip, sport, dstip, dport, proto) -> bool:
        """Check whether a flow's 5-tuple matches a known P2P connection.

        Single-flow convenience wrapper around
        :meth:`is_p2p_related_flow_batch`. Prefer the batch method when
        checking more than one flow, since it costs one redis round trip
        total instead of one per flow.

        Parameters:
            srcip: Source IP of the flow.
            sport: Source port of the flow.
            dstip: Destination IP of the flow.
            dport: Destination port of the flow.
            proto: Transport protocol of the flow (e.g. "tcp").

        Returns:
            True if the flow matches a stored P2P connection tuple.
        """
        return self.is_p2p_related_flow_batch(
            [(srcip, sport, dstip, dport, proto)]
        )[0]

    def is_p2p_related_flow_batch(self, flows: Sequence[Tuple]) -> List[bool]:
        """Check many flow 5-tuples against known P2P connections at once.

        The p2p4slips Go daemon stores each authenticated P2P TCP
        connection it holds directly in the ``p2p:connections`` redis
        set, as ``"{protocol}|{local_ip}|{local_port}|{remote_ip}|
        {remote_port}"`` entries. A flow matches if its tuple (or the
        reverse of it, since either side of the flow may be the local
        or remote endpoint) is a member of that set.

        All ``SISMEMBER`` checks for every flow are sent in a single
        pipelined round trip, instead of one round trip per flow (or
        per flow per direction), to keep the cost of checking many
        flows (e.g. every uid behind one evidence) close to the cost
        of a single redis call.

        Parameters:
            flows: Sequence of (srcip, sport, dstip, dport, proto) tuples.

        Returns:
            One bool per input flow, in the same order, True where the
            flow matches a stored P2P connection tuple.
        """
        if not flows:
            return []
        pipe = self.r.pipeline(transaction=False)
        for srcip, sport, dstip, dport, proto in flows:
            proto = str(proto or "").lower()
            entry = f"{proto}|{srcip}|{sport}|{dstip}|{dport}"
            reverse_entry = f"{proto}|{dstip}|{dport}|{srcip}|{sport}"
            pipe.sismember(self.constants.P2P_CONNECTIONS, entry)
            pipe.sismember(self.constants.P2P_CONNECTIONS, reverse_entry)
        results = pipe.execute()
        return [
            bool(results[i] or results[i + 1])
            for i in range(0, len(results), 2)
        ]

    def cache_network_opinion(self, target: str, opinion: dict, time: float):
        cache_key = f"{self.constants.FIDES_CACHE_KEY}:{target}"

        cache_data = {
            self.constants.FIDES_CACHE_CREATED_SECONDS: time,
            **opinion,
        }
        self.r.hmset(cache_key, cache_data)
        self.r.expire(cache_key, self.default_ttl, nx=True)

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
        self.r.hexpire(
            self.constants.PEER_TRUST,
            self.extended_ttl,
            peer_ip,
            nx=True,
        )

    def get_peer_trust(self, peer_ip):
        trust = self.r.hget(self.constants.PEER_TRUST, peer_ip)
        if trust:
            return float(trust)
        return None

    def record_p2p_message(self, direction: str, message: dict) -> None:
        """Record one bounded P2P send or receive event for observability.

        Parameters:
            direction: Either ``sent`` or ``received``.
            message: JSON-serializable message metadata.
        """
        message_type = str(message.get("message_type") or "unknown")
        record = {"direction": direction, "timestamp": time.time(), **message}
        key = self._p2p_message_counts_key()
        field = f"{direction}:{message_type}"
        with self.r.pipeline() as pipe:
            pipe.hincrby(key, field, 1)
            # safety net in case the timewindow-end cleanup is ever missed
            pipe.hexpire(key, self.default_ttl, field, nx=True)
            pipe.execute()
        self.r.lpush(self.constants.P2P_MESSAGE_HISTORY, json.dumps(record))
        self.r.ltrim(self.constants.P2P_MESSAGE_HISTORY, 0, 999)

    def _p2p_message_counts_key(self) -> str:
        """Per-timewindow key so old counters don't accumulate forever."""
        timewindow = self.get_current_timewindow() or 1
        return f"{self.constants.P2P_MESSAGE_COUNTS}_{timewindow}"

    def get_p2p_message_telemetry(self) -> dict:
        """Return P2P message counters and newest bounded activity.

        Returns:
            Message counters and decoded recent message records.
        """
        records = []
        for raw in self.r.lrange(self.constants.P2P_MESSAGE_HISTORY, 0, 199):
            try:
                records.append(json.loads(raw))
            except (TypeError, ValueError):
                continue
        return {
            "counts": self.r.hgetall(self._p2p_message_counts_key()),
            "activity": records,
        }
