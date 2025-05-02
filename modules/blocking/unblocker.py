from threading import Lock
from typing import Dict
from slips_files.common.abstracts.unblocker import IUnblocker
from slips_files.core.structures.evidence import TimeWindow


class Unblocker(IUnblocker):
    """
    For every blocking method in slips, there should be an unblocker
    implemented
    """

    name = "iptables_unblocker"

    def __init__(self, db):
        IUnblocker.__init__(self, db)
        self.requests_lock = Lock()
        self.requests = {}

    def unblock_request(
        self,
        ip: str,
        how_many_tws_to_block: int,
        current_tw: int,
        flags: Dict[str, str],
    ):
        tw_to_unblock_at: TimeWindow = self._calc_unblock_time(
            ip, current_tw, how_many_tws_to_block
        )
        self._add_req(ip, tw_to_unblock_at, flags)

    def _check_if_time_to_unblock(self):
        """
        This method should be called in a thread that checks the timestamps
        in self.requests regularly.
        Each time a ts is reached, it should call _unblock()
        """
        ...

    def _add_req(
        self, ip: str, tw_to_unblock_at: TimeWindow, flags: Dict[str, str]
    ):
        """
        Add an unblocking request to self.requests
        :param ts_to_unblock: unix ts to unblock the given ip at
        """
        with self.requests_lock:
            self.requests[ip] = {
                "tw_to_unblock": tw_to_unblock_at,
                "flags": flags,
            }

    def _del_request(self, ip):
        """Delete an unblocking request from self.requests"""
        if ip in self.requests:
            with self.requests_lock:
                del self.requests[ip]

    def _unblock(
        self,
        ip_to_unblock,
        flags: Dict[str, str],
    ):
        """Unblocks an ip based on the given flags"""

        ...
