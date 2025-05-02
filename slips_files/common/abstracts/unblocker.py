# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from abc import ABC, abstractmethod
import time
from datetime import datetime
from threading import Thread
from slips_files.core.database.database_manager import DBManager
from slips_files.core.structures.evidence import TimeWindow


class Unblocker(ABC):
    """
    For every blocking method in slips, there should be an unblocker
    implemented
    """

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    def __init__(self, db: DBManager):
        self.db = db
        self.checker = Thread(
            target=self._check_if_time_to_unblock,
            daemon=True,
            name=f"{self.name}_unblocking_checker",
        )
        self.requests = {}

    @abstractmethod
    def _add_req(self, *args, **kwargs):
        """Add an unblocking request to self.requests"""

    @abstractmethod
    def _del_request(self, *args, **kwargs):
        """Delete an unblocking request from self.requests"""

    @abstractmethod
    def unblock_request(self, *args, **kwargs):
        """
        Only public method.
        Used by the blocking module to request an unblock
        """

    @abstractmethod
    def _unblock(self, *args, **kwargs):
        """
        Should contain the logic to unblock, throught the FW for
        example.
        is called whenever a ts is reached in _check_if_time_to_unblock()
        to do the actual unblocking
        """

    def _check_if_time_to_unblock(self):
        """
        This method should be called in a thread that checks the timestamps
        in self.requests regularly.
        Each time a ts is reached, it should call _unblock()
        """
        while True:
            requests_to_del = []

            now = datetime.now().replace(microsecond=0)
            for ip, request in self.requests.items():
                ts = self.request["ts_to_unblock"]
                if ts >= now:
                    if self._unblock(ip):
                        requests_to_del.append(ip)

            for ip in requests_to_del:
                self._del_req(ip)

            time.sleep(1)  # sleep 1 second between checks

    def _calc_unblock_time(
        self, ip: str, cur_tw: TimeWindow, how_many_tws_to_block
    ) -> TimeWindow:
        """
        Calculates the timestamp to unblock.
        It adds how_many_tws_to_block to the current time window and
        returns the resulting timewindow
        """
        # we unblock at the end of this tw
        tw_to_unblock: int = cur_tw.number + how_many_tws_to_block
        tw_start, tw_end = self.db.get_tw_limits(
            f"profile_{ip}", f"timewindow{tw_to_unblock}"
        )
        return TimeWindow(
            number=tw_to_unblock, start_time=tw_start, end_time=tw_end
        )
