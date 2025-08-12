# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from abc import ABC, abstractmethod
from threading import Thread

from slips_files.common.slips_utils import utils
from slips_files.core.database.database_manager import DBManager
from slips_files.core.structures.evidence import TimeWindow


class IUnblocker(ABC):
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
            target=self.check_if_time_to_unblock,
            daemon=True,
            name=f"{self.name}_unblocking_checker",
        )
        self.requests = {}

    @abstractmethod
    def _add_req(self, *args, **kwargs):
        """Add an unblocking request to self.requests"""

    @abstractmethod
    def del_request(self, *args, **kwargs):
        """Delete an unblocking request from self.requests"""

    @abstractmethod
    def unblock_request(self, *args, **kwargs):
        """
        Only public method.
        Used by the blocking module to request an unblock
        """

    @abstractmethod
    def check_if_time_to_unblock(self):
        """a bg thread that unblocks ips once their ts is reached"""
        ...

    async def _get_tw_to_unblock_at(
        self, ip: str, cur_tw: int, how_many_tws_to_block: int
    ) -> TimeWindow:
        """
        Calculates the timestamp to unblock.
        It adds how_many_tws_to_block to the current time window and
        returns the resulting timewindow
        """
        # we unblock at the end of this tw
        tw_to_unblock: int = cur_tw + how_many_tws_to_block
        tw_start, tw_end = await self.db.get_tw_limits(
            f"profile_{ip}", f"timewindow{tw_to_unblock}"
        )
        tw_start: str = utils.convert_ts_format(tw_start, "iso")
        tw_end: str = utils.convert_ts_format(tw_end, "iso")
        return TimeWindow(
            number=tw_to_unblock, start_time=tw_start, end_time=tw_end
        )
