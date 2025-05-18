from threading import Lock
import time
from typing import Callable
from slips_files.common.abstracts.unblocker import IUnblocker
from slips_files.common.printer import Printer
from slips_files.common.slips_utils import utils
from slips_files.core.structures.evidence import TimeWindow


class ARPUnblocker(IUnblocker):
    """
    For every blocking module in slips, there should be an unblocker
    implemented
    this is the unblocker for the arp poisoner.
    """

    name = "arp_poisoner_unblocker"

    def __init__(self, db, should_stop: Callable, logger, log: Callable):
        IUnblocker.__init__(self, db)
        # this is the blocking module's should_stop method
        # the goal is to stop the threads started by this module when the
        # blocking module's should_stop returns True
        self.should_stop = should_stop
        # this logger's main purpose is to start the printer
        self.logger = logger
        self.printer = Printer(self.logger, self.name)
        # this log method is used to log unblocking requests to blocking.log
        self.log = log
        self.requests_lock = Lock()
        self.requests = {}

    def print(self, *args, **kwargs):
        return self.printer.print(*args, **kwargs)

    def unblock_request(
        self,
        ip: str,
        current_tw: int,
    ):
        """
        schedules unblocking for the given ip for the next timewindow.
        """
        if ip in self.requests:
            # ip is already blocked, extend the blocking by 1 tw
            tws = self.requests[ip]["block_this_ip_for"]
            block_this_ip_for = tws + 1
        else:
            # measured in tws
            block_this_ip_for = 1

        tw_to_unblock_at: TimeWindow = self._get_tw_to_unblock_at(
            ip, current_tw, block_this_ip_for
        )
        self._add_req(ip, current_tw, tw_to_unblock_at, block_this_ip_for)

    def _check_if_time_to_unblock(self, ip: str):
        """
        Checks if the poisoning period of the given ip is over.
        If so, it deletes the ip's request from self.requests.
        so that the arp poisoner would stop poisoning it reqularly.
        """
        request = self.requests[ip]
        ts: str = request["tw_to_unblock"].end_time
        ts: float = utils.convert_ts_format(ts, "unixtimestamp")
        if time.time() < ts:
            return

        self._del_request(ip)
        self._log_successful_unblock(ip)

    def _log_successful_unblock(self, ip):
        blocking_ts: float = self.db.get_blocking_timestamp(ip)
        now = time.time()

        blocking_hrs: int = utils.get_time_diff(blocking_ts, now, "hours")
        blocking_hrs = round(blocking_hrs, 1)

        blocking_tws: int = self.db.get_equivalent_tws(blocking_hrs)
        printable_blocking_ts = utils.convert_ts_format(
            blocking_ts, utils.alerts_format
        )
        printable_now = utils.convert_ts_format(now, utils.alerts_format)
        txt = (
            f"Done poisoning {ip}. The poisoning lasted {blocking_tws} "
            f"timewindows. ({blocking_hrs}hrs - "
            f"From {printable_blocking_ts} to {printable_now})."
        )
        self.log(txt)

    def update_requests(self):
        """
        is called whenever a new timewindow starts. (on msgs to tw_closed)
        the only purpose of this is to keep track of how many tws the ips in
        self.requests will stay blocked for.
        it answers this question
        "how many extra tws should IP X stay blocked in?"
        """
        new_requests = {}
        with self.requests_lock:
            for ip, req in self.requests.items():
                new_req = req
                new_req["block_this_ip_for"] = req["block_this_ip_for"] - 1
                new_requests[ip] = new_req
            self.requests = new_requests

    def _add_req(
        self,
        ip: str,
        current_tw: str,
        tw_to_unblock_at: TimeWindow,
        block_this_ip_for: int,
    ):
        """
        Add an unblocking request to self.requests
        :param tw_to_unblock_at: unix ts to unblock the given ip at
        :param block_this_ip_for: number of following timewindows this ip
        will remain blocked in.
        """
        with self.requests_lock:
            self.requests[ip] = {
                "tw_to_unblock": tw_to_unblock_at,
                "block_this_ip_for": block_this_ip_for,
            }

        interval = self.requests[ip]["block_this_ip_for"]
        self.log(
            f"Current TW: {current_tw}. Registered a request to stop "
            f"poisoning {ip} at the end "
            f"of timewindow: {tw_to_unblock_at}. IP will be "
            f"poisoned for {interval} timewindows. "
            f"Timestamp to stop poisoning: {tw_to_unblock_at.end_time}) "
        )

    def _del_request(self, ip):
        """Delete an unblocking request from self.requests"""
        if ip in self.requests:
            with self.requests_lock:
                del self.requests[ip]
