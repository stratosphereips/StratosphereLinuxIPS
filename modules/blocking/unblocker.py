from threading import Lock
import time
import threading
from typing import Dict, Callable
from slips_files.common.abstracts.unblocker import IUnblocker
from slips_files.common.printer import Printer
from slips_files.common.slips_utils import utils
from slips_files.core.structures.evidence import TimeWindow
from modules.blocking.exec_iptables_cmd import exec_iptables_command


class Unblocker(IUnblocker):
    """
    For every blocking method in slips, there should be an unblocker
    implemented
    """

    name = "iptables_unblocker"

    def __init__(self, db, sudo, should_stop: Callable, logger, log: Callable):
        IUnblocker.__init__(self, db)
        # this is the blocking module's should_stop method
        # the goal is to stop the threads started by this module when the
        # blocking module's should_stop returns True
        self.should_stop = should_stop
        # this logger's main purpose is to start the printer
        self.logger = logger
        self.printer = Printer(self.logger, self.name)
        self.sudo = sudo
        # this log method is used to log unblocking requests to blocking.log
        self.log = log
        self.requests_lock = Lock()
        self.requests = {}
        self._start_checker_thread()

    def print(self, *args, **kwargs):
        return self.printer.print(*args, **kwargs)

    def _start_checker_thread(self):
        self.unblocker_thread = threading.Thread(
            target=self._check_if_time_to_unblock,
            daemon=True,
            name="iptables_unblocker_thread",
        )
        utils.start_thread(self.unblocker_thread, self.db)

    def unblock_request(
        self,
        ip: str,
        how_many_tws_to_block: int,
        current_tw: int,
        flags: Dict[str, str],
    ):
        # if this ip was blocked, and is still setting alerts, how many tws
        # to extend its blocking?
        extend_blocking_for = 1
        # first check if there's already an unblocking request, if so,
        # we extend the blocking 1 more timewindow.
        try:
            print(
                f"@@@@@@@@@@@@@@@@ !!!!!!!!!!!!!!!!!!!!!!!! Extending "
                f"the blockinnnnggg for {ip}"
            )
            tw_to_unblock_at: TimeWindow = self.requests[ip]["tw_to_unblock"]
            tw_to_unblock_at: TimeWindow = self._get_tw_to_unblock_at(
                ip,
                tw_to_unblock_at.number + extend_blocking_for,
                how_many_tws_to_block,
            )
            self.log(
                f"Extending the blocking period for {ip} for"
                f" {extend_blocking_for} extra timewindow."
            )
        except KeyError:
            print(f"@@@@@@@@@@@@@@@@ unblock_request for ip {ip}")
            tw_to_unblock_at: TimeWindow = self._get_tw_to_unblock_at(
                ip, current_tw, how_many_tws_to_block
            )
            print(
                f"@@@@@@@@@@@@@@@@ unblocking {ip} at the end of {tw_to_unblock_at}"
            )

        self._add_req(ip, tw_to_unblock_at, flags)

    def _check_if_time_to_unblock(self):
        """
        This method should be called in a thread that checks the timestamps
        in self.requests regularly.
        Each time a ts is reached, it should call _unblock()
        """
        while not self.should_stop():
            now = time.time()
            requests_to_del = []

            for ip, request in self.requests.items():
                ts: str = request["tw_to_unblock"].end_time
                ts: float = utils.convert_ts_format(ts, "unixtimestamp")
                print(
                    f"@@@@@@@@@@@@@@@@ [_check_if_time_to_unblock]"
                    f" checking if time to unvblock {ip} {request}"
                )
                if ts >= now:
                    print(
                        f"@@@@@@@@@@@@@@@@ time to unblock {ip} in the "
                        f"fw {request}"
                    )
                    flags: Dict[str, str] = request["flags"]
                    if self._unblock(ip, flags):
                        self._log_successful_unblock(ip)
                        self.db.del_blocked_ip(ip)
                        requests_to_del.append(ip)

            for ip in requests_to_del:
                print(
                    f"@@@@@@@@@@@@@@@@ [_check_if_time_to_unblock] "
                    f"seleting request for {ip}"
                )

                self._del_request(ip)
            print("@@@@@@@@@@@@@@@@ [_check_if_time_to_unblock] sleeping 10")
            time.sleep(10)

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
            f"The blocking of {ip} lasted {blocking_tws} timewindows. "
            f"({blocking_hrs}hrs - "
            f"From {printable_blocking_ts} to {printable_now})"
        )
        self.log(txt)

    def _add_req(
        self, ip: str, tw_to_unblock_at: TimeWindow, flags: Dict[str, str]
    ):
        """
        Add an unblocking request to self.requests
        :param tw_to_unblock_at: unix ts to unblock the given ip at
        """
        with self.requests_lock:
            self.requests[ip] = {
                "tw_to_unblock": tw_to_unblock_at,
                "flags": flags,
            }

        self.log(
            f"Registered unblocking request to unblock {ip} at the end "
            f"of the next timewindow. "
            f"Timewindow to unblock: {tw_to_unblock_at} "
            f"Timestamp to unblock: {tw_to_unblock_at.end_time}) "
        )
        print(f"@@@@@@@@@@@@@@@@ added req for {ip} ")
        from pprint import pp

        pp(self.requests)

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
        from_ = flags.get("from_")
        to = flags.get("to")
        dport = flags.get("dport")
        sport = flags.get("sport")
        protocol = flags.get("protocol")

        # This dictionary will be used to construct the rule
        options = {
            "protocol": f" -p {protocol}" if protocol else "",
            "dport": f" --dport {dport}" if dport else "",
            "sport": f" --sport {sport}" if sport else "",
        }
        # Set the default behaviour to unblock all traffic from and to an ip
        if from_ is None and to is None:
            from_, to = True, True

        # Set the appropriate iptables flag to use in the command
        # The module sending the message HAS TO specify either
        # 'from_' or 'to' or both
        # so that this function knows which rule to delete
        # if both or none were specified we'll be unblocking all traffic from
        # and to the given ip
        unblocked = False
        # Block traffic from source ip
        if from_:
            unblocked = exec_iptables_command(
                self.sudo,
                action="delete",
                ip_to_block=ip_to_unblock,
                flag="-s",
                options=options,
            )

        # Block traffic to distination ip
        if to:
            unblocked = exec_iptables_command(
                self.sudo,
                action="delete",
                ip_to_block=ip_to_unblock,
                flag="-d",
                options=options,
            )

        if unblocked:
            cur_timewindow = self.db.get_timewindow(
                time.time(), f"profile_{ip_to_unblock}"
            )
            txt = f"IP {ip_to_unblock} is unblocked in {cur_timewindow}."
            self.print(txt)
            self.log(txt)
            print(f"@@@@@@@@@@@@@@@@ unblocked {ip_to_unblock} in the fw")
            return True
        else:
            txt = f"An errror occured. Unable to unblock {ip_to_unblock}"
            self.print(txt)
            self.log(txt)
            return False
