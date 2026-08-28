from threading import Lock
import time
import threading
from typing import Dict, Callable
from slips_files.common.abstracts.iunblocker import IUnblocker
from slips_files.common.printer import Printer
from slips_files.common.slips_utils import utils
from slips_files.core.structures.evidence import TimeWindow
from modules.blocking.exec_iptables_cmd import delete_slips_rules_for_ip


class Unblocker(IUnblocker):
    """
    For every blocking module in slips, there should be an unblocker
    implemented
    this is the one for the firewall blocker.
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
        self._restore_requests()
        self._start_checker_thread()

    def _restore_requests(self) -> None:
        """Restore persisted unblock schedules after a blocker restart."""
        states = self.db.get_firewall_block_states()
        if not isinstance(states, dict):
            return
        for ip, state in states.items():
            if not isinstance(state, dict) or not state.get("unblock_at"):
                continue
            try:
                timewindow = TimeWindow(
                    number=-1,
                    end_time=str(state["unblock_at"]),
                )
                remaining = max(0, int(state.get("remaining_timewindows", 0)))
            except (TypeError, ValueError):
                continue
            self.requests[str(ip)] = {
                "tw_to_unblock": timewindow,
                "block_this_ip_for": remaining,
                "flags": state.get("flags", {}),
            }

    def print(self, *args, **kwargs):
        return self.printer.print(*args, **kwargs)

    def _start_checker_thread(self):
        self.unblocker_thread = threading.Thread(
            target=self.check_if_time_to_unblock,
            daemon=True,
            name="iptables_unblocker_thread",
        )
        utils.start_thread(self.unblocker_thread, self.db)

    def unblock_request(
        self,
        ip: str,
        current_tw: int,
        flags: Dict[str, str],
    ) -> Dict[str, object]:
        """
        schedules unblocking for the given ip for the next timewindow.
        """
        request = self.prepare_unblock_request(ip, current_tw, flags)
        self.register_unblock_request(ip, request)
        return request

    def prepare_unblock_request(
        self,
        ip: str,
        current_tw: int,
        flags: Dict[str, str],
    ) -> Dict[str, object]:
        """Calculate an unblock request without mutating firewall state.

        Parameters:
            ip: Address being blocked or extended.
            current_tw: Current profile time-window number.
            flags: Firewall direction and optional transport selectors.

        Returns:
            Request containing the deadline, duration and copied flags.
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
        return {
            "tw_to_unblock": tw_to_unblock_at,
            "block_this_ip_for": block_this_ip_for,
            "flags": dict(flags),
        }

    def register_unblock_request(
        self, ip: str, request: Dict[str, object]
    ) -> None:
        """Persist and activate a previously calculated unblock request.

        Parameters:
            ip: Address owned by the request.
            request: Result returned by prepare_unblock_request.
        """
        self._add_req(
            ip,
            request["tw_to_unblock"],
            request["flags"],
            request["block_this_ip_for"],
        )

    def check_if_time_to_unblock(self):
        """
        This method should be called in a thread that checks the timestamps
        in self.requests regularly.
        Each time a ts is reached, it should call _unblock()
        """
        while not self.should_stop():
            now = time.time()
            with self.requests_lock:
                for ip, request in list(self.requests.items()):
                    try:
                        timestamp: str = request["tw_to_unblock"].end_time
                        deadline = float(
                            utils.convert_ts_format(timestamp, "unixtimestamp")
                        )
                    except (AttributeError, TypeError, ValueError) as error:
                        message = f"Unable to read unblock deadline for {ip}: {error}"
                        self.print(message, 0, 1)
                        self.log(message)
                        continue
                    if now < deadline:
                        continue
                    flags: Dict[str, str] = request["flags"]
                    if self._unblock(ip, flags):
                        self._log_successful_unblock(ip)
                        self.db.del_blocked_ip(ip)
                        self.db.del_firewall_block_state(ip)
                        self.requests.pop(ip, None)
            time.sleep(10)

    def _log_successful_unblock(self, ip: str) -> None:
        """Log how long an IP was blocked when its start time is known.

        Parameters:
            ip: IP address whose firewall rules were removed.
        """
        blocking_ts: float = self.db.get_blocking_timestamp(ip)
        if blocking_ts is None:
            self.log(
                f"The blocking of {ip} ended; its start time was unavailable."
            )
            return
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

    def update_requests(self):
        """
        is called whenever a new timewindow starts. (on msgs to tw_closed)
        the only purpose of this is to keep track of how many tws the ips in
        self.requests will stay blocked for.
        it answers this question
        "how many extra tws should IP X stay blocked in?"
        """
        with self.requests_lock:
            for ip, req in self.requests.items():
                remaining = max(0, req["block_this_ip_for"] - 1)
                req["block_this_ip_for"] = remaining
                self.db.set_firewall_block_state(
                    ip,
                    self._firewall_state(req, remaining),
                )

    def _firewall_state(
        self, request: Dict[str, object], remaining: int
    ) -> Dict[str, object]:
        """Build the persisted representation of an unblock request.

        Parameters:
            request: Active in-memory unblock request.
            remaining: Number of additional full time windows.

        Returns:
            Serializable firewall state for Redis and the web interface.
        """
        flags = request["flags"]
        state: Dict[str, object] = {
            "unblock_at": request["tw_to_unblock"].end_time,
            "remaining_timewindows": remaining,
            "flags": flags,
            "updated_at": time.time(),
        }
        for state_key, flag_key in (
            ("recovered", "_recovered"),
            ("recovery_status", "_recovery_status"),
            ("origin_run", "_origin_run"),
            ("rule_comment", "rule_comment"),
        ):
            if flags.get(flag_key) is not None:
                state[state_key] = flags[flag_key]
        return state

    def _add_req(
        self,
        ip: str,
        tw_to_unblock_at: TimeWindow,
        flags: Dict[str, str],
        block_this_ip_for: int,
    ):
        """Add or replace an IP's scheduled unblock request.

        Parameters:
            ip: IP address whose firewall rules must later be removed.
            tw_to_unblock_at: Time window containing the unblock deadline.
            flags: Rule direction and optional transport selectors.
            block_this_ip_for: Remaining time windows for the block.
        """
        request = {
            "tw_to_unblock": tw_to_unblock_at,
            "block_this_ip_for": block_this_ip_for,
            "flags": flags,
        }
        self.db.set_firewall_block_state(
            ip,
            self._firewall_state(request, block_this_ip_for),
        )
        with self.requests_lock:
            self.requests[ip] = request

        interval = self.requests[ip]["block_this_ip_for"]
        self.log(
            f"Registered unblocking request to unblock {ip} at the end "
            f"of the next timewindow. {tw_to_unblock_at}. IP will be "
            f"blocked for {interval} timewindows. "
            f"Timestamp to unblock: {tw_to_unblock_at.end_time}) "
        )

    def del_request(self, ip):
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
        if delete_slips_rules_for_ip(self.sudo, ip_to_unblock, flags):
            cur_timewindow = self.db.get_timewindow(
                time.time(), f"profile_{ip_to_unblock}"
            )
            txt = f"IP {ip_to_unblock} is unblocked in {cur_timewindow}."
            self.print(txt)
            self.log(txt)
            return True
        else:
            txt = f"An errror occured. Unable to unblock {ip_to_unblock}"
            self.print(txt)
            self.log(txt)
            return False
