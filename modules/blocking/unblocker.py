from threading import Lock
import time
from typing import Dict
from slips_files.common.abstracts.unblocker import IUnblocker
from slips_files.core.structures.evidence import TimeWindow


class Unblocker(IUnblocker):
    """
    For every blocking method in slips, there should be an unblocker
    implemented
    """

    name = "iptables_unblocker"

    def __init__(self, db, sudo):
        IUnblocker.__init__(self, db)
        self.sudo = sudo
        self.requests_lock = Lock()
        self.requests = {}

    def unblock_request(
        self,
        ip: str,
        how_many_tws_to_block: int,
        current_tw: int,
        flags: Dict[str, str],
    ):
        print(f"@@@@@@@@@@@@@@@@ unblock_request for ip {ip}")
        tw_to_unblock_at: TimeWindow = self._calc_unblock_time(
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
        while True:
            now = time.time()
            requests_to_del = []

            for ip, request in self.requests.items():
                ts: float = self.request["tw_to_unblock"].end_time
                flags: Dict[str, str] = self.request["flags"]
                print(
                    f"@@@@@@@@@@@@@@@@ [_check_if_time_to_unblock]"
                    f" checking if time to unvblock {ip} {request}"
                )
                if ts >= now:
                    print(
                        f"@@@@@@@@@@@@@@@@ time to unblock {ip} in the "
                        f"fw {request}"
                    )
                    if self._unblock(ip, flags):
                        requests_to_del.append(ip)

            for ip in requests_to_del:
                print(
                    f"@@@@@@@@@@@@@@@@ [_check_if_time_to_unblock] "
                    f"seleting request for {ip}"
                )

                self._del_req(ip)
            print("@@@@@@@@@@@@@@@@ [_check_if_time_to_unblock] sleeping 5")
            time.sleep(5)

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
            unblocked = self.exec_iptables_command(
                action="delete",
                ip_to_block=ip_to_unblock,
                flag="-s",
                options=options,
            )

        # Block traffic to distination ip
        if to:
            unblocked = self.exec_iptables_command(
                action="delete",
                ip_to_block=ip_to_unblock,
                flag="-d",
                options=options,
            )

        if unblocked:
            self.print(f"Unblocked: {ip_to_unblock}")
            print(f"@@@@@@@@@@@@@@@@ unblocked {ip_to_unblock} in the fw")
            return True

        return False
