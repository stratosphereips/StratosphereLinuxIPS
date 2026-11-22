# SPDX-License-Identifier: GPL-2.0-only
"""Reverse DNS lookups of the IPs seen by Slips."""

import ipaddress
import socket
import time
from functools import lru_cache
from typing import Any, Awaitable, Callable

from modules.ip_info.negative_cache import NegativeCache
from slips_files.core.database.database_manager import DBManager


class RDNS:
    """Resolve the reverse DNS name of IPs and remember each outcome."""

    def __init__(self, db: DBManager) -> None:
        """Start with no failed lookups.

        Parameters:
            db: Database manager of the ip_info module.
        """
        self.db = db
        # to avoid repeated failed rdns lookups. we wait 300s before retries.
        self.failed_lookups = NegativeCache()

    def get_ip_family(self, ip: str) -> int:
        """
        returns the family of the IP, AF_INET or AF_INET6
        :param ip: str
        """
        return self._get_ip_family_cached(ip)

    @staticmethod
    @lru_cache(maxsize=1024)
    def _get_ip_family_cached(ip: str) -> int:
        """
        Return the socket address family for an IP-like string.

        :param ip: IP address or IP-like string.
        :return: AF_INET6 when the value contains ':', otherwise AF_INET.
        """
        return socket.AF_INET6 if ":" in ip else socket.AF_INET

    def _save_rdns_result(
        self, ip: str, status: str, hostname: str = ""
    ) -> dict | bool:
        """Cache a reverse lookup result, including unsuccessful attempts.

        Parameters:
            ip: Address queried using the system resolver.
            status: resolved, no_record, or error.
            hostname: Returned name, when the lookup succeeded.

        Returns:
            The resolved name mapping, or False when no name was found.
        """
        now = time.time()
        retry_delay = (
            86400
            if status == "no_record" and ipaddress.ip_address(ip).is_global
            else self.failed_lookups.ttl_seconds
        )
        rdns_info = {"reverse_dns": hostname} if hostname else {}
        self.db.set_ip_info(
            ip,
            {
                **rdns_info,
                "reverse_dns_lookup": {
                    "status": status,
                    "checked_at": now,
                    "retry_after": now + retry_delay,
                },
            },
        )
        if hostname:
            self.failed_lookups.remove(ip)
        else:
            self.failed_lookups.add(ip)
        return rdns_info or False

    def get_rdns(self, ip: str) -> dict | bool:
        """
        get reverse DNS of an ip
        returns RDNS of the given ip or False if not found
        :param ip: str
        """
        if self.failed_lookups.has(ip):
            return False
        previous_lookup = self.db.get_ip_info(ip, "reverse_dns_lookup")
        if (
            isinstance(previous_lookup, dict)
            and previous_lookup.get("retry_after", 0) > time.time()
        ):
            return False
        try:
            # works with both ipv4 and ipv6
            reverse_dns: str = socket.gethostbyaddr(ip)[0]
            # if there's no reverse dns record for this ip, reverse_dns will be an ip.
            try:
                # check if the reverse_dns value is a valid IP address
                socket.inet_pton(self.get_ip_family(reverse_dns), reverse_dns)
                # reverse_dns is an ip. there's no reverse dns. don't store
                return self._save_rdns_result(ip, "no_record")
            except socket.error:
                # reverse_dns is a valid hostname, store it
                return self._save_rdns_result(ip, "resolved", reverse_dns)
        except (socket.gaierror, socket.herror) as error:
            is_record_missing = (
                isinstance(error, socket.herror) and error.errno in (1, 4)
            ) or (
                isinstance(error, socket.gaierror)
                and error.errno
                in (
                    socket.EAI_NONAME,
                    getattr(socket, "EAI_NODATA", socket.EAI_NONAME),
                )
            )
            return self._save_rdns_result(
                ip, "no_record" if is_record_missing else "error"
            )
        except OSError:
            return self._save_rdns_result(ip, "error")

    async def get_rdns_async(
        self, ip: str, run_in_executor: Callable[..., Awaitable[Any]]
    ) -> dict | bool:
        """Resolve reverse DNS without blocking the event loop.

        Parameters:
            ip: IP address to resolve.
            run_in_executor: Async helper that runs blocking callables in
                a bounded executor.

        Returns:
            Reverse DNS mapping, or False if not found.
        """
        return await run_in_executor(self.get_rdns, ip)

    def clear_caches(self) -> None:
        """Free the cached address families when the module stops."""
        self._get_ip_family_cached.cache_clear()
