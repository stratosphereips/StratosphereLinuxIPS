"""Read enforcement exemptions from the local whitelist file."""

# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

import ipaddress
import time
from pathlib import Path
from typing import Any

from slips_files.core.helpers.whitelist.whitelist_parser import (
    WhitelistParser,
    web_whitelist_path,
)


class BlockingWhitelist:
    """Cache blocking-only rules without touching the flow processing path."""

    def __init__(self, manager: Any) -> None:
        """Configure the file reader for an enforcement module or worker.

        Parameters:
            manager: Owner providing configuration, database and printer.
        """
        self.manager = manager
        self.enabled = manager.conf.enable_local_whitelist()
        self.path = manager.conf.local_whitelist_path()
        self._ips: set[str] = set()
        self._fingerprint: tuple | None = None
        self._next_check = 0.0

    def addresses(self) -> set[str]:
        """Refresh changed whitelist files at most once every two seconds.

        Returns:
            IP addresses protected from firewall blocking and ARP poisoning.
        """
        if not self.enabled:
            return set()
        now = time.monotonic()
        if now < self._next_check:
            return self._ips
        fingerprints = []
        for path in (Path(self.path), web_whitelist_path(self.path)):
            try:
                stat = path.stat()
                fingerprints.append(
                    (stat.st_ino, stat.st_mtime_ns, stat.st_size)
                )
            except FileNotFoundError:
                fingerprints.append(None)
        fingerprint = tuple(fingerprints)
        if fingerprint != self._fingerprint:
            parser = WhitelistParser(self.manager.db, self.manager)
            parser.local_whitelist_path = self.path
            parser.parse()
            self._ips = {
                str(ipaddress.ip_address(ip))
                for ip, rule in parser.whitelisted_ips.items()
                if rule["what_to_ignore"] == "blocking"
            }
            self._fingerprint = fingerprint
        self._next_check = now + 2
        return self._ips

    def is_exempt(self, ip: str) -> bool:
        """Check the address being acted on, independently of alert matching.

        Parameters:
            ip: Firewall or ARP poisoning target address.

        Returns:
            Whether a blocking-only whitelist rule protects this address.
        """
        try:
            address = str(ipaddress.ip_address(ip))
        except ValueError:
            return False
        return address in self.addresses()
