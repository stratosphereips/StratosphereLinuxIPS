# SPDX-License-Identifier: GPL-2.0-only
"""Vendor lookups of the MAC addresses seen by Slips."""

import asyncio
import json
from multiprocessing.synchronize import SEM_VALUE_MAX
from queue import Queue
from typing import Any, Awaitable, Callable

import requests

from modules.ip_info.negative_cache import NegativeCache
from slips_files.common.mac import classify_mac
from slips_files.common.slips_utils import utils
from slips_files.core.database.database_manager import DBManager


class MACVendor:
    """Find the vendor of a MAC address, offline first, then online."""

    def __init__(self, db: DBManager) -> None:
        """Start with the offline MAC database not loaded yet.

        Parameters:
            db: Database manager of the ip_info module.
        """
        self.db = db
        # MAC lookups stay in this process, so they need no shared semaphore.
        self.pending_mac_queries = Queue(maxsize=min(30000000, SEM_VALUE_MAX))
        self.failed_online_lookups = NegativeCache()
        self.mac_vendor_db_loaded = False

    async def read_mac_db(self) -> bool | None:
        """
        waits 10 mins for the update manager to download the mac db and
        opens it for reading. retries opening every 3s
        """
        trials = 0
        while True:
            if trials >= 60:
                # that's 10 mins of waiting for the macdb (600s)
                # dont wait forever
                return

            try:
                utils.load_mac_vendor_index("databases/macaddress-db.json")
                self.mac_vendor_db_loaded = True
                return True
            except OSError:
                # update manager hasn't downloaded it yet
                try:
                    await asyncio.sleep(10)
                    trials += 1
                except KeyboardInterrupt:
                    return False

    def get_vendor_online(self, mac_addr: str) -> str | bool:
        """Ask macvendors.com for the vendor of a MAC address.

        Used when the offline database doesn't know the address.

        Parameters:
            mac_addr: MAC address to look up.

        Returns:
            The vendor name, or False when there's none or the lookup failed.
        """
        # If there is no match in the online database,
        # you will receive an empty response with a status code
        # of HTTP/1.1 204 No Content
        url = "https://api.macvendors.com"
        if self.failed_online_lookups.has(mac_addr):
            return False
        try:
            response = requests.get(f"{url}/{mac_addr}", timeout=2)
            if response.status_code == 200:
                # this online db returns results in an array like str [{results}],
                # make it json
                if vendor := response.text:
                    self.failed_online_lookups.remove(mac_addr)
                    return vendor
            self.failed_online_lookups.add(mac_addr)
            return False
        except (
            requests.exceptions.ReadTimeout,
            requests.exceptions.ConnectionError,
            json.decoder.JSONDecodeError,
        ):
            self.failed_online_lookups.add(mac_addr)
            return False

    def get_vendor_offline(self, mac_addr: str, profileid: str) -> str | bool:
        """
        Gets vendor from Slips' offline database at databases/macaddr-db.json.
        """
        if not self.mac_vendor_db_loaded:
            # when update manager is done updating the mac db, we should ask
            # the db for all these pending queries
            self.pending_mac_queries.put((mac_addr, profileid))
            return False

        try:
            return utils.get_mac_vendor_from_mac_addr(mac_addr) or False
        except OSError:
            self.mac_vendor_db_loaded = False
            self.pending_mac_queries.put((mac_addr, profileid))
            return False

    async def get_vendor_async(
        self,
        mac_addr: str,
        profileid: str,
        run_in_executor: Callable[..., Awaitable[Any]],
    ) -> dict | bool:
        """Resolve MAC vendor information without blocking the event loop.

        Parameters:
            mac_addr: MAC address to enrich.
            profileid: Profile identifier associated with the MAC.
            run_in_executor: Async helper that runs blocking callables in
                a bounded executor.

        Returns:
            Vendor information dict or False.
        """
        if not utils.is_ignored_ip(profileid.split("_")[-1]):
            # dont try to get the MAC vendor of public ips, the MAC
            # here is irrelevant (might be the gateway's)
            return False

        address_type = classify_mac(mac_addr)
        if address_type == "locally_administered":
            return {
                "MAC": mac_addr,
                "Vendor": "Unknown",
                "mac_address_type": address_type,
            }
        if address_type != "universally_administered":
            return False

        # don't look for the vendor again if we already have it for this
        # profileid
        if self.db.get_mac_vendor_from_profile(profileid):
            return True

        mac_info: dict = {"MAC": mac_addr}

        if vendor := self.get_vendor_offline(mac_addr, profileid):
            mac_info["Vendor"] = vendor
            self.db.set_mac_vendor_to_profile(profileid, mac_addr, vendor)
        elif vendor := await run_in_executor(self.get_vendor_online, mac_addr):
            mac_info["Vendor"] = vendor
            self.db.set_mac_vendor_to_profile(profileid, mac_addr, vendor)
        else:
            mac_info["Vendor"] = "Unknown"

        return mac_info

    def check_if_we_have_pending_offline_mac_queries(self) -> None:
        """
        Checks if we have pending MAC queries to get the vendor of.
        These pending queries are MACs that should bee looked up in the
        local downloaded mac db, but aren't because update manager hasn't
        downloaded it yet for whatever reason.
        queries are taken from the pending_mac_queries queue.
        """
        if not self.mac_vendor_db_loaded:
            return

        if self.pending_mac_queries.empty():
            return

        while True:
            try:
                mac, profileid = self.pending_mac_queries.get(timeout=0.5)
                if vendor := self.get_vendor_offline(mac, profileid):
                    self.db.set_mac_vendor_to_profile(profileid, mac, vendor)
            except Exception:
                # queue is empty
                return
