# SPDX-License-Identifier: GPL-2.0-only
"""Whois lookups of the domains seen by Slips."""

import datetime
from contextlib import redirect_stderr, redirect_stdout
from typing import Any, Awaitable, Callable

import whois

from modules.ip_info.negative_cache import NegativeCache
from slips_files.common.slips_utils import utils
from slips_files.core.database.database_manager import DBManager
from slips_files.core.helpers.whitelist.whitelist import Whitelist


class DomainInfo:
    """Look up the age and the owner of a domain using whois."""

    def __init__(self, db: DBManager, whitelist: Whitelist) -> None:
        """Start with no cached domains.

        Parameters:
            db: Database manager of the ip_info module.
            whitelist: Used to extract the TLD of a domain.
        """
        self.db = db
        self.whitelist = whitelist
        self.valid_tlds = frozenset(whois.validTlds())
        self.domain_validity_cache: dict[str, bool] = {}
        # to avoid repeated failed whois lookups. we wait 300s before retries.
        self.failed_whois_lookups = NegativeCache()

    def has_cached_info(self, domain: str) -> bool:
        """Check whether the age and owner of a domain are already known.

        Parameters:
            domain: Domain to check.

        Returns:
            Whether a whois lookup can be skipped.
        """
        cached_data = self.db.get_domain_data(domain)
        if cached_data and ("Age" in cached_data and "Org" in cached_data):
            # we already have info about this domain
            return True
        return False

    def is_valid_domain(self, domain: str) -> bool:
        """Check whether whois can know anything about a domain.

        Local names and unknown TLDs are skipped, whois has no record of
        them.

        Parameters:
            domain: Domain to check.

        Returns:
            Whether the domain is worth a whois lookup.
        """
        cached_result = self.domain_validity_cache.get(domain)
        if cached_result is not None:
            return cached_result

        if domain.endswith(".arpa") or domain.endswith(".local"):
            self.domain_validity_cache[domain] = False
            return False

        domain_tld: str = self.whitelist.domain_analyzer.get_tld(domain)
        if domain_tld not in self.valid_tlds:
            self.domain_validity_cache[domain] = False
            return False
        self.domain_validity_cache[domain] = True
        return True

    def query_whois(self, domain: str) -> Any:
        """Ask whois about a domain, keeping its output off the terminal.

        Parameters:
            domain: Domain to look up.

        Returns:
            The whois result, or None when there's none or the lookup
            failed.
        """
        if self.failed_whois_lookups.has(domain):
            return None
        try:
            with (
                open("/dev/null", "w") as f,
                redirect_stdout(f),
                redirect_stderr(f),
            ):
                result = whois.query(domain, timeout=2.0)
                if result:
                    self.failed_whois_lookups.remove(domain)
                    return result
                self.failed_whois_lookups.add(domain)
                return None
        except Exception:
            self.failed_whois_lookups.add(domain)
            return None

    def get_domain_info(self, domain: str) -> None:
        """
        Gets the age and org of a domain using whois
        """
        if not self.is_valid_domain(domain) or self.has_cached_info(domain):
            return

        res = self.query_whois(domain)
        if res:
            if res.creation_date:
                age = utils.get_time_diff(
                    res.creation_date,
                    datetime.datetime.now(),
                    return_type="days",
                )
                self.db.set_info_for_domains(domain, {"Age": age})
            if hasattr(res, "registrant") and res.registrant:
                self.db.set_info_for_domains(domain, {"Org": res.registrant})
                return

        # usually support.microsoft.com doesnt have a registrant,
        # but microsoft.com does
        sld = utils.extract_hostname(domain)
        sld_res = self.query_whois(sld)
        if sld_res and hasattr(res, "registrant") and sld_res.registrant:
            self.db.set_info_for_domains(domain, {"Org": sld_res.registrant})

    async def get_domain_info_async(
        self, domain: str, run_in_executor: Callable[..., Awaitable[Any]]
    ) -> None:
        """Get domain age and organization without blocking the event loop.

        Parameters:
            domain: Domain to enrich.
            run_in_executor: Async helper that runs blocking callables in
                a bounded executor.
        """
        if not self.is_valid_domain(domain) or self.has_cached_info(domain):
            return

        res = await run_in_executor(self.query_whois, domain)
        if res:
            if res.creation_date:
                age = utils.get_time_diff(
                    res.creation_date,
                    datetime.datetime.now(),
                    return_type="days",
                )
                self.db.set_info_for_domains(domain, {"Age": age})
            if hasattr(res, "registrant") and res.registrant:
                self.db.set_info_for_domains(domain, {"Org": res.registrant})
                return

        sld = utils.extract_hostname(domain)
        sld_res = await run_in_executor(self.query_whois, sld)
        if sld_res and hasattr(res, "registrant") and sld_res.registrant:
            self.db.set_info_for_domains(domain, {"Org": sld_res.registrant})

    def clear_caches(self) -> None:
        """Free the cached domain checks when the module stops."""
        self.domain_validity_cache.clear()
