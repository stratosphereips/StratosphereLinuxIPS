# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from abc import ABC, abstractmethod
import time

import redis

from slips_files.core.database.database_manager import DBManager
from slips_files.core.helpers.whitelist.matcher import WhitelistMatcher


class IWhitelistAnalyzer(ABC):
    """
    Every whitelist supported type (e.g. IPs, domains, MACs, etc)
    has its own analyser  this is the
    interface for it.

    """

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    def __init__(self, db: DBManager, whitelist_manager=None, **kwargs):
        self.db = db
        # the file that manages all analyzers
        self.manager = whitelist_manager
        self.match = WhitelistMatcher()
        self._next_rules_refresh = time.monotonic() + 2
        self._known_rules: set[str] | None = None
        self.init(**kwargs)

    def refresh_rules(self, kind: str, filter_name: str = "") -> dict | None:
        """Refresh worker-local rules at most once every two seconds.

        Parameters:
            kind: Existing Redis whitelist category.
            filter_name: Bloom filter attribute to rebuild after key changes.

        Returns:
            Fresh rules, or None when no refresh is due or Redis is unavailable.
        """
        now = time.monotonic()
        if now < self._next_rules_refresh:
            return None
        self._next_rules_refresh = now + 2
        try:
            rules = self.db.get_whitelist(kind)
        except redis.RedisError:
            return None
        keys = set(rules)
        if filter_name and keys != self._known_rules:
            filters = self.manager.bloom_filters
            setattr(
                filters, filter_name, filters._create_bloom_filter(keys, 0.001)
            )
        self._known_rules = keys
        return rules

    @abstractmethod
    def init(self):
        """
        the goal of this is to have one common __init__() above for all
        whitelist analyzers, which is the one in this file, and a different
        init() per helper
        this init will have access to all keyword args passes when
        initializing the module
        """

    @abstractmethod
    def is_whitelisted(self, *args): ...
