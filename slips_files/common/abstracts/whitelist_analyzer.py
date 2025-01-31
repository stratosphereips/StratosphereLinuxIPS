# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from abc import ABC, abstractmethod

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
        self.init(**kwargs)

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
