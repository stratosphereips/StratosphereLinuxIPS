# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import inspect
from asyncio import Task
from typing import List

from slips_files.common.slips_utils import utils
from slips_files.common.abstracts.iasync_module import IAsyncModule
from .conn import Conn
from .dns import DNS
from .downloaded_file import DownloadedFile
from .notice import Notice
from .smtp import SMTP
from .software import Software
from .ssh import SSH
from .ssl import SSL
from .tunnel import Tunnel
from slips_files.core.helpers.whitelist.whitelist import Whitelist


class FlowAlerts(IAsyncModule):
    name = "Flow Alerts"
    description = (
        "Alerts about flows: long connection, successful ssh, "
        "password guessing, self-signed certificate, data exfiltration, etc."
    )
    authors = ["Kamila Babayeva", "Sebastian Garcia", "Alya Gomaa"]

    async def init(self):
        # Set up channel handlers - this should be the first thing in init()
        self.channels = {
            "new_flow": self.new_flow_msg_handler,
            "new_ssh": self.new_ssh_msg_handler,
            "new_notice": self.new_notice_msg_handler,
            "new_ssl": self.new_ssl_msg_handler,
            "tw_closed": self.tw_closed_msg_handler,
            "new_dns": self.new_dns_msg_handler,
            "new_downloaded_file": self.new_downloaded_file_msg_handler,
            "new_smtp": self.new_smtp_msg_handler,
            "new_software": self.new_software_msg_handler,
            "new_tunnel": self.new_tunnel_msg_handler,
        }
        await self.db.subscribe(self.pubsub, self.channels.keys())

        self.whitelist = Whitelist(self.logger, self.db)
        self.dns = DNS(self.db, flowalerts=self)
        self.software = Software(self.db, flowalerts=self)
        self.notice = Notice(self.db, flowalerts=self)
        self.smtp = SMTP(self.db, flowalerts=self)
        self.ssl = SSL(self.db, flowalerts=self)
        self.ssh = SSH(self.db, flowalerts=self)
        self.downloaded_file = DownloadedFile(self.db, flowalerts=self)
        self.tunnel = Tunnel(self.db, flowalerts=self)
        self.conn = Conn(self.db, flowalerts=self)
        # list of async functions to await before flowalerts shuts down
        self.tasks: List[Task] = []

    async def new_flow_msg_handler(self, msg):
        """Handler for new_flow channel messages"""
        analyzers = [self.conn, self.ssl]
        await self._run_analyzers(analyzers, msg)

    async def new_ssh_msg_handler(self, msg):
        """Handler for new_ssh channel messages"""
        analyzers = [self.ssh]
        await self._run_analyzers(analyzers, msg)

    async def new_notice_msg_handler(self, msg):
        """Handler for new_notice channel messages"""
        analyzers = [self.notice]
        await self._run_analyzers(analyzers, msg)

    async def new_ssl_msg_handler(self, msg):
        """Handler for new_ssl channel messages"""
        analyzers = [self.ssl]
        await self._run_analyzers(analyzers, msg)

    async def tw_closed_msg_handler(self, msg):
        """Handler for tw_closed channel messages"""
        analyzers = [self.conn]
        await self._run_analyzers(analyzers, msg)

    async def new_dns_msg_handler(self, msg):
        """Handler for new_dns channel messages"""
        analyzers = [self.dns]
        await self._run_analyzers(analyzers, msg)

    async def new_downloaded_file_msg_handler(self, msg):
        """Handler for new_downloaded_file channel messages"""
        analyzers = [self.downloaded_file]
        await self._run_analyzers(analyzers, msg)

    async def new_smtp_msg_handler(self, msg):
        """Handler for new_smtp channel messages"""
        analyzers = [self.smtp]
        await self._run_analyzers(analyzers, msg)

    async def new_software_msg_handler(self, msg):
        """Handler for new_software channel messages"""
        analyzers = [self.software]
        await self._run_analyzers(analyzers, msg)

    async def new_tunnel_msg_handler(self, msg):
        """Handler for new_tunnel channel messages"""
        analyzers = [self.tunnel]
        await self._run_analyzers(analyzers, msg)

    async def _run_analyzers(self, analyzers, msg):
        """Run the given analyzers on the message"""
        for analyzer in analyzers:
            # some analyzers are async functions
            if inspect.iscoroutinefunction(analyzer.analyze):
                # analyzer will run normally, until it finishes.
                # tasks inside this analyzer will run asynchrously,
                # and finish whenever they finish, we'll not wait for them
                task = self.create_task(analyzer.analyze, msg)
                # to wait for these functions before flowalerts shuts down
                self.tasks.append(task)
            else:
                analyzer.analyze(msg)

    async def shutdown_gracefully(self):
        self.dns.shutdown_gracefully()

    async def pre_main(self):
        utils.drop_root_privs_permanently()
        self.dns.pre_analyze()

    async def main(self):
        """Main loop function"""
        # The main loop is now handled by the base class through message dispatching
        # Individual message handlers are called automatically when messages arrive
        pass
