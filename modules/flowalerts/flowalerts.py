import asyncio
import inspect
from asyncio import Task
from typing import List

from slips_files.common.slips_utils import utils
from slips_files.common.abstracts.async_module import AsyncModule
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


class FlowAlerts(AsyncModule):
    name = "Flow Alerts"
    description = (
        "Alerts about flows: long connection, successful ssh, "
        "password guessing, self-signed certificate, data exfiltration, etc."
    )
    authors = ["Kamila Babayeva", "Sebastian Garcia", "Alya Gomaa"]

    def init(self):
        self.subscribe_to_channels()
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

    def subscribe_to_channels(self):
        channels = (
            "new_flow",
            "new_ssh",
            "new_notice",
            "new_ssl",
            "tw_closed",
            "new_dns",
            "new_downloaded_file",
            "new_smtp",
            "new_software",
            "new_tunnel",
        )
        for channel in channels:
            channel_obj = self.db.subscribe(channel)
            self.channels.update({channel: channel_obj})

    async def shutdown_gracefully(self):
        await asyncio.gather(*self.tasks)

    def pre_main(self):
        utils.drop_root_privs()
        self.analyzers_map = {
            "new_downloaded_file": [self.downloaded_file.analyze],
            "new_notice": [self.notice.analyze],
            "new_smtp": [self.smtp.analyze],
            "new_flow": [self.conn.analyze, self.ssl.analyze],
            "new_dns": [self.dns.analyze],
            "tw_closed": [self.conn.analyze],
            "new_ssh": [self.ssh.analyze],
            "new_software": [self.software.analyze],
            "new_tunnel": [self.tunnel.analyze],
            "new_ssl": [self.ssl.analyze],
        }

    async def main(self):
        for channel, analyzers in self.analyzers_map.items():
            msg: dict = self.get_msg(channel)
            if not msg:
                continue

            for analyzer in analyzers:
                # some analyzers are async functions
                if inspect.iscoroutinefunction(analyzer):
                    # analyzer will run normally, until it finishes.
                    # tasks inside this analyzer will run asynchrously,
                    # and finish whenever they finish, we'll not wait for them
                    loop = asyncio.get_event_loop()
                    task = loop.create_task(analyzer(msg))
                    # to wait for these functions before flowalerts shuts down
                    self.tasks.append(task)
                    # Allow the event loop to run the scheduled task
                    await asyncio.sleep(0)
                else:
                    analyzer(msg)
