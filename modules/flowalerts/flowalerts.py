from slips_files.common.slips_utils import utils
from slips_files.common.abstracts.module import IModule
from .conn import Conn
from .dns import DNS
from .downloaded_file import DownloadedFile
from .notice import Notice
from .smtp import SMTP
from .ssh import SSH
from .ssl import SSL
from slips_files.core.helpers.whitelist import Whitelist

from .tunnel import Tunnel


class FlowAlerts(IModule):
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
        self.notice = Notice(self.db, flowalerts=self)
        self.smtp = SMTP(self.db, flowalerts=self)
        self.ssl = SSL(self.db, flowalerts=self)
        self.ssh = SSH(self.db, flowalerts=self)
        self.downloaded_file = DownloadedFile(self.db, flowalerts=self)
        self.tunnel = Tunnel(self.db, flowalerts=self)
        self.conn = Conn(self.db, flowalerts=self)

    def subscribe_to_channels(self):
        self.c1 = self.db.subscribe("new_flow")
        self.c2 = self.db.subscribe("new_ssh")
        self.c3 = self.db.subscribe("new_notice")
        self.c4 = self.db.subscribe("new_ssl")
        self.c5 = self.db.subscribe("tw_closed")
        self.c6 = self.db.subscribe("new_dns")
        self.c7 = self.db.subscribe("new_downloaded_file")
        self.c8 = self.db.subscribe("new_smtp")
        self.c9 = self.db.subscribe("new_software")
        self.c10 = self.db.subscribe("new_weird")
        self.c11 = self.db.subscribe("new_tunnel")
        self.channels = {
            "new_flow": self.c1,
            "new_ssh": self.c2,
            "new_notice": self.c3,
            "new_ssl": self.c4,
            "tw_closed": self.c5,
            "new_dns": self.c6,
            "new_downloaded_file": self.c7,
            "new_smtp": self.c8,
            "new_software": self.c9,
            "new_weird": self.c10,
            "new_tunnel": self.c11,
        }

    def pre_main(self):
        utils.drop_root_privs()

    def main(self):
        self.conn.analyze()
        self.notice.analyze()
        self.dns.analyze()
        self.smtp.analyze()
        self.ssl.analyze()
        self.ssh.analyze()
        self.downloaded_file.analyze()
        self.tunnel.analyze()
