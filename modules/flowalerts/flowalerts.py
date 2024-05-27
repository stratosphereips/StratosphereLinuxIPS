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
        self.channels = {
            "new_flow": self.db.subscribe("new_flow"),
            "new_ssh": self.db.subscribe("new_ssh"),
            "new_notice": self.db.subscribe("new_notice"),
            "new_ssl": self.db.subscribe("new_ssl"),
            "tw_closed": self.db.subscribe("tw_closed"),
            "new_dns": self.db.subscribe("new_dns"),
            "new_downloaded_file": self.db.subscribe("new_downloaded_file"),
            "new_smtp": self.db.subscribe("new_smtp"),
            "new_software": self.db.subscribe("new_software"),
            "new_weird": self.db.subscribe("new_weird"),
            "new_tunnel": self.db.subscribe("new_tunnel"),
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
