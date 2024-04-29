from modules.exporting_alerts.slack_exporter import SlackExporter
from modules.exporting_alerts.stix_exporter import StixExporter
from slips_files.common.slips_utils import utils
from slips_files.common.abstracts.module import IModule
import json


class ExportingAlerts(IModule):
    """
    Module to export alerts to slack and/or STIX
    You need to have the token in your environment
    variables to use this module
    """

    name = "Exporting Alerts"
    description = "Export alerts to slack or STIX format"
    authors = ["Alya Gomaa"]

    def init(self):
        self.slack = SlackExporter(self.logger, self.db)
        self.stix = StixExporter(self.logger, self.db)
        self.c1 = self.db.subscribe("export_evidence")
        self.channels = {"export_evidence": self.c1}

    def shutdown_gracefully(self):
        self.slack.shutdown_gracefully()
        self.stix.shutdown_gracefully()

    def pre_main(self):
        utils.drop_root_privs()

        if self.slack.should_export():
            self.slack.send_init_msg()

        if self.stix.should_export():
            # This thread is responsible for waiting n seconds before
            # each push to the stix server
            # it starts the timer when the first alert happens
            self.stix.start_exporting_thread()

    def main(self):
        if msg := self.get_msg("export_evidence"):
            evidence = json.loads(msg["data"])
            description: str = evidence["description"]

            if self.slack.should_export():
                srcip = evidence["profile"]["ip"]
                msg_to_send = f"Src IP {srcip} Detected {description}"
                self.slack.export(msg_to_send)

            if self.stix.should_export():
                msg_to_send = (
                    evidence["evidence_type"],
                    evidence["attacker"]["value"],
                )
                added_to_stix: bool = self.stix.add_to_stix_file(msg_to_send)
                if added_to_stix:
                    # now export to taxii
                    self.stix.export()
                else:
                    self.print("Problem in add_to_stix_file()", 0, 3)
