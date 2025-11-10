# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json

from modules.exporting_alerts.slack_exporter import SlackExporter
from modules.exporting_alerts.stix_exporter import StixExporter
from slips_files.common.slips_utils import utils
from slips_files.common.abstracts.iasync_module import IAsyncModule


class ExportingAlerts(IAsyncModule):
    """
    Module to export alerts to slack and/or STIX
    You need to have the token in your environment
    variables to use this module
    """

    name = "Exporting Alerts"
    description = "Export alerts to slack or STIX format"
    authors = ["Alya Gomaa"]

    async def init(self):
        # Set up channel handlers - this should be the first thing in init()
        self.channels = {
            "export_evidence": self.export_evidence_msg_handler,
        }
        await self.db.subscribe(self.pubsub, self.channels.keys())

        self.slack = SlackExporter(self.logger, self.db)
        self.stix = StixExporter(self.logger, self.db)

    def shutdown_gracefully(self):
        self.slack.shutdown_gracefully()
        self.stix.shutdown_gracefully()

    async def pre_main(self):
        utils.drop_root_privs_permanently()

        export_to_slack = self.slack.should_export()
        export_to_stix = self.stix.should_export()

        if export_to_slack:
            await self.slack.send_init_msg()

        if export_to_stix:
            # This async task is responsible for waiting n seconds before
            # each push to the stix server
            # it starts the timer when the first alert happens
            await self.stix.start_exporting_thread()

        if not export_to_slack or export_to_stix:
            return 1

    def remove_sensitive_info(self, evidence: dict) -> str:
        """
        removes the leaked location co-ords from the evidence
        description before exporting
        returns the description without sensitive info
        """
        if "NETWORK_GPS_LOCATION_LEAKED" not in evidence["evidence_type"]:
            return evidence["description"]

        description = evidence["description"]
        return description[: description.index("Leaked location")]

    async def export_evidence_msg_handler(self, msg):
        """Handler for export_evidence channel messages"""
        try:
            evidence = json.loads(msg["data"])
            description = self.remove_sensitive_info(evidence)
            if self.slack.should_export():
                srcip = evidence["profile"]["ip"]
                msg_to_send = f"Src IP {srcip} Detected {description}"
                await self.slack.export(msg_to_send)

            if self.stix.should_export():
                msg_to_send = (
                    evidence["evidence_type"],
                    evidence["attacker"]["value"],
                )
                added_to_stix: bool = await self.stix.add_to_stix_file(
                    msg_to_send
                )
                if added_to_stix:
                    # now export to taxii
                    await self.stix.export()
                else:
                    self.print("Problem in add_to_stix_file()", 0, 3)
        except Exception as e:
            self.print(f"Error processing export_evidence message: {e}")

    async def main(self):
        """Main loop function"""
        # The main loop is now handled by the base class through message dispatching
        # Individual message handlers are called automatically when messages arrive
        pass
