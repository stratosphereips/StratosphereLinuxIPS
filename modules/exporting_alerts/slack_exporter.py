# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from slack import WebClient
from slack.errors import SlackApiError
from slips_files.common.slips_utils import utils
from slips_files.common.abstracts.exporter import IExporter
from slips_files.common.parsers.config_parser import ConfigParser


class SlackExporter(IExporter):
    def init(self):
        self.configs_read: bool = self.read_configuration()
        if self.should_export():
            self.print("Exporting to Slack.")

    @property
    def name(self):
        return "SlackExporter"

    def read_configuration(self) -> bool:
        """reurns true if all necessary configs are present and read"""
        conf = ConfigParser()

        # Available options ['slack','stix']
        self.export_to = conf.export_to()
        if "slack" not in self.export_to:
            return False

        slack_token_filepath = conf.slack_token_filepath()
        try:
            self.token: str = self.read_slack_token(slack_token_filepath)
        except (FileNotFoundError, NameError):
            self.print(
                f"Please add slack bot token to "
                f"{slack_token_filepath}. Exporting to Slack "
                f"aborted..",
                0,
                1,
            )
            return False

        self.slack_channel_name = conf.slack_channel_name()
        self.sensor_name = conf.sensor_name()
        return True

    def send_init_msg(self):
        self.export(
            f"{utils.get_human_readable_datetime()}: "
            f"Slips started on sensor: {self.sensor_name}."
        )

    def send_stop_msg(self):
        self.export(
            f"{utils.get_human_readable_datetime()}: "
            f"Slips stopped on sensor: {self.sensor_name}."
        )

    def read_slack_token(self, filepath) -> str:
        """
        reads slack_token_filepath.
        returns the token as a str
        """
        with open(filepath) as f:
            token = f.read()

        if len(token) < 5:
            self.print(f"invalid slack bot token in {filepath}.", 0, 2)
            raise NameError
        return token

    def export(self, msg_to_send: str) -> bool:
        """exports evidence/alerts to Slack"""
        slack_client = WebClient(token=self.token)
        try:
            slack_client.chat_postMessage(
                # Channel name is set in slips.yaml
                channel=self.slack_channel_name,
                # Sensor name is set in slips.yaml
                text=f"{self.sensor_name}: {msg_to_send}",
            )
            return True

        except SlackApiError as e:
            # You will get a SlackApiError if "ok" is False
            assert e.response[
                "error"
            ], "Problem while exporting to slack."  # str like
            # 'invalid_auth', 'channel_not_found'
            return False

    def shutdown_gracefully(self):
        """Exits gracefully"""
        if not self.should_export():
            return
        self.print("Done exporting to Slack.")
        self.send_stop_msg()

    def should_export(self) -> bool:
        """Determines whether to export or not"""
        return self.configs_read
