# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from stix2 import Indicator, Bundle
from cabby import create_client
import time
import threading
import os

from slips_files.common.abstracts.exporter import IExporter
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils


class StixExporter(IExporter):
    def init(self):
        self.port = None
        self.is_running_non_stop: bool = self.db.is_running_non_stop()
        self.stix_filename = "STIX_data.json"
        self.configs_read: bool = self.read_configuration()
        if self.should_export():
            self.print(
                f"Exporting to Stix & TAXII very "
                f"{self.push_delay} seconds."
            )
            # This bundle should be created once and we should
            # append all indicators to it
            self.is_bundle_created = False
            # To avoid duplicates in STIX_data.json
            self.added_ips = set()
            self.export_to_taxii_thread = threading.Thread(
                target=self.schedule_sending_to_taxii_server,
                daemon=True,
                name="stix_exporter_to_taxii_thread",
            )

    def start_exporting_thread(self):
        # This thread is responsible for waiting n seconds before
        # each push to the stix server
        # it starts the timer when the first alert happens
        utils.start_thread(self.export_to_taxii_thread, self.db)

    @property
    def name(self):
        return "StixExporter"

    def create_client(self):
        client = create_client(
            self.TAXII_server,
            use_https=self.use_https,
            port=self.port,
            discovery_path=self.discovery_path,
        )

        if self.jwt_auth_path != "":
            client.set_auth(
                username=self.taxii_username,
                password=self.taxii_password,
                # URL used to obtain JWT token
                jwt_auth_url=self.jwt_auth_path,
            )
        else:
            # User didn't provide jwt_auth_path in slips.yaml
            client.set_auth(
                username=self.taxii_username,
                password=self.taxii_password,
            )
        return client

    def inbox_service_exists_in_taxii_server(self, services):
        """
        Checks if inbox service is available in the taxii server
        """
        for service in services:
            if "inbox" in service.type.lower():
                return True

        self.print(
            "Server doesn't have inbox available. "
            "Exporting STIX_data.json is cancelled.",
            0,
            2,
        )
        return False

    def read_stix_file(self) -> str:
        with open(self.stix_filename) as stix_file:
            stix_data = stix_file.read()
        return stix_data

    def export(self) -> bool:
        """
        Exports evidence/alerts to the TAXII server
        Uses Inbox Service (TAXII Service to Support Producer-initiated
         pushes of cyber threat information) to publish
        our STIX_data.json file
        """
        if not self.should_export:
            return False

        client = self.create_client()

        # Check the available services to make sure inbox service is there
        services = client.discover_services()
        if not self.inbox_service_exists_in_taxii_server(services):
            return False

        stix_data: str = self.read_stix_file()

        # Make sure we don't push empty files
        if len(stix_data) == 0:
            return False

        binding = "urn:stix.mitre.org:json:2.1"
        # URI is the path to the inbox service we want to
        # use in the taxii server
        client.push(
            stix_data,
            binding,
            collection_names=[self.collection_name],
            uri=self.inbox_path,
        )
        self.print(
            f"Successfully exported to TAXII server: " f"{self.TAXII_server}.",
            1,
            0,
        )
        return True

    def shutdown_gracefully(self):
        """Exits gracefully"""
        # We need to publish to taxii server before stopping
        if self.should_export():
            self.export()

    def should_export(self) -> bool:
        """Determines whether to export or not"""
        return self.is_running_non_stop and "stix" in self.export_to

    def read_configuration(self) -> bool:
        """Reads configuration"""
        conf = ConfigParser()
        # Available options ['slack','stix']
        self.export_to = conf.export_to()

        if "stix" not in self.export_to:
            return False

        self.TAXII_server = conf.taxii_server()
        self.port = conf.taxii_port()
        self.use_https = conf.use_https()
        self.discovery_path = conf.discovery_path()
        self.inbox_path = conf.inbox_path()
        # push_delay is only used when slips is running using -i
        self.push_delay = conf.push_delay()
        self.collection_name = conf.collection_name()
        self.taxii_username = conf.taxii_username()
        self.taxii_password = conf.taxii_password()
        self.jwt_auth_path = conf.jwt_auth_path()
        # push delay exists -> create a thread that waits
        # push delay doesn't exist -> running using file not interface
        # -> only push to taxii server once before
        # stopping
        return True

    def ip_exists_in_stix_file(self, ip):
        """Searches for ip in STIX_data.json to avoid exporting duplicates"""
        return ip in self.added_ips

    def get_ioc_pattern(self, ioc_type: str, attacker) -> str:
        patterns_map = {
            "ip": f"[ip-addr:value = '{attacker}']",
            "domain": f"[domain-name:value = '{attacker}']",
            "url": f"[url:value = '{attacker}']",
        }
        if ioc_type not in ioc_type:
            self.print(f"Can't set pattern for STIX. {attacker}", 0, 3)
            return False
        return patterns_map[ioc_type]

    def add_to_stix_file(self, to_add: tuple) -> bool:
        """
        Function to export evidence to a STIX_data.json file in the cwd.
        It keeps appending the given indicator to STIX_data.json until they're
         sent to the
        taxii server
        msg_to_send is a tuple: (evidence_type,attacker)
            evidence_type: e.g PortScan, ThreatIntelligence etc
            attacker: ip of the attcker
        """
        evidence_type, attacker = (
            to_add[0],
            to_add[1],
        )
        # Get the right description to use in stix
        name = evidence_type
        ioc_type = utils.detect_ioc_type(attacker)
        pattern: str = self.get_ioc_pattern(ioc_type, attacker)
        # Required Indicator Properties: type, spec_version, id, created,
        # modified , all are set automatically
        # Valid_from, created and modified attribute will
        # be set to the current time
        # ID will be generated randomly
        # ref https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_6khi84u7y58g
        indicator = Indicator(
            name=name, pattern=pattern, pattern_type="stix"
        )  # the pattern language that the indicator pattern is expressed in.
        # Create and Populate Bundle.
        # All our indicators will be inside bundle['objects'].
        bundle = Bundle()
        if not self.is_bundle_created:
            bundle = Bundle(indicator)
            # Clear everything in the existing STIX_data.json
            # if it's not empty
            open(self.stix_filename, "w").close()
            # Write the bundle.
            with open(self.stix_filename, "w") as stix_file:
                stix_file.write(str(bundle))
            self.is_bundle_created = True
        elif not self.ip_exists_in_stix_file(attacker):
            # Bundle is already created just append to it
            # r+ to delete last 4 chars
            with open(self.stix_filename, "r+") as stix_file:
                # delete the last 4 characters in the file ']\n}\n' so we
                # can append to the objects array and add them back later
                stix_file.seek(0, os.SEEK_END)
                stix_file.seek(stix_file.tell() - 4, 0)
                stix_file.truncate()

            # Append mode to add the new indicator to the objects array
            with open(self.stix_filename, "a") as stix_file:
                # Append the indicator in the objects array
                stix_file.write(f",{str(indicator)}" + "]\n}\n")

        # Set of unique ips added to stix_data.json to avoid duplicates
        self.added_ips.add(attacker)
        self.print("Indicator added to STIX_data.json", 2, 0)
        return True

    def schedule_sending_to_taxii_server(self):
        """
        Responsible for publishing STIX_data.json to the taxii server every
        self.push_delay seconds when running on an interface only
        """
        while True:
            # on an interface, we use the push delay from slips.yaml
            # on files, we push once when slips is stopping
            time.sleep(self.push_delay)
            # Sometimes the time's up and we need to send to
            # server again but there's no
            # new alerts in stix_data.json yet
            if os.path.exists(self.stix_filename):
                self.export()
                # Delete stix_data.json file so we don't send duplicates
                os.remove(self.stix_filename)
                self.is_bundle_created = False
            else:
                self.print(
                    f"{self.push_delay} seconds passed, "
                    f"no new alerts in STIX_data.json.",
                    2,
                    0,
                )
