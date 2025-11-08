# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
import os
import threading
import time
from typing import List, Optional
from urllib.parse import urljoin

from stix2 import Bundle, Indicator, parse
from taxii2client.v21 import Server

from slips_files.common.abstracts.iexporter import IExporter
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
                f"Exporting alerts to STIX 2 / TAXII every "
                f"{self.push_delay} seconds."
            )
            self.added_ips = set()
            self.bundle_objects: List[Indicator] = []
            self._load_existing_bundle()
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

    def _base_url(self) -> str:
        scheme = "https" if self.use_https else "http"
        default_port = 443 if self.use_https else 80
        if self.port:
            try:
                port = int(self.port)
            except (TypeError, ValueError):
                port = None
            if port and port != default_port:
                return f"{scheme}://{self.TAXII_server}:{port}"
        return f"{scheme}://{self.TAXII_server}"

    def _build_url(self, path: str) -> str:
        if not path:
            return self._base_url()
        if path.startswith("http://") or path.startswith("https://"):
            return path
        # urljoin discards url path if relative path does not start with /
        adjusted = path if path.startswith("/") else f"/{path}"
        return urljoin(self._base_url(), adjusted)

    def _load_existing_bundle(self) -> None:
        """
        Loads indicators from an existing STIX_data.json file so we can resume
        without creating duplicates if Slips was restarted.
        """
        if not os.path.exists(self.stix_filename):
            return
        try:
            with open(self.stix_filename, "r") as stix_file:
                data = stix_file.read().strip()
        except OSError as err:
            self.print(f"Unable to read {self.stix_filename}: {err}", 0, 3)
            return

        if not data:
            return

        try:
            bundle = parse(data)
        except Exception as err:  # stix2 raises generic Exception
            self.print(f"Invalid STIX bundle, starting fresh: {err}", 0, 3)
            return

        if not isinstance(bundle, Bundle):
            self.print("STIX_data.json does not contain a bundle.", 0, 3)
            return

        self.bundle_objects = list(bundle.objects)
        for indicator in self.bundle_objects:
            attacker = self._extract_attacker_from_indicator(indicator)
            if attacker:
                self.added_ips.add(attacker)

    def _extract_attacker_from_indicator(self, indicator: Indicator) -> Optional[str]:
        pattern = getattr(indicator, "pattern", None)
        if not pattern:
            return None
        start = pattern.find("'")
        end = pattern.rfind("'")
        if start == -1 or end == -1 or end <= start:
            return None
        return pattern[start + 1 : end]

    def _serialize_bundle(self) -> str:
        bundle = Bundle(*self.bundle_objects)
        return bundle.serialize(pretty=True)

    def _write_bundle(self) -> None:
        with open(self.stix_filename, "w") as stix_file:
            stix_file.write(self._serialize_bundle())

    def create_collection(self):
        if not self.collection_name:
            self.print(
                "collection_name is missing in slips.yaml; cannot export STIX.",
                0,
                3,
            )
            return None

        discovery_url = self._build_url(self.discovery_path)
        try:
            server = Server(
                discovery_url,
                user=self.taxii_username or None,
                password=self.taxii_password or None,
            )
        except Exception as err:
            self.print(f"Failed to connect to TAXII discovery: {err}", 0, 3)
            return None

        if not server.api_roots:
            self.print("TAXII server returned no API roots.", 0, 3)
            return None

        for api_root in server.api_roots:
            try:
                for collection in api_root.collections:
                    if collection.id == self.collection_name:
                        return collection
                    if (
                        hasattr(collection, "title")
                        and collection.title == self.collection_name
                    ):
                        return collection
            except Exception as err:
                self.print(
                    f"Could not list collections for API root {api_root.url}: {err}",
                    0,
                    3,
                )

        self.print(
            f"Collection '{self.collection_name}' was not found on the TAXII "
            f"server.",
            0,
            3,
        )
        return None

    def read_stix_file(self) -> str:
        if not os.path.exists(self.stix_filename):
            return ""

        with open(self.stix_filename, "r") as stix_file:
            return stix_file.read()

    def export(self) -> bool:
        """
        Exports evidence/alerts to a TAXII 2.x collection by pushing the
        STIX_data.json bundle as a TAXII envelope.
        """
        if not self.should_export():
            return False

        stix_data: str = self.read_stix_file()
        if len(stix_data.strip()) == 0:
            return False

        try:
            bundle_dict = json.loads(stix_data)
        except json.JSONDecodeError as err:
            self.print(f"STIX_data.json is not valid JSON: {err}", 0, 3)
            return False

        objects = bundle_dict.get("objects") or []
        if not objects:
            return False

        collection = self.create_collection()
        if not collection:
            return False

        try:
            collection.add_objects(bundle_dict)
        except Exception as err:
            self.print(f"Failed to push bundle to TAXII collection: {err}", 0, 3)
            return False

        self.print(
            f"Successfully exported {len(objects)} indicators to TAXII "
            f"collection '{self.collection_name}'.",
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
        # push_delay is only used when slips is running using -i
        self.push_delay = conf.push_delay()
        self.collection_name = conf.collection_name()
        self.taxii_username = conf.taxii_username()
        self.taxii_password = conf.taxii_password()
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
        pattern = patterns_map.get(ioc_type)
        if not pattern:
            self.print(f"Can't set pattern for STIX. {attacker}", 0, 3)
            return ""
        return pattern

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
        if not pattern:
            return False
        if self.ip_exists_in_stix_file(attacker):
            self.print(
                f"{attacker} already exists in STIX bundle, skipping duplicate.",
                2,
                0,
            )
            return False
        # Required Indicator Properties: type, spec_version, id, created,
        # modified , all are set automatically
        # Valid_from, created and modified attribute will
        # be set to the current time
        # ID will be generated randomly
        # ref https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_6khi84u7y58g
        indicator = Indicator(
            name=name, pattern=pattern, pattern_type="stix"
        )  # the pattern language that the indicator pattern is expressed in.

        self.bundle_objects.append(indicator)
        self._write_bundle()

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
                exported = self.export()
                if exported:
                    # Delete stix_data.json file so we don't send duplicates
                    os.remove(self.stix_filename)
                    self.bundle_objects = []
                    self.added_ips.clear()
            else:
                self.print(
                    f"{self.push_delay} seconds passed, "
                    f"no new alerts in STIX_data.json.",
                    2,
                    0,
                )
