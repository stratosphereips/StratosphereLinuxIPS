# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import ipaddress
import json
import os
import threading
import time
import textwrap
from datetime import datetime, timezone
from uuid import uuid4
from typing import Dict, List, Optional
from urllib.parse import urljoin

import requests
from stix2 import Bundle, Indicator, parse
from taxii2client.v21 import Server
from xml.sax.saxutils import escape

from slips_files.common.abstracts.iexporter import IExporter
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.common.slips_utils import utils


class StixExporter(IExporter):
    def init(self):
        self.port = None
        self.is_running_non_stop: bool = self.db.is_running_non_stop()
        self.output_dir = self._resolve_output_dir()
        self.stix_filename = os.path.join(self.output_dir, "STIX_data.json")
        self.export_log_path = os.path.join(
            self.output_dir, "stix_exporter.log"
        )
        self.direct_export = False
        self.collection_cache = threading.local()
        self.direct_export_attempts = 0
        self.direct_export_success = 0
        self.direct_export_fail = 0
        self.direct_export_workers = 1
        self.direct_export_max_workers = 1
        self.direct_export_retry_max = 0
        self.direct_export_retry_backoff = 0.0
        self.direct_export_retry_max_delay = 0.0
        self.exported_evidence_lock = threading.Lock()
        self.taxii_version = 2
        self.taxii1_inbox_path = "/services/inbox"
        self.configs_read: bool = self.read_configuration()
        self.export_to_taxii_thread = None
        self.last_exported_count = 0
        self._log_export(
            f"Init output_dir={self.output_dir} stix_file={self.stix_filename}"
        )
        if self.should_export():
            self.print(
                f"Exporting alerts to STIX / TAXII {self.taxii_version} "
                f"every {self.push_delay} seconds."
            )
            self._log_export(
                "Export enabled "
                f"target={self._base_url()} "
                f"discovery_path={self.discovery_path} "
                f"collection={self.collection_name} "
                f"taxii_version={self.taxii_version} "
                f"push_delay={self.push_delay} "
                f"direct_export={self.direct_export} "
                f"direct_export_workers={self.direct_export_workers} "
                f"direct_export_max_workers={self.direct_export_max_workers} "
                f"direct_export_retry_max={self.direct_export_retry_max} "
                f"direct_export_retry_backoff={self.direct_export_retry_backoff} "
                f"direct_export_retry_max_delay={self.direct_export_retry_max_delay}"
            )
            self.exported_evidence_ids = set()
            self.last_exported_count = 0
            if self.direct_export:
                self._log_export(
                    "Direct export enabled; skipping STIX_data.json storage."
                )
            else:
                self.bundle_objects: List[Indicator] = []
                self._load_existing_bundle()
                self._ensure_bundle_file()
                if self.is_running_non_stop:
                    self.export_to_taxii_thread = threading.Thread(
                        target=self.schedule_sending_to_taxii_server,
                        daemon=True,
                        name="stix_exporter_to_taxii_thread",
                    )
        else:
            self._log_export(
                f"Export disabled export_to={self.export_to}"
            )

    def start_exporting_thread(self):
        # This thread is responsible for waiting n seconds before
        # each push to the stix server
        # it starts the timer when the first alert happens
        if self.export_to_taxii_thread:
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

    def _log_export(self, message: str) -> None:
        timestamp = (
            datetime.utcnow()
            .replace(tzinfo=timezone.utc)
            .isoformat()
        )
        line = f"{timestamp} {message}\n"
        try:
            with open(self.export_log_path, "a", encoding="utf-8") as log_file:
                log_file.write(line)
        except OSError as err:
            self.print(
                f"Unable to write STIX exporter log: {err}",
                0,
                3,
            )

    def _resolve_output_dir(self) -> str:
        """
        Determines the directory where STIX_data.json should be stored.
        Falls back to the current working directory if the DB does not
        have an output directory set yet.
        """
        output_dir = getattr(self.db, "output_dir", None)
        if not output_dir:
            output_dir = self.db.get_output_dir()
        if isinstance(output_dir, bytes):
            output_dir = output_dir.decode("utf-8")
        if not output_dir:
            output_dir = os.getcwd()
        output_dir = os.path.abspath(output_dir)
        os.makedirs(output_dir, exist_ok=True)
        return output_dir

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
            bundle = parse(data, allow_custom=True)
        except Exception as err:  # stix2 raises generic Exception
            self.print(f"Invalid STIX bundle, starting fresh: {err}", 0, 3)
            return

        if not isinstance(bundle, Bundle):
            self.print("STIX_data.json does not contain a bundle.", 0, 3)
            return

        self.bundle_objects = list(bundle.objects)
        self.last_exported_count = len(self.bundle_objects)
        for indicator in self.bundle_objects:
            evidence_id = self._extract_evidence_id(indicator)
            if evidence_id:
                self.exported_evidence_ids.add(evidence_id)

    def _ensure_bundle_file(self) -> None:
        """
        Guarantee that STIX_data.json exists even before the first indicator
        arrives so the user can inspect the file immediately.
        """
        if os.path.exists(self.stix_filename):
            return
        bundle_stub = {
            "type": "bundle",
            "id": f"bundle--{uuid4()}",
            "objects": [],
        }
        with open(self.stix_filename, "w") as stix_file:
            json.dump(bundle_stub, stix_file, indent=2)

    def _extract_evidence_id(self, indicator: Indicator) -> Optional[str]:
        try:
            return indicator.get("x_slips_evidence_id")  # type: ignore[index]
        except AttributeError:
            return None

    def _serialize_bundle(self) -> str:
        bundle = Bundle(*self.bundle_objects, allow_custom=True)
        return bundle.serialize(pretty=True)

    def _write_bundle(self) -> None:
        if not self.bundle_objects:
            self._ensure_bundle_file()
            return

        with open(self.stix_filename, "w") as stix_file:
            stix_file.write(self._serialize_bundle())

    def create_collection(self):
        if self.taxii_version == 1:
            self._log_export(
                "TAXII 1 configured; skipping TAXII 2 collection discovery."
            )
            return None
        if not self.collection_name:
            self.print(
                "collection_name is missing in slips.yaml; cannot export STIX.",
                0,
                3,
            )
            self._log_export("Export skipped: collection_name missing.")
            return None

        discovery_url = self._build_url(self.discovery_path)
        self._log_export(f"Resolving TAXII collection via {discovery_url}")
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
            self._log_export("Export failed: no API roots in discovery.")
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
        self._log_export(
            f"Export failed: collection '{self.collection_name}' not found."
        )
        return None

    def _get_collection_cached(self):
        cached = getattr(self.collection_cache, "collection", None)
        if cached is not None:
            return cached
        collection = self.create_collection()
        if collection:
            self.collection_cache.collection = collection
        return collection

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
        if self.taxii_version == 1:
            self._log_export(
                "Export skipped: TAXII 1 requires direct_export."
            )
            return False
        if not self.should_export():
            self._log_export("Export skipped: stix not enabled.")
            return False
        if self.direct_export:
            self._log_export("Export skipped: direct_export enabled.")
            return False

        stix_data: str = self.read_stix_file()
        if len(stix_data.strip()) == 0:
            self._log_export("Export skipped: STIX_data.json is empty.")
            return False

        try:
            bundle_dict = json.loads(stix_data)
        except json.JSONDecodeError as err:
            self.print(f"STIX_data.json is not valid JSON: {err}", 0, 3)
            self._log_export(f"Export failed: invalid JSON {err}")
            return False

        objects = bundle_dict.get("objects") or []
        if not objects:
            self._log_export("Export skipped: STIX bundle has no objects.")
            return False

        new_objects = objects[self.last_exported_count :]
        if not new_objects:
            self._log_export("Export skipped: no new STIX objects.")
            return False

        self._log_export(
            f"Export start target={self._base_url()} "
            f"collection={self.collection_name} "
            f"new_objects={len(new_objects)} "
            f"total_objects={len(objects)} "
            f"last_exported_count={self.last_exported_count}"
        )
        sample = []
        for obj in new_objects[:5]:
            sample.append(
                {
                    "id": obj.get("id"),
                    "type": obj.get("type"),
                    "pattern": obj.get("pattern"),
                }
            )
        if sample:
            self._log_export(f"Export sample objects={sample}")
        collection = self.create_collection()
        if not collection:
            return False

        envelope = {"objects": new_objects}

        try:
            status = collection.add_objects(envelope)
        except Exception as err:
            self.print(f"Failed to push bundle to TAXII collection: {err}", 0, 3)
            response = getattr(err, "response", None)
            if response is not None:
                self._log_export(
                    f"Export failed: HTTP {response.status_code} "
                    f"response={response.text[:2000]}"
                )
            else:
                self._log_export(f"Export failed: push error {err}")
            return False
        if getattr(status, "failure_count", 0):
            self.print(
                f"TAXII rejected {status.failure_count} object(s).",
                0,
                3,
            )
            for failure in status.failures[:5]:
                obj_id = failure.get("id")
                reason = failure.get("message")
                self.print(
                    f"TAXII failure for {obj_id}: {reason}",
                    0,
                    3,
                )
            self._log_export(
                f"Export completed with failures "
                f"success={status.success_count} "
                f"failure={status.failure_count}"
            )

        self.last_exported_count = len(objects)

        self.print(
            f"Successfully exported {len(new_objects)} indicators to TAXII "
            f"collection '{self.collection_name}'.",
            2,
            0,
        )
        self._log_export(
            f"Export success count={len(new_objects)} "
            f"collection={self.collection_name}"
        )
        return True

    def shutdown_gracefully(self):
        """Exits gracefully"""
        # We need to publish to taxii server before stopping
        if self.should_export() and not self.direct_export:
            self.export()

    def should_export(self) -> bool:
        """Determines whether to export or not"""
        return "stix" in self.export_to

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
        self.taxii_version = self._normalize_taxii_version(conf.taxii_version())
        self.direct_export = bool(conf.taxii_direct_export())
        self.direct_export_workers = conf.taxii_direct_export_workers()
        self.direct_export_max_workers = conf.taxii_direct_export_max_workers()
        self.direct_export_retry_max = conf.taxii_direct_export_retry_max()
        self.direct_export_retry_backoff = conf.taxii_direct_export_retry_backoff()
        self.direct_export_retry_max_delay = (
            conf.taxii_direct_export_retry_max_delay()
        )
        if self.taxii_version == 1 and not self.direct_export:
            self._log_export(
                "TAXII 1 selected; forcing direct_export=true."
            )
            self.direct_export = True
        # push delay exists -> create a thread that waits
        # push delay doesn't exist -> running using file not interface
        # -> only push to taxii server once before
        # stopping
        return True

    def _normalize_taxii_version(self, value) -> int:
        if value is None:
            return 2
        text = str(value).strip().lower()
        if text.startswith("1"):
            return 1
        return 2

    def get_ioc_pattern(self, ioc_type: str, attacker) -> str:
        if ioc_type in ("ip", "ip_range"):
            try:
                if ioc_type == "ip":
                    ip_obj = ipaddress.ip_address(attacker)
                    ip_value = attacker
                else:
                    ip_obj = ipaddress.ip_network(attacker, strict=False)
                    ip_value = str(ip_obj)
            except ValueError:
                self.print(f"Invalid IP value for STIX: {attacker}", 0, 3)
                return ""
            addr_type = "ipv4-addr" if ip_obj.version == 4 else "ipv6-addr"
            return f"[{addr_type}:value = '{ip_value}']"

        patterns_map = {
            "domain": f"[domain-name:value = '{attacker}']",
            "url": f"[url:value = '{attacker}']",
        }
        pattern = patterns_map.get(ioc_type)
        if not pattern:
            self.print(f"Can't set pattern for STIX. {attacker}", 0, 3)
            self._log_export(
                f"Evidence skipped: unsupported ioc_type={ioc_type} "
                f"attacker={attacker}"
            )
            return ""
        return pattern

    def _build_indicator_labels(self, evidence: dict) -> List[str]:
        labels = []
        evidence_type = evidence.get("evidence_type")
        if evidence_type:
            labels.append(str(evidence_type).lower())
        threat_level = evidence.get("threat_level")
        if threat_level:
            labels.append(str(threat_level).lower())
        return labels

    def _build_valid_from(self, evidence: dict) -> Optional[datetime]:
        timestamp = evidence.get("timestamp")
        if not timestamp:
            return None
        try:
            dt_obj = utils.convert_to_datetime(timestamp)
        except Exception:
            return None
        if not utils.is_aware(dt_obj):
            dt_obj = utils.convert_ts_to_tz_aware(dt_obj)
        return dt_obj.astimezone(timezone.utc)

    def _build_custom_properties(
        self, evidence: dict, date_added: Optional[str]
    ) -> Dict[str, object]:
        victim = evidence.get("victim") or {}
        attacker = evidence.get("attacker") or {}
        timewindow = evidence.get("timewindow") or {}
        profile = evidence.get("profile") or {}

        custom_properties: Dict[str, object] = {
            "x_slips_evidence_id": evidence.get("id"),
            "x_slips_threat_level": evidence.get("threat_level"),
            "x_slips_profile_ip": profile.get("ip"),
            "x_slips_timewindow": timewindow.get("number"),
            "x_slips_attacker_direction": attacker.get("direction"),
            "x_slips_attacker_ti": attacker.get("TI"),
            "date_added": date_added,
        }

        victim_value = victim.get("value")
        if victim_value:
            custom_properties["x_slips_victim"] = victim_value

        uids = evidence.get("uid")
        if uids:
            custom_properties["x_slips_flow_uids"] = uids

        dst_port = evidence.get("dst_port")
        if dst_port:
            custom_properties["x_slips_dst_port"] = dst_port

        src_port = evidence.get("src_port")
        if src_port:
            custom_properties["x_slips_src_port"] = src_port

        return {
            key: value
            for key, value in custom_properties.items()
            if value not in (None, "", [], {})
        }

    def _build_indicator(self, evidence: dict):
        attacker = (evidence.get("attacker") or {}).get("value")
        if not attacker:
            attacker = (evidence.get("profile") or {}).get("ip")
        if not attacker:
            attacker = (evidence.get("victim") or {}).get("value")
        if not attacker:
            self.print("Evidence missing attacker value; skipping.", 0, 3)
            self._log_export(
                f"Evidence skipped: missing attacker value id={evidence.get('id')}"
            )
            return None

        evidence_id = evidence.get("id")
        if evidence_id:
            with self.exported_evidence_lock:
                if evidence_id in self.exported_evidence_ids:
                    self.print(
                        f"Evidence {evidence_id} already exported; skipping.",
                        3,
                        0,
                    )
                    self._log_export(
                        f"Evidence skipped: already exported id={evidence_id}"
                    )
                    return None

        self.print(
            f"Processing evidence {evidence_id or attacker} "
            f"(profile={evidence.get('profile')}, attacker={evidence.get('attacker')})",
            2,
            0,
        )

        ioc_type = utils.detect_ioc_type(attacker)
        pattern: str = self.get_ioc_pattern(ioc_type, attacker)
        if not pattern:
            self.print(
                f"Unable to build STIX pattern for attacker {attacker}.", 0, 3
            )
            self._log_export(
                f"Evidence skipped: invalid STIX pattern "
                f"id={evidence_id} attacker={attacker} ioc_type={ioc_type}"
            )
            return None

        indicator_labels = self._build_indicator_labels(evidence)
        valid_from = self._build_valid_from(evidence)
        date_added = (
            valid_from.isoformat()
            if isinstance(valid_from, datetime)
            else datetime.utcnow().replace(tzinfo=timezone.utc).isoformat()
        )
        custom_properties = self._build_custom_properties(evidence, date_added)

        indicator = Indicator(
            name=evidence.get("evidence_type", "Slips Alert"),
            description=evidence.get("description"),
            pattern=pattern,
            pattern_type="stix",
            valid_from=valid_from,
            labels=indicator_labels or None,
            allow_custom=True,
            custom_properties=custom_properties or None,
        )
        return indicator, evidence_id, attacker, ioc_type

    def _build_taxii1_cybox_properties(
        self, attacker: str, ioc_type: str
    ) -> Optional[str]:
        if ioc_type in ("ip", "ip_range"):
            try:
                if ioc_type == "ip":
                    ip_obj = ipaddress.ip_address(attacker)
                    ip_value = attacker
                else:
                    ip_obj = ipaddress.ip_network(attacker, strict=False)
                    ip_value = str(ip_obj)
            except ValueError:
                return None
            addr_type = "ipv4-addr" if ip_obj.version == 4 else "ipv6-addr"
            return (
                f'<cybox:Properties xsi:type="AddressObj:AddressObjectType" '
                f'category="{addr_type}">'
                f"<AddressObj:Address_Value>{escape(ip_value)}</AddressObj:Address_Value>"
                "</cybox:Properties>"
            )

        if ioc_type == "domain":
            return (
                '<cybox:Properties xsi:type="DomainNameObj:DomainNameObjectType">'
                f"<DomainNameObj:Value>{escape(attacker)}</DomainNameObj:Value>"
                "</cybox:Properties>"
            )

        if ioc_type == "url":
            return (
                '<cybox:Properties xsi:type="URIObj:URIObjectType">'
                "<URIObj:Type>URL</URIObj:Type>"
                f"<URIObj:Value>{escape(attacker)}</URIObj:Value>"
                "</cybox:Properties>"
            )

        return None

    def _build_taxii1_package(
        self, evidence: dict, attacker: str, ioc_type: str
    ) -> Optional[str]:
        properties_xml = self._build_taxii1_cybox_properties(attacker, ioc_type)
        if not properties_xml:
            return None

        package_id = f"example:STIXPackage-{uuid4()}"
        indicator_id = f"example:indicator-{uuid4()}"
        title = escape(evidence.get("evidence_type", "Slips Alert"))
        description = escape(evidence.get("description", ""))

        stix_xml = f"""
        <stix:STIX_Package
          xmlns:stix="http://stix.mitre.org/stix-1"
          xmlns:indicator="http://stix.mitre.org/Indicator-2"
          xmlns:cybox="http://cybox.mitre.org/cybox-2"
          xmlns:AddressObj="http://cybox.mitre.org/objects#AddressObject-2"
          xmlns:DomainNameObj="http://cybox.mitre.org/objects#DomainNameObject-1"
          xmlns:URIObj="http://cybox.mitre.org/objects#URIObject-2"
          xmlns:example="http://example.com"
          xmlns:stixCommon="http://stix.mitre.org/common-1"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          id="{package_id}"
          version="1.2">
          <stix:STIX_Header>
            <stix:Title>{title}</stix:Title>
          </stix:STIX_Header>
          <stix:Indicators>
            <stix:Indicator id="{indicator_id}" xsi:type="indicator:IndicatorType">
              <indicator:Title>{title}</indicator:Title>
              <indicator:Description>{description}</indicator:Description>
              <indicator:Observable>
                <cybox:Object>
                  {properties_xml}
                </cybox:Object>
              </indicator:Observable>
            </stix:Indicator>
          </stix:Indicators>
        </stix:STIX_Package>
        """
        return textwrap.dedent(stix_xml).strip()

    def _build_taxii1_inbox_message(
        self, collection_name: str, stix_xml: str
    ) -> str:
        message_id = uuid4()
        inbox_xml = f"""
        <taxii_11:Inbox_Message
          xmlns:taxii_11="http://taxii.mitre.org/messages/taxii_xml_binding-1.1"
          message_id="{message_id}">
          <taxii_11:Destination_Collection_Name>{escape(collection_name)}</taxii_11:Destination_Collection_Name>
          <taxii_11:Content_Block>
            <taxii_11:Content_Binding>urn:stix.mitre.org:xml:1.2</taxii_11:Content_Binding>
            <taxii_11:Content>
        {stix_xml}
            </taxii_11:Content>
          </taxii_11:Content_Block>
        </taxii_11:Inbox_Message>
        """
        return textwrap.dedent(inbox_xml).strip()

    def _export_taxii1(
        self,
        evidence: dict,
        evidence_id: Optional[str],
        attacker: str,
        ioc_type: str,
        start_ts: float,
    ) -> bool:
        if not self.collection_name:
            self.direct_export_fail += 1
            self._log_export("Direct export failed: collection_name missing.")
            return False

        stix_xml = self._build_taxii1_package(evidence, attacker, ioc_type)
        if not stix_xml:
            self.direct_export_fail += 1
            self._log_export(
                f"Direct export failed: unsupported ioc_type={ioc_type} attacker={attacker}"
            )
            return False

        inbox_xml = self._build_taxii1_inbox_message(
            self.collection_name, stix_xml
        )
        headers = {
            "Content-Type": "application/xml",
            "Accept": "application/xml",
            "X-TAXII-Content-Type": "urn:taxii.mitre.org:message:xml:1.1",
            "X-TAXII-Accept": "urn:taxii.mitre.org:message:xml:1.1",
            "X-TAXII-Protocol": "urn:taxii.mitre.org:protocol:http:1.0",
            "X-TAXII-Services": "urn:taxii.mitre.org:services:1.1",
        }
        auth = None
        if self.taxii_username and self.taxii_password:
            auth = (self.taxii_username, self.taxii_password)
        inbox_url = self._build_url(self.taxii1_inbox_path)

        try:
            response = requests.post(
                inbox_url,
                data=inbox_xml.encode("utf-8"),
                headers=headers,
                auth=auth,
                timeout=10,
            )
        except Exception as err:
            self.direct_export_fail += 1
            self._log_export(f"Direct export failed: TAXII 1 request error {err}")
            duration = time.time() - start_ts
            self._log_export(
                f"Direct export duration_seconds={duration:.3f}"
            )
            return False

        if not response.ok or 'status_type="FAILURE"' in response.text:
            self.direct_export_fail += 1
            self._log_export(
                f"Direct export failed: HTTP {response.status_code} "
                f"response={response.text[:2000]}"
            )
            duration = time.time() - start_ts
            self._log_export(
                f"Direct export duration_seconds={duration:.3f}"
            )
            return False

        self.direct_export_success += 1
        if evidence_id:
            with self.exported_evidence_lock:
                self.exported_evidence_ids.add(evidence_id)
        duration = time.time() - start_ts
        self._log_export(
            f"Direct export success id={evidence_id} "
            f"collection={self.collection_name} "
            f"duration_seconds={duration:.3f}"
        )
        return True

    def add_to_stix_file(self, evidence: dict) -> bool:
        """
        Function to export evidence to a STIX_data.json file in the cwd.
        It keeps appending the given indicator to STIX_data.json until they're
         sent to the
        taxii server
        evidence is a dictionary that contains the alert data
        """
        if self.direct_export:
            self._log_export(
                "Direct export enabled: skipping STIX_data.json write."
            )
            return False

        indicator_data = self._build_indicator(evidence)
        if not indicator_data:
            return False
        indicator, evidence_id, attacker, ioc_type = indicator_data

        self.bundle_objects.append(indicator)
        self._write_bundle()

        if evidence_id:
            with self.exported_evidence_lock:
                self.exported_evidence_ids.add(evidence_id)

        self.print(
            f"Indicator added to STIX bundle at {self.stix_filename}", 2, 0
        )
        self._log_export(
            f"Evidence exported id={evidence_id} attacker={attacker} "
            f"ioc_type={ioc_type} stix_file={self.stix_filename}"
        )
        return True

    def export_evidence_direct(self, evidence: dict) -> bool:
        if not self.should_export():
            self._log_export("Direct export skipped: stix not enabled.")
            return False

        indicator_data = self._build_indicator(evidence)
        if not indicator_data:
            return False
        indicator, evidence_id, attacker, ioc_type = indicator_data

        self.direct_export_attempts += 1
        start = time.time()
        self._log_export(
            f"Direct export attempt id={evidence_id} attacker={attacker} "
            f"ioc_type={ioc_type} "
            f"target={self._base_url()} collection={self.collection_name} "
            f"taxii_version={self.taxii_version}"
        )

        if self.taxii_version == 1:
            return self._export_taxii1(
                evidence, evidence_id, attacker, ioc_type, start
            )

        indicator_payload = json.loads(indicator.serialize())
        envelope = {"objects": [indicator_payload]}

        collection = self._get_collection_cached()
        if not collection:
            self.direct_export_fail += 1
            return False

        try:
            status = collection.add_objects(envelope)
        except Exception as err:
            self.direct_export_fail += 1
            self.print(
                f"Failed to push indicator to TAXII collection: {err}", 0, 3
            )
            response = getattr(err, "response", None)
            if response is not None:
                self._log_export(
                    f"Direct export failed: HTTP {response.status_code} "
                    f"response={response.text[:2000]}"
                )
            else:
                self._log_export(f"Direct export failed: push error {err}")
            duration = time.time() - start
            self._log_export(
                f"Direct export duration_seconds={duration:.3f}"
            )
            return False

        if getattr(status, "failure_count", 0):
            self.direct_export_fail += 1
            self._log_export(
                f"Direct export failed: status failures="
                f"{status.failure_count}"
            )
            for failure in status.failures[:5]:
                obj_id = failure.get("id")
                reason = failure.get("message")
                self._log_export(
                    f"Direct export failure for {obj_id}: {reason}"
                )
            duration = time.time() - start
            self._log_export(
                f"Direct export duration_seconds={duration:.3f}"
            )
            return False

        self.direct_export_success += 1
        if evidence_id:
            with self.exported_evidence_lock:
                self.exported_evidence_ids.add(evidence_id)
        duration = time.time() - start
        self._log_export(
            f"Direct export success id={evidence_id} "
            f"success={status.success_count} "
            f"collection={self.collection_name} "
            f"duration_seconds={duration:.3f}"
        )
        return True

    def schedule_sending_to_taxii_server(self):
        """
        Responsible for publishing STIX_data.json to the taxii server every
        self.push_delay seconds when running on an interface only
        """
        if self.direct_export:
            self._log_export(
                "Scheduler disabled: direct_export enabled."
            )
            return
        while True:
            # on an interface, we use the push delay from slips.yaml
            # on files, we push once when slips is stopping
            time.sleep(self.push_delay)
            # Sometimes the time's up and we need to send to
            # server again but there's no
            # new alerts in stix_data.json yet
            if os.path.exists(self.stix_filename):
                self._log_export(
                    f"Scheduler tick: attempting export "
                    f"stix_file={self.stix_filename}"
                )
                self.export()
            else:
                self.print(
                    f"{self.push_delay} seconds passed, "
                    f"no new alerts in STIX_data.json.",
                    2,
                    0,
                )
                self._log_export(
                    "Scheduler tick: no STIX_data.json found to export."
                )
