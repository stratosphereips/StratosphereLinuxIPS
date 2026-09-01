# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""
Exports Slips alerts/evidence to an IDMEFv2 Manager over HTTPS.

Slips acts as an IDMEFv2 Analyzer (the HTTP client) and POSTs one IDMEFv2
JSON message per request to the Manager (the HTTP server), over mutual TLS
1.3, as described in draft-lehmann-idmefv2-https-transport:
  - one POST per alert, normally to "/"
  - body is a single IDMEFv2 JSON object
  - mutual TLS, TLS 1.3 only
  - the Manager certificate must carry a DNS subjectAltName (validated by
    check_hostname); wildcard identifiers are prohibited
"""

import os
import ssl

import httpx

from slips_files.common.abstracts.iexporter import IExporter
from slips_files.common.idmefv2 import IDMEFv2
from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.core.structures.evidence import dict_to_evidence


class IdmefExporter(IExporter):
    def init(self):
        # httpx client, created lazily once configuration is validated.
        self.client = None
        # converts Slips evidence objects to IDMEFv2 Message objects.
        self.idmef = IDMEFv2(self.printer.logger, self.db)
        self.configs_read: bool = self.read_configuration()
        if self.should_export():
            self._build_client()
            self.print(f"Exporting IDMEFv2 alerts to {self.manager_url}.")

    @property
    def name(self):
        return "IdmefExporter"

    def read_configuration(self) -> bool:
        """
        Reads the IDMEFv2 manager configuration.
        Returns True only when idmef_manager export is enabled and the mutual
        TLS material is present, since the transport mandates mutual TLS.
        """
        conf = ConfigParser()

        # Available options ['slack', 'stix', 'idmef_manager']
        self.export_to = conf.export_to()
        if "idmef_manager" not in [str(x).lower() for x in self.export_to]:
            return False

        self.manager_url: str = conf.idmef_manager_url()
        self.ca_path: str = conf.idmef_manager_trusted_ca()
        self.cert_path: str = conf.idmef_manager_client_certificate()
        self.key_path: str = conf.idmef_manager_client_private_key()
        self.timeout: float = conf.idmef_manager_timeout()

        # Mutual TLS material is required; there are no default cert paths.
        missing = [
            path
            for path in (self.ca_path, self.cert_path, self.key_path)
            if not (path and os.path.isfile(path))
        ]
        if missing:
            self.print(
                f"Cannot export to IDMEFv2 manager: missing or unset mutual "
                f"TLS certificate file(s): {', '.join(str(p) for p in missing)}"
                f". Set 'client_certificate', 'client_private_key' and "
                f"'trusted_ca' under exporting_alerts.idmef_manager in "
                f"slips.yaml. Exporting to IDMEFv2 manager aborted..",
                0,
                1,
            )
            return False

        return True

    def _create_ssl_context(self) -> ssl.SSLContext:
        """
        Builds the client-side mutual TLS context.
        TLS 1.3 only, validates the manager's DNS SAN, and presents the
        Slips (analyzer) certificate to the manager.
        """
        context = ssl.create_default_context(
            purpose=ssl.Purpose.SERVER_AUTH,
            cafile=self.ca_path,
        )
        # The draft requires TLS 1.3 or newer and prohibits earlier versions.
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3

        # Present the analyzer certificate to the manager.
        context.load_cert_chain(
            certfile=self.cert_path,
            keyfile=self.key_path,
        )

        # Validate the manager's DNS SAN against the URL hostname.
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        return context

    def _build_client(self):
        """Creates the persistent httpx client used for exporting."""
        ssl_context = self._create_ssl_context()
        timeout = httpx.Timeout(
            connect=5.0,
            read=self.timeout,
            write=self.timeout,
            pool=5.0,
        )
        limits = httpx.Limits(
            max_connections=20,
            max_keepalive_connections=10,
            keepalive_expiry=30.0,
        )
        self.client = httpx.Client(
            verify=ssl_context,
            timeout=timeout,
            limits=limits,
            headers={"Accept": "application/json"},
        )

    def _to_idmef_payload(self, evidence: dict):
        """
        Converts a Slips evidence dict (as published on the export_evidence
        channel) to an IDMEFv2 JSON-serializable payload.
        Returns None if the evidence can't be converted.
        """
        try:
            evidence_obj = dict_to_evidence(evidence)
        except Exception as e:
            self.print(
                f"Could not parse evidence for IDMEFv2 export: {e}", 0, 1
            )
            return None

        idmef_msg = self.idmef.convert_to_idmef_event(evidence_obj)
        if not idmef_msg:
            # convert_to_idmef_event already logged the reason
            return None
        # idmefv2.Message is a dict subclass; make a plain JSON-safe dict
        return dict(idmef_msg)

    def export(self, evidence: dict) -> bool:
        """
        Exports a single Slips evidence to the IDMEFv2 manager as one POST.
        Returns True if the manager acknowledged the alert with a 2xx status.
        """
        if not self.should_export() or not self.client:
            return False

        payload = self._to_idmef_payload(evidence)
        if payload is None:
            return False

        try:
            response = self.client.post(self.manager_url, json=payload)
        except httpx.HTTPError as e:
            self.print(
                f"Failed to export alert to IDMEFv2 manager "
                f"{self.manager_url}: {e}",
                0,
                1,
            )
            return False

        if response.status_code not in range(200, 300):
            self.print(
                f"IDMEFv2 manager rejected alert: "
                f"{response.status_code} {response.text}",
                0,
                1,
            )
            return False

        self.print(
            f"Alert {payload.get('ID')} acknowledged by IDMEFv2 manager "
            f"with HTTP {response.status_code}.",
            2,
            0,
        )
        return True

    def shutdown_gracefully(self):
        """Exits gracefully"""
        if not self.should_export():
            return
        if self.client:
            try:
                self.client.close()
            except Exception:
                pass

    def should_export(self) -> bool:
        """Determines whether to export or not"""
        return self.configs_read
