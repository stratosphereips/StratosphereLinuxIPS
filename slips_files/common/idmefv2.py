# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import json
from enum import Enum
from idmefv2 import Message
import traceback
from datetime import datetime
from typing import Tuple
from uuid import uuid4
import jsonschema

from slips_files.common.printer import Printer
from slips_files.core.structures.alerts import Alert
from slips_files.core.output import Output
from slips_files.common.slips_utils import utils
from slips_files.core.structures.evidence import (
    Evidence,
    IoCType,
    ThreatLevel,
    EvidenceType,
)


class IDMEFv2Status(Enum):
    EVIDENCE = "Event"
    ALERT = "Incident"


class IDMEFv2Severity(Enum):
    UNKNOWN = "Unknown"
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


DEFAULT_ADDRESS = "0.0.0.0"


class IDMEFv2:
    """
    Class to convert Slips evidence and alerts to
    The Incident Detection Message Exchange Format version 2 (IDMEFv2 format).
    More Details about it here:
    https://www.ietf.org/id/draft-lehmann-idmefv2-03.html#name-the-alert-class
    """

    name = "IDMEFv2"

    def __init__(self, logger: Output, db):
        self.printer = Printer(logger, self.name)
        self.db = db
        self.model: str = utils.get_slips_version()
        self.analyzer = {
            "IP": self.get_host_ip(),
            "Name": "Slips",
            "Model": self.model,
            "Category": ["NIDS"],
            "Data": ["Flow", "Network"],
            "Method": ["Heuristic"],
        }
        # the used idmef version
        self.version = "2.0.3"

    def get_host_ip(self) -> str:
        if not self.db.is_running_non_stop():
            return DEFAULT_ADDRESS
        if host_ip := self.db.get_host_ip():
            return host_ip
        return DEFAULT_ADDRESS

    def print(self, *args, **kwargs):
        return self.printer.print(*args, **kwargs)

    def convert_threat_level_to_idmefv2_severity(
        self, threat_lvl: ThreatLevel
    ) -> str:
        """
        converts slips threat level to a valid IDMEFv2 Severity value
        All threat levels have a corresponding sevirity except
        for the Critical threat level, so we map it to High severity
        """
        if hasattr(IDMEFv2Severity, threat_lvl.name):
            return getattr(IDMEFv2Severity, threat_lvl.name).value

        if threat_lvl.name == "CRITICAL":
            return IDMEFv2Severity.HIGH.value

    def extract_role_type(
        self, evidence: Evidence, role=None
    ) -> Tuple[str, str]:
        """
        extracts the attacker or victim's ip/domain/url from the evidence
        and returns the ip/domain/url and its' type
        :param evidence: a Slips Evidence object
        :param role: can be "victim" or "attacker"
        """
        if role == "attacker":
            ioc = evidence.attacker.value
            ioc_type = evidence.attacker.ioc_type
        elif role == "victim":
            ioc = evidence.victim.value
            ioc_type = evidence.victim.ioc_type

        # map of slips victim types to IDMEF supported types
        type_ = {
            IoCType.IP.name: "IP",
            IoCType.DOMAIN.name: "Hostname",
            IoCType.URL.name: "URL",
        }
        # todo make sure that its a fq domain
        return ioc, type_[ioc_type]

    def extract_file_size_from_evidence(self, evidence: Evidence) -> int:
        """
        the evidence given should be of type EvidenceType.MALICIOUS_DOWNLOADED_FILE
        this function extracts the size of the malicious downloaded file
        from the given evidence
        """
        return int(
            evidence.description.replace(".", "")
            .split("size:")[1]
            .split("from")[0]
        )

    def convert_to_idmef_alert(self, alert: Alert) -> Message:
        """
        converts the given alert to IDMEFv2 alert
        """
        try:
            now = datetime.now(utils.local_tz).isoformat("T")
            iso_start_time = utils.convert_format(
                alert.timewindow.start_time, "iso"
            ).replace(" ", "T")
            iso_end_time = utils.convert_format(
                alert.timewindow.end_time, "iso"
            ).replace(" ", "T")

            msg = Message()
            msg.update(
                {
                    "Version": self.version,
                    "Analyzer": self.analyzer,
                    "Source": [{"IP": alert.profile.ip}],
                    "ID": alert.id,
                    "Status": "Incident",
                    "StartTime": iso_start_time,
                    # Timestamp indicating when the message was created
                    "CreateTime": now,
                    "CorrelID": alert.correl_id,
                    "Note": json.dumps(
                        {
                            "accumulated_threat_level": alert.accumulated_threat_level,
                            "timewindow": alert.timewindow.number,
                            # temporary. there's an issue with the imefv2 python
                            # library validator, it doesn't recognize the endtime
                            # as a supported property!
                            "EndTime": iso_end_time,
                        }
                    ),
                }
            )
            msg.validate()
            return msg

        except jsonschema.exceptions.ValidationError as e:
            self.print(f"Validation failure: {e} {e}", 0, 1)

        except Exception as e:
            self.print(f"Error in convert(): {e}", 0, 1)
            self.print(traceback.format_exc(), 0, 1)

    def is_icmp_code(self, code) -> bool:
        """checks if the given string is an icmp error code"""
        return str(code).startswith("0x")

    def convert_to_idmef_event(self, evidence: Evidence) -> Message:
        """
        Function to convert Slips evidence to
        The Incident Detection Message Exchange Format version 2
        (IDMEFv2 format).
        More Details about it here:
        https://www.ietf.org/id/draft-lehmann-idmefv2-03.html#name-the-alert-class
        """
        try:
            now = datetime.now(utils.local_tz).isoformat("T")
            iso_ts: str = utils.convert_format(
                evidence.timestamp, "iso"
            ).replace(" ", "T")
            attacker, attacker_type = self.extract_role_type(
                evidence, role="attacker"
            )
            severity: str = self.convert_threat_level_to_idmefv2_severity(
                evidence.threat_level
            )

            msg = Message()
            msg.update(
                {
                    "Version": self.version,
                    "Analyzer": self.analyzer,
                    "Status": IDMEFv2Status.EVIDENCE.value,
                    # that is a uuid4()
                    "ID": evidence.id,
                    "Severity": severity,
                    # Timestamp indicating the deduced start of the event
                    "StartTime": iso_ts,
                    # Timestamp indicating when the message was created
                    "CreateTime": now,
                    "Confidence": evidence.confidence,
                    "Description": evidence.description,
                    "Source": [{attacker_type: attacker, "Note": {}}],
                }
            )
            msg["Analyzer"].update({"Method": [evidence.method.value]})

            # netflow icmp flows "ports" start with 0x, they're not really
            # ports they're error codes, so ignore them
            if evidence.src_port and not self.is_icmp_code(evidence.src_port):
                msg["Source"][0].update({"Port": [int(evidence.src_port)]})

            if evidence.proto:
                msg["Source"][0].update({"Protocol": [evidence.proto.name]})

            if evidence.attacker.TI:
                msg["Source"][0].update({"TI": [evidence.attacker.TI]})

            if evidence.attacker.AS:
                msg["Source"][0]["Note"].update({"AS": evidence.attacker.AS})

            if evidence.attacker.rDNS:
                msg["Source"][0]["Note"].update(
                    {"rDNS": evidence.attacker.rDNS}
                )
            if evidence.attacker.SNI:
                msg["Source"][0]["Note"].update({"SNI": evidence.attacker.SNI})

            if hasattr(evidence, "victim") and evidence.victim:
                victim, victim_type = self.extract_role_type(
                    evidence, role="victim"
                )
                msg["Target"] = [
                    {
                        victim_type: victim,
                        "Note": {},
                    }
                ]

                if evidence.dst_port and not self.is_icmp_code(
                    evidence.dst_port
                ):
                    msg["Target"][0].update({"Port": [int(evidence.dst_port)]})

                if evidence.victim.TI:
                    msg["Target"][0]["Note"].update({"TI": evidence.victim.TI})
                if evidence.victim.AS:
                    msg["Target"][0]["Note"].update({"AS": evidence.victim.AS})
                if evidence.victim.rDNS:
                    msg["Target"][0]["Note"].update(
                        {"rDNS": evidence.victim.rDNS}
                    )
                if evidence.victim.SNI:
                    msg["Target"][0]["Note"].update(
                        {"SNI": evidence.victim.SNI}
                    )

            if (
                evidence.evidence_type
                == EvidenceType.MALICIOUS_DOWNLOADED_FILE
                and evidence.attacker.ioc_type == IoCType.MD5
            ):
                msg["Attachment"] = [
                    {
                        "Name": str(uuid4()),
                        "Hash": [f"md5:{evidence.attacker.value}"],
                    }
                ]
                if "size" in evidence.description:
                    msg["Attachment"][0].update(
                        {
                            "Size": self.extract_file_size_from_evidence(
                                evidence
                            )
                        }
                    )

            if evidence.rel_id:
                msg["RelID"] = evidence.rel_id

            if msg["Source"][0]["Note"]:
                # notes in idmef format should be strings
                msg["Source"][0]["Note"] = json.dumps(msg["Source"][0]["Note"])
            else:
                # remove the note field since its empty
                del msg["Source"][0]["Note"]

            if "Target" in msg:
                if msg["Target"][0]["Note"]:
                    msg["Target"][0]["Note"] = json.dumps(
                        msg["Target"][0]["Note"]
                    )
                else:
                    # remove the note field since its empty
                    del msg["Target"][0]["Note"]

            # PS: The "Note" field is added by the evidencehandler before
            # logging the evidence to alerts.json
            msg.validate()
            return msg

        except jsonschema.exceptions.ValidationError as e:
            self.print(f"Validation failure: {e}", 0, 1)
        except Exception as e:
            self.print(f"Error in convert_to_idmef_event(): {e}", 0, 1)
            self.print(traceback.format_exc(), 0, 1)
