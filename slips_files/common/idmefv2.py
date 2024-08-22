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
        self.model = f"Stratosphere Linux IPS {utils.get_slips_version()}"
        self.analyzer = {
            "IP": "192.168.1.2",
            "Name": "Slips",
            "Model": self.model,
            "Category": ["NIDS"],
            "Data": ["Flow"],
            "Method": ["Heuristic"],
        }
        # the used idmef version
        self.version = "2.0.3"

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
            ioc_type = evidence.attacker.attacker_type
        elif role == "victim":
            ioc = evidence.victim.value
            ioc_type = evidence.victim.victim_type

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

    def remove_unwanted_fields(self, msg: Message) -> Message:
        # these fields contain nothing about the details of the evidence
        # and they are duplicate striongs in every evidence that take space
        # in alerts.json
        # it's better to remove them after validating the msg
        for field in ("Analyzer", "Version"):
            msg.pop(field)
        return msg

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
            # TODO should be logged using a module's print!
            print(f"IDMEFv2 Validation failure: {e.message}")

        except Exception as e:
            print(f"Error in convert(): {e}")
            print(traceback.format_exc())

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
                    "Source": [{attacker_type: attacker}],
                }
            )

            if evidence.port:
                msg["Source"][0].update({"Port": [evidence.port]})

            if evidence.proto:
                msg["Source"][0].update({"Protocol": [evidence.proto.name]})

            if hasattr(evidence, "victim") and evidence.victim:
                victim, victim_type = self.extract_role_type(
                    evidence, role="victim"
                )
                msg["Target"] = [{victim_type: victim}]

            # todo check that we added all the fields from the plan
            # todo add alerts too not just evidence
            if (
                evidence.evidence_type
                == EvidenceType.MALICIOUS_DOWNLOADED_FILE
                and evidence.attacker.attacker_type == IoCType.MD5
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

            # PS: The "Note" field is added by the evidencehandler before
            # logging the evidence to alerts.json
            msg.validate()
            msg = self.remove_unwanted_fields(msg)
            return msg

        except jsonschema.exceptions.ValidationError as e:
            # TODO should be logged using a module's print!
            print(f"IDMEFv2 Validation failure: {e.message}")

        except Exception as e:
            print(f"Error in convert(): {e}")
            print(traceback.format_exc())
