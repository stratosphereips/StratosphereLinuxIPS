"""
contains functions used to format the evidence for logging/logging
"""

from typing import (
    Dict,
    Optional,
)
from slips_files.common.style import (
    red,
    cyan,
)
from slips_files.common.slips_utils import utils
from slips_files.core.structures.evidence import (
    Evidence,
    IoCType,
)
from slips_files.core.structures.alerts import (
    Alert,
)


class EvidenceFormatter:
    def __init__(self, db):
        self.db = db

    def get_evidence_to_log(
        self, evidence: Evidence, flow_datetime: str
    ) -> str:
        """
        Returns the line of evidence that we log to alerts logfiles only.
        Not to the CLI.
        """
        timewindow_number = evidence.timewindow.number
        extra_info: str = self.get_printable_attacker_and_victim_info(evidence)
        profile_info = self.get_printable_profile_info(evidence)

        evidence_str = (
            f"{flow_datetime} (TW {timewindow_number}): "
            f"Src IP {profile_info}. "
            f"Detected {evidence.description} {extra_info}"
        )

        return evidence_str

    def get_printable_profile_info(self, evidence: Evidence) -> str:
        """
        Formats profile information including IP and
        optional hostname, ensuring alignment.
        """
        ip = evidence.profile.ip
        hostname = self.db.get_hostname_from_profile(str(evidence.profile))

        if not hostname:
            return f"{ip:26}"

        # Adjust alignment to ensure total length of 26
        # characters (IP + hostname)
        padding_len = 26 - len(ip) - len(hostname) - 3
        return f"{ip} ({hostname}){' ' * padding_len}"

    def get_printable_alert(self, alert: Alert) -> str:
        """
        returns the printable alert.
        aka the start and end time of the timewindow causing the alert
        """
        time_format = "%Y/%m/%d %H:%M:%S"
        twid_start_time: str = utils.convert_format(
            alert.timewindow.start_time, time_format
        )
        tw_stop_time: str = utils.convert_format(
            alert.timewindow.end_time, time_format
        )

        alert_to_print = f"IP {alert.profile.ip} "
        hostname: Optional[str] = self.db.get_hostname_from_profile(
            str(alert.profile)
        )
        if hostname:
            alert_to_print += f"({hostname}) "

        alert_to_print += (
            f"detected as malicious in timewindow {alert.timewindow.number} "
            f"(start {twid_start_time}, stop {tw_stop_time}) \n"
        )

        return alert_to_print

    def format_evidence_for_printing(
        self,
        alert: Alert,
        all_evidence: Dict[str, Evidence],
    ) -> str:
        """
        Function to format the string with all the desciption of the
        evidence causing the given alert
        """
        # once we reach a certain threshold of accumulated
        # threat_levels, we produce an alert
        # Now instead of printing the last evidence only,
        # we print all of them
        alert_to_print: str = red(self.get_printable_alert(alert))
        alert_to_print += red("given the following evidence:\n")

        for evidence in all_evidence.values():
            evidence: Evidence = self.add_threat_level_to_evidence_description(
                evidence
            )
            evidence_string = self.line_wrap(
                f"Detected {evidence.description}"
            )
            alert_to_print += cyan(f"\t- {evidence_string}\n")

        # Add the timestamp to the alert.
        # this datetime, the one that is printed, will be of the last
        # evidence only
        readable_datetime: str = utils.convert_format(
            alert.last_evidence.timestamp, utils.alerts_format
        )
        alert_to_print: str = red(f"{readable_datetime} ") + alert_to_print
        return alert_to_print

    def add_threat_level_to_evidence_description(
        self, evidence: Evidence
    ) -> Evidence:
        evidence.description += (
            f" threat level: " f"{evidence.threat_level.name.lower()}."
        )
        return evidence

    def get_printable_attacker_and_victim_info(
        self, evidence: Evidence
    ) -> str:
        """
        Checks for IPs in the attacker and victim fields of the given
        evidence and returns both attacker and victim
        ip_identification from the database.
        """
        results = []

        for entity_name in ("attacker", "victim"):
            entity = getattr(evidence, entity_name, None)
            if not entity or entity.ioc_type != IoCType.IP.name:
                continue

            cached_info = self.db.get_ip_identification(entity.value) or {}
            info_parts = []
            for info_type, info in cached_info.items():
                if not info:
                    continue

                cleaned_type = info_type.replace("_", " ")
                info_parts.append(f"{cleaned_type}: {info}")

            if info_parts:
                results.append(f"IP {entity.value}: " + ", ".join(info_parts))

        return ", ".join(results)

    def line_wrap(self, txt):
        """
        is called for evidence that are goinng to be printed in the terminal
        line wraps the given text so it looks nice
        """
        # max chars per line
        wrap_at = 155

        wrapped_txt = ""
        for indx in range(0, len(txt), wrap_at):
            wrapped_txt += txt[indx : indx + wrap_at]
            wrapped_txt += f'\n{" "*10}'

        # remove the \n at the end
        wrapped_txt = wrapped_txt[:-11]
        if wrapped_txt.endswith("\n"):
            wrapped_txt = wrapped_txt[:-1]

        return wrapped_txt
