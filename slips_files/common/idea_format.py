import traceback
from datetime import datetime
from typing import Tuple

import validators

from slips_files.common.slips_utils import utils
from slips_files.core.evidence_structure.evidence import (
    Evidence,
    IoCType,
    EvidenceType,
    )


def get_ip_version(ip: str) -> str:
    """returns 'IP6' or 'IP4'"""
    if validators.ipv4(ip):
        ip_version = "IP4"
    elif validators.ipv6(ip):
        ip_version = "IP6"
    return ip_version


def extract_cc_server_ip(evidence: Evidence) -> Tuple[str, str]:
    """
    extracts the CC server's IP from CC evidence
    and returns the following in a tuple
    ip_version: 'IP6' or 'IP4'
    and the IP
    """
    # get the destination IP
    cc_server = evidence.description.split("destination IP: ")[1].split(" ")[0]
    return cc_server, get_ip_version(cc_server)


def extract_cc_botnet_ip(evidence: Evidence) -> Tuple[str, str]:
    """
    extracts the botnet's IP aka client's ip from the CC evidence
    and returns the following  in a tuple
    ip_version: 'IP6' or 'IP4'
    and the IP
    """
    # this evidence belongs to the botnet's profile, not the server
    srcip = evidence.attacker.value
    return srcip, get_ip_version(srcip)


def extract_victim(evidence: Evidence) -> Tuple[str, str]:
    ip = evidence.victim.value
    # map of slips victim types to IDEA supported types
    cases = {
        IoCType.IP.name: get_ip_version(ip),
        IoCType.DOMAIN.name: "Hostname",
        IoCType.URL.name: "URL",
    }
    return ip, cases[evidence.victim.victim_type]


def extract_attacker(evidence: Evidence) -> Tuple[str, str]:
    ip = evidence.attacker.value
    # map of slips victim types to IDEA supported types
    cases = {
        IoCType.IP.name: get_ip_version(ip),
        IoCType.DOMAIN.name: "Hostname",
        IoCType.URL.name: "URL",
    }
    return ip, cases[evidence.attacker.attacker_type]


def idea_format(evidence: Evidence):
    """
    Function to format our evidence according to I
    ntrusion Detection Extensible Alert (IDEA format).
    Detailed explanation of IDEA categories:
    https://idea.cesnet.cz/en/classifications
    """
    try:
        idea_dict = {
            "Format": "IDEA0",
            "ID": evidence.id,
            # both times represet the time of the detection, we probably
            # don't need flow_datetime
            "DetectTime": datetime.now(utils.local_tz).isoformat(),
            "EventTime": datetime.now(utils.local_tz).isoformat(),
            "Category": [evidence.category.value],
            "Confidence": evidence.confidence,
            "Source": [{}],
        }

        attacker, attacker_type = extract_attacker(evidence)
        idea_dict["Source"][0].update({attacker_type: [attacker]})

        # according to the IDEA format
        # When someone communicates with C&C, both sides of communication are
        # sources, differentiated by the Type attribute, 'C&C' or 'Botnet'
        # https://idea.cesnet.cz/en/design#:~:text=to%20string%20%E2%80%9CIDEA1
        # %E2%80%9D.-,Sources%20and%20targets,-As%20source%20of
        if evidence.evidence_type == EvidenceType.COMMAND_AND_CONTROL_CHANNEL:
            # botnet, ip_version = extract_cc_botnet_ip(evidence)
            idea_dict["Source"][0].update({"Type": ["Botnet"]})

            cc_server, ip_version = extract_cc_server_ip(evidence)
            server_info: dict = {ip_version: [cc_server], "Type": ["CC"]}

            idea_dict["Source"].append(server_info)

        # the idx of the daddr, in CC detections, it's the second one
        idx = (
            1
            if (evidence.evidence_type == EvidenceType.COMMAND_AND_CONTROL_CHANNEL)
            else 0
        )
        if evidence.port:
            idea_dict["Source"][idx].update({"Port": [evidence.port]})
        if evidence.proto:
            idea_dict["Source"][idx].update({"Proto": [evidence.proto.name]})

        if hasattr(evidence, "victim") and evidence.victim:
            # is the dstip ipv4/ipv6 or mac?
            victims_ip: str
            victim_type: str
            victims_ip, victim_type = extract_victim(evidence)
            idea_dict["Target"] = [{victim_type: [victims_ip]}]

        # update the dstip description if specified in the evidence
        if hasattr(evidence, "source_target_tag") and evidence.source_target_tag:
            # https://idea.cesnet.cz/en/classifications#sourcetargettagsourcetarget_classification
            idea_dict["Source"][0].update({"Type": [evidence.source_target_tag.value]})

        # add the description
        attachment = {
            "Attach": [
                {
                    "Content": evidence.description,
                    "ContentType": "text/plain",
                }
            ]
        }
        idea_dict.update(attachment)

        # only evidence of type scanning have conn_count
        if evidence.conn_count:
            idea_dict["ConnCount"] = evidence.conn_count

        if evidence.evidence_type == EvidenceType.MALICIOUS_DOWNLOADED_FILE:
            idea_dict["Attach"] = [
                {
                    "Type": ["Malware"],
                    "Hash": [f"md5:{evidence.attacker.value}"],
                }
            ]
            if "size" in evidence.description:
                idea_dict.update(
                    {
                        "Size": int(
                            evidence.description.replace(".", "")
                            .split("size:")[1]
                            .split("from")[0]
                        )
                    }
                )

        return idea_dict
    except Exception as e:
        print(f"Error in idea_format(): {e}")
        print(traceback.print_stack())
