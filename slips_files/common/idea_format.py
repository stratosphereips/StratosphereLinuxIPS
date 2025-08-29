# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from datetime import datetime
from typing import Tuple

import validators

from slips_files.common.slips_utils import utils
from slips_files.core.structures.evidence import (
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
    cc_server = evidence.description.split("server IP: ")[1].split(" ")[0]
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


def extract_role_type(evidence: Evidence, role=None) -> str:
    """
    extracts the attacker or victim's ip/domain/url from the evidence
    :param role: can be "victim" or "attacker"
    """
    if role == "attacker":
        ioc = evidence.attacker.value
        ioc_type = evidence.attacker.ioc_type
    elif role == "victim":
        ioc = evidence.victim.value
        ioc_type = evidence.victim.ioc_type

    if ioc_type == IoCType.IP:
        return ioc, get_ip_version(ioc)

    # map of slips victim types to IDEA supported types
    idea_type = {
        IoCType.DOMAIN: "Hostname",
        IoCType.URL: "URL",
    }
    return ioc, idea_type[ioc_type]


def idea_format(evidence: Evidence):
    """
    Function to format our evidence according to I
    ntrusion Detection Extensible Alert (IDEA format).
    Detailed explanation of IDEA categories:
    https://idea.cesnet.cz/en/classifications
    """
    # try:
    idea_dict = {
        "Format": "IDEA0",
        "ID": evidence.id,
        # both times represet the time of the detection, we probably
        # don't need flow_datetime
        "DetectTime": datetime.now(utils.local_tz).isoformat(),
        "EventTime": datetime.now(utils.local_tz).isoformat(),
        "Confidence": evidence.confidence,
        "Source": [{}],
    }

    attacker, attacker_type = extract_role_type(evidence, role="attacker")
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

    # the idx of the daddr, in CC detections, is the second one
    idx = (
        1
        if (evidence.evidence_type == EvidenceType.COMMAND_AND_CONTROL_CHANNEL)
        else 0
    )
    if evidence.src_port:
        idea_dict["Source"][idx].update({"Port": [evidence.src_port]})
    if evidence.src_port:
        idea_dict["Target"][idx].update({"Port": [evidence.dst_port]})
    if evidence.proto:
        idea_dict["Source"][idx].update({"Proto": [evidence.proto.name]})

    if hasattr(evidence, "victim") and evidence.victim:
        # is the dstip ipv4/ipv6 or mac?
        victims_ip: str
        victim_type: str
        victims_ip, victim_type = extract_role_type(evidence, role="victim")
        idea_dict["Target"] = [{victim_type: [victims_ip]}]

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

    if evidence.evidence_type == EvidenceType.MALICIOUS_DOWNLOADED_FILE:
        md5 = evidence.description.split("downloaded file ")[-1].split(
            ". size"
        )[0]
        idea_dict["Attach"] = [
            {
                "Type": ["Malware"],
                "Hash": [f"md5:{md5}"],
            }
        ]
        if "size" in evidence.description:
            idea_dict.update(
                {
                    "Size": int(
                        evidence.description.replace(".", "")
                        .split("size:")[1]
                        .split("bytes")[0]
                    )
                }
            )

    return idea_dict
    # except Exception as e:
    #     print(f"Error in idea_format(): {e}")
    #     print(traceback.format_exc())
