import validators
from datetime import datetime
from typing import Tuple
from slips_files.common.slips_utils import utils
from slips_files.core.evidence_structure.evidence import (
    Evidence,
    Direction,
    IoCType,
    EvidenceType,
    )


def get_ip_version(ip: str) -> str:
    """returns 'IP6' or 'IP4'"""
    if validators.ipv4(ip):
        ip_version = 'IP4'
    elif validators.ipv6(ip):
        ip_version = 'IP6'
    return ip_version


def extract_cc_server_ip(evidence: Evidence) -> Tuple[str, str]:
    """
    extracts the CC server's IP from CC evidence
    and returns the following in a tuple
    ip_version: 'IP6' or 'IP4'
    and the IP
    """
    # get the destination IP
    cc_server = evidence.description \
        .split('destination IP: ')[1] \
        .split(' ')[0]
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



def idea_format(evidence: Evidence):
    """
    Function to format our evidence according to I
    ntrusion Detection Extensible Alert (IDEA format).
    Detailed explanation of IDEA categories:
    https://idea.cesnet.cz/en/classifications
    """
    idea_dict = {
        'Format': 'IDEA0',
        'ID': evidence.id,
        # both times represet the time of the detection, we probably
        # don't need flow_datetime
        'DetectTime': datetime.now(utils.local_tz).isoformat(),
        'EventTime': datetime.now(utils.local_tz).isoformat(),
        'Category': [evidence.category.value],
        'Confidence': evidence.confidence,
        'Source': [{}],
    }

    # is the srcip ipv4/ipv6 or mac?
    if validators.ipv4(evidence.profile.ip):
        idea_dict['Source'][0].update({'IP4': [evidence.profile.ip]})
    elif validators.ipv6(evidence.profile.ip):
        idea_dict['Source'][0].update({'IP6': [evidence.profile.ip]})
    elif validators.mac_address(evidence.profile.ip):
        idea_dict['Source'][0].update({'MAC': [evidence.profile.ip]})
    elif validators.url(evidence.profile.ip):
        idea_dict['Source'][0].update({'URL': [evidence.profile.ip]})


    # according to the IDEA format
    # When someone communicates with C&C, both sides of communication are
    # sources, differentiated by the Type attribute, 'C&C' or 'Botnet'
    # https://idea.cesnet.cz/en/design#:~:text=to%20string%20%E2%80%9CIDEA1
    # %E2%80%9D.-,Sources%20and%20targets,-As%20source%20of
    if evidence.evidence_type == EvidenceType.COMMAND_AND_CONTROL_CHANNEL:
        botnet, ip_version = extract_cc_botnet_ip(evidence)
        idea_dict['Source'].append({
            ip_version: [botnet],
            'Type': ['Botnet']
            })

        cc_server, ip_version = extract_cc_server_ip(evidence)
        idea_dict['Source'].append({
            ip_version: [cc_server],
            'Type': ['CC']
            })

    # some evidence have a dst ip
    if evidence.attacker.direction == Direction.DST:
        # is the dstip ipv4/ipv6 or mac?
        if validators.ipv4(evidence.attacker.value):
            idea_dict['Target'] = [{'IP4': [evidence.attacker.value]}]
        elif validators.ipv6(evidence.attacker.value):
            idea_dict['Target'] = [{'IP6': [evidence.attacker.value]}]
        elif validators.mac_address(evidence.attacker.value):
            idea_dict['Target'] = [{'MAC': [evidence.attacker.value]}]
        elif validators.url(evidence.attacker.value):
            idea_dict['Target'][0].update({'URL': [evidence.profile.ip]})

        # try to extract the hostname/SNI/rDNS of the dstip form the
        # description if available
        hostname = False
        try:
            hostname = evidence.description.split('rDNS: ')[1]
        except IndexError:
            ...
        try:
            hostname = evidence.description.split('SNI: ')[1]
        except IndexError:
            pass

        if hostname:
            idea_dict['Target'][0].update({'Hostname': [hostname]})

        # update the dstip description if specified in the evidence
        if evidence.source_target_tag:
            # https://idea.cesnet.cz/en/classifications#sourcetargettagsourcetarget_classification
            idea_dict['Target'][0].update({'Type': [
                evidence.source_target_tag]})

    elif IoCType.DOMAIN == evidence.attacker.attacker_type:
        # the ioc is a domain
        if evidence.attacker.attacker_type == IoCType.DOMAIN:
            attacker_type = 'Hostname'
        else:
            attacker_type = 'URL'

        target_info = {attacker_type: [evidence.attacker.value]}
        idea_dict['Target'] = [target_info]

        # update the dstdomain description if specified in the evidence
        if evidence.source_target_tag:
            idea_dict['Target'][0].update(
                {
                    'Type': [evidence.source_target_tag.value]
                }
            )
    elif evidence.source_target_tag:
        # the ioc is the srcip, therefore the tag is
        # desscribing the source
        idea_dict['Source'][0].update(
            {
                'Type': [evidence.source_target_tag.value]
            }
        )

    # add the port/proto
    # for all alerts, the srcip is in IDEA_dict['Source'][0]
    # and the dstip is in IDEA_dict['Target'][0]
    # for alert that only have a source, this is the port/proto
    # of the source ip
    key = 'Source'

    if 'Target' in idea_dict:
        # if the alert has a target, add the port/proto to the target(dstip)
        key = 'Target'

    # for C&C alerts IDEA_dict['Source'][0] is the
    # Botnet aka srcip and IDEA_dict['Source'][1] is the C&C aka dstip
    if evidence.evidence_type == EvidenceType.COMMAND_AND_CONTROL_CHANNEL:
        # idx of the dict containing the dstip, we'll
        # use this to add the port and proto to this dict
        key = 'Source'

    if evidence.port:
        idea_dict[key][0].update({'Port': [evidence.port]})
    if evidence.proto:
        idea_dict[key][0].update({'Proto': [evidence.proto.name]})

    # add the description
    attachment = {
        'Attach': [
            {
                'Content': evidence.description,
                'ContentType': 'text/plain',
            }
        ]
    }
    idea_dict.update(attachment)

    # only evidence of type scanning have conn_count
    if evidence.conn_count:
        idea_dict['ConnCount'] = evidence.conn_count

    if evidence.evidence_type == EvidenceType.MALICIOUS_DOWNLOADED_FILE:
        idea_dict['Attach'] = [
            {
                'Type': ['Malware'],
                'Hash': [f'md5:{evidence.attacker.value}'],
            }

        ]
        if 'size' in evidence.description:
            idea_dict.update(
                {'Size': int(evidence.description.replace(".",'').split(
                    'size:')[1].split('from')[0])}
            )

    return idea_dict


