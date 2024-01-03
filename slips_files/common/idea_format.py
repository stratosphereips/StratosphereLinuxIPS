import validators
from datetime import datetime
from slips_files.common.slips_utils import utils
from slips_files.core.evidence_structure.evidence import (
    dict_to_evidence,
    Evidence,
    Direction,
    IoCType,
    EvidenceType,
    IDEACategory,
    Proto,
    Tag
    )

def idea_format(evidence: Evidence):
    """
    Function to format our evidence according to Intrusion Detection Extensible Alert (IDEA format).
    Detailed explanation of IDEA categories: https://idea.cesnet.cz/en/classifications
    """
    IDEA_dict = {
        'Format': 'IDEA0',
        'ID': evidence.id,
        # both times represet the time of the detection, we probably don't need flow_datetime
        'DetectTime': datetime.now(utils.local_tz).isoformat(),
        'EventTime': datetime.now(utils.local_tz).isoformat(),
        'Category': [f"Anomaly.{evidence.category.anomaly}" if
                     evidence.category.anomaly else evidence.category],
        'Confidence': evidence.confidence,
        'Source': [{}],
    }

    # is the srcip ipv4/ipv6 or mac?
    if validators.ipv4(evidence.profile.ip):
        IDEA_dict['Source'][0].update({'IP4': [evidence.profile.ip]})
    elif validators.ipv6(evidence.profile.ip):
        IDEA_dict['Source'][0].update({'IP6': [evidence.profile.ip]})
    elif validators.mac_address(evidence.profile.ip):
        IDEA_dict['Source'][0].update({'MAC': [evidence.profile.ip]})
    elif validators.url(evidence.profile.ip):
        IDEA_dict['Source'][0].update({'URL': [evidence.profile.ip]})


    # When someone communicates with C&C, both sides of communication are
    # sources, differentiated by the Type attribute, 'C&C' or 'Botnet'
    if evidence.evidence_type == 'Command-and-Control-channels-detection':
        # get the destination IP
        dstip = evidence.description.split('destination IP: ')[
            1].split(' ')[0]

        if validators.ipv4(dstip):
            ip_version = 'IP4'
        elif validators.ipv6(dstip):
            ip_version = 'IP6'

        IDEA_dict['Source'].append({ip_version: [dstip], 'Type': ['CC']})
    print(f"@@@@@@@@@@@@@@@@ evidence.attacker.direction.value {evidence.attacker.direction}")
    # some evidence have a dst ip
    if evidence.attacker.direction == Direction.DST:
        # is the dstip ipv4/ipv6 or mac?
        if validators.ipv4(evidence.attacker.value):
            IDEA_dict['Target'] = [{'IP4': [evidence.attacker.value]}]
        elif validators.ipv6(evidence.attacker.value):
            IDEA_dict['Target'] = [{'IP6': [evidence.attacker.value]}]
        elif validators.mac_address(evidence.attacker.value):
            IDEA_dict['Target'] = [{'MAC': [evidence.attacker.value]}]
        elif validators.url(evidence.attacker.value):
            IDEA_dict['Target'][0].update({'URL': [evidence.profile.ip]})

        # try to extract the hostname/SNI/rDNS of the dstip form the description if available
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
            IDEA_dict['Target'][0].update({'Hostname': [hostname]})

        # update the dstip description if specified in the evidence
        if evidence.source_target_tag:
            # https://idea.cesnet.cz/en/classifications#sourcetargettagsourcetarget_classification
            IDEA_dict['Target'][0].update({'Type': [
                evidence.source_target_tag]})

    elif IoCType.DOMAIN == evidence.attacker.attacker_type:
        # the ioc is a domain
        if evidence.attacker.attacker_type == IoCType.DOMAIN:
            attacker_type = 'Hostname'
        else:
            attacker_type = 'URL'

        target_info = {attacker_type: [evidence.attacker.value]}
        IDEA_dict['Target'] = [target_info]

        # update the dstdomain description if specified in the evidence
        if evidence.source_target_tag:
            IDEA_dict['Target'][0].update(
                {
                    'Type': [evidence.source_target_tag.value]
                }
            )
    elif evidence.source_target_tag:
        # the ioc is the srcip, therefore the tag is
        # desscribing the source
        IDEA_dict['Source'][0].update(
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
    # this idx is used for selecting the right dict to add port/proto
    idx = 0

    if 'Target' in IDEA_dict:
        # if the alert has a target, add the port/proto to the target(dstip)
        key = 'Target'
        idx = 0

    # for C&C alerts IDEA_dict['Source'][0] is the
    # Botnet aka srcip and IDEA_dict['Source'][1] is the C&C aka dstip
    if evidence.evidence_type == EvidenceType.COMMAND_AND_CONTROL_CHANNEL:
        # idx of the dict containing the dstip, we'll
        # use this to add the port and proto to this dict
        key = 'Source'
        idx = 1

    if evidence.port:
        IDEA_dict[key][idx].update({'Port': [evidence.port]})
    if evidence.proto:
        IDEA_dict[key][idx].update({'Proto': [evidence.proto.name]})

    # add the description
    attachment = {
        'Attach': [
            {
                'Content': evidence.description,
                'ContentType': 'text/plain',
            }
        ]
    }
    IDEA_dict.update(attachment)

    # only evidence of type scanning have conn_count
    if evidence.conn_count:
        IDEA_dict['ConnCount'] = evidence.conn_count

    if evidence.evidence_type == EvidenceType.MALICIOUS_DOWNLOADED_FILE:
        IDEA_dict['Attach'] = [
            {
                'Type': ['Malware'],
                'Hash': [f'md5:{evidence.attacker.value}'],
            }

        ]
        if 'size' in evidence.description:
            IDEA_dict.update(
                {'Size': int(evidence.description.replace(".",'').split(
                    'size:')[1].split('from')[0])}
            )

    return IDEA_dict
