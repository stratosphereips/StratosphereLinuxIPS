from flask import Blueprint
from flask import render_template
import json
from collections import defaultdict
from datetime import datetime
from typing import Dict, List
from database.database import __database__
from slips_files.common.slips_utils import utils

analysis = Blueprint('analysis', __name__, static_folder='static', static_url_path='/analysis/static',
                     template_folder='templates')


# ----------------------------------------
# HELPER FUNCTIONS
# ----------------------------------------
def ts_to_date(ts, seconds=False):
    if seconds:
        return utils.convert_format(ts, '%Y/%m/%d %H:%M:%S.%f')
    return utils.convert_format(ts, '%Y/%m/%d %H:%M:%S')


def get_all_tw_with_ts(profileid):
    tws = __database__.db.zrange(f"tws{profileid}", 0, -1, withscores=True)
    dict_tws = defaultdict(dict)

    for tw_tuple in tws:
        tw_n = tw_tuple[0]
        tw_ts = tw_tuple[1]
        tw_date = ts_to_date(tw_ts)
        dict_tws[tw_n]["tw"] = tw_n
        dict_tws[tw_n]["name"] = "TW" + " " + tw_n.split("timewindow")[1] + ":" + tw_date
        dict_tws[tw_n]["blocked"] = False  # needed to color profiles
    return dict_tws


def get_ip_info(ip):
    """
    Retrieve IP information from database
    :param ip: active IP
    :return: all data about the IP in database
    """
    data = {'geocountry': "-", 'asnorg': "-", 'reverse_dns': "-", "threat_intel": "-", "url": "-", "down_file": "-",
            "ref_file": "-",
            "com_file": "-"}
    if ip_info := __database__.cachedb.hget('IPsInfo', ip):
        ip_info = json.loads(ip_info)
        # Hardcoded decapsulation due to the complexity of data in side. Ex: {"asn":{"asnorg": "CESNET", "timestamp": 0.001}}

        # set geocountry
        geocountry = ip_info.get('geocountry', '-')

        # set asn
        asn = ip_info.get('asn', False)
        asnorg = '-'
        if asn:
            # we have the asn key, do we have the org to display?
            if 'org' in asn:
                asnorg = asn['org']
            elif 'number' in asn:
                asnorg = asn['number']

        reverse_dns = ip_info.get('reverse_dns', '-')

        # set threatintel
        threatintel = ip_info.get('threatintelligence', False)
        threatintel_info = [threatintel.get('description', '-') + "," + threatintel.get('threat_level',
                                                                                 '-') + " threat level" if threatintel else '-']
        # set vt
        vt_scores = ip_info.get("VirusTotal", False)
        url, down_file, ref_file, com_file = '-', '-', '-', '-'
        if vt_scores:
            url = vt_scores.get("URL", "-")
            down_file = vt_scores.get("down_file", "-")
            ref_file = vt_scores.get("ref_file", "-")
            com_file = vt_scores.get("com_file", "-")

        # set data
        data = {'geocountry': geocountry, 'asnorg': asnorg,
                'reverse_dns': reverse_dns,
                'threat_intel': threatintel_info, "url": url,
                "down_file": down_file, "ref_file": ref_file,
                "com_file": com_file}
    return data


# ----------------------------------------
#
# ----------------------------------------


# ----------------------------------------
# ROUTE FUNCTIONS
# ----------------------------------------
@analysis.route("/profiles_tws")
def set_profile_tws():
    '''
    Set profiles and their timewindows into the tree.
    Blocked are highligted in red.
    :return: (profile, [tw, blocked], blocked)
    '''

    profiles_dict = {}
    # Fetch profiles
    profiles = __database__.db.smembers('profiles')
    for profileid in profiles:
        profile_word, profile_ip = profileid.split("_")
        profiles_dict[profile_ip] = False

    if blocked_profiles := __database__.db.smembers('malicious_profiles'):
        for profile in blocked_profiles:
            blocked_ip = profile.split("_")[-1]
            profiles_dict[blocked_ip] = True

    data = [
        {"profile": profile_ip, "blocked": blocked_state}
        for profile_ip, blocked_state in profiles_dict.items()
    ]
    return {
        'data': data
    }


@analysis.route("/info/<ip>")
def set_ip_info(ip):
    '''
    Set info about the ip in route /info/<ip> (geocountry, asn, TI)
    :param ip: active IP
    :return: information about IP in database
    '''
    ip_info = get_ip_info(ip)
    ip_info["ip"] = ip
    data = [ip_info]

    return {
        'data': data
    }


@analysis.route("/tws/<profileid>")
def set_tws(profileid):
    '''
    Set timewindows for selected profile
    :param profileid: ip of the profile
    :return:
    '''

    # Fetch all profile TWs
    tws: Dict[str, dict] = get_all_tw_with_ts(f"profile_{profileid}")

    blocked_tws: List[str] = []
    for tw_id, twid_details in tws.items():
        is_blocked: bool = __database__.db.hget(
            f'profile_{profileid}_{tw_id}',
            'alerts'
        )
        if is_blocked:
            blocked_tws.append(tw_id)

    for tw in blocked_tws:
        tws[tw]['blocked'] = True

    data = [
        {
            "tw": tw_value["tw"],
            "name": tw_value["name"],
            "blocked": tw_value["blocked"],
        }
        for tw_key, tw_value in tws.items()
    ]
    return {
        "data": data
    }


@analysis.route("/intuples/<profile>/<timewindow>")
def set_intuples(profile, timewindow):
    """
    Set intuples of a chosen profile and timewindow.
    :param profile: active profile
    :param timewindow: active timewindow
    :return: (tuple, string, ip_info)
    """
    data = []
    if intuples := __database__.db.hget(
        f"profile_{profile}_{timewindow}", 'InTuples'
    ):
        intuples = json.loads(intuples)
        for key, value in intuples.items():
            ip, port, protocol = key.split("-")
            ip_info = get_ip_info(ip)

            outtuple_dict = dict({'tuple': key, 'string': value[0]})
            outtuple_dict.update(ip_info)
            data.append(outtuple_dict)

    return {
        'data': data
    }

@analysis.route("/outtuples/<profile>/<timewindow>")
def set_outtuples(profile, timewindow):
    """
    Set outtuples of a chosen profile and timewindow.
    :param profile: active profile
    :param timewindow: active timewindow
    :return: (tuple, key, ip_info)
    """

    data = []
    if outtuples := __database__.db.hget(
        f"profile_{profile}_{timewindow}", 'OutTuples'
    ):
        outtuples = json.loads(outtuples)

        for key, value in outtuples.items():
            ip, port, protocol = key.split("-")
            ip_info = get_ip_info(ip)
            outtuple_dict = dict({'tuple': key, 'string': value[0]})
            outtuple_dict.update(ip_info)
            data.append(outtuple_dict)

    return {
        'data': data
    }


@analysis.route("/timeline_flows/<profile>/<timewindow>")
def set_timeline_flows(profile, timewindow):
    """
    Set timeline flows of a chosen profile and timewindow.
    :return: list of timeline flows as set initially in database
    """
    data = []
    if timeline_flows := __database__.db.hgetall(
        f"profile_{profile}_{timewindow}_flows"
    ):
        for key, value in timeline_flows.items():
            value = json.loads(value)

            # convert timestamp to date
            timestamp = value["ts"]
            dt_obj = ts_to_date(timestamp, seconds=True)
            value["ts"] = dt_obj

            # limit duration decimals
            duration = float(value["dur"])
            value["dur"] = "{:.5f}".format(duration)

            data.append(value)

    return {
        'data': data
    }


@analysis.route("/timeline/<profile>/<timewindow>")
def set_timeline(profile, timewindow,):
    """
    Set timeline data of a chosen profile and timewindow
    :return: list of timeline as set initially in database
    """
    data = []

    if timeline := __database__.db.zrange(
        f"profile_{profile}_{timewindow}_timeline", 0, -1
    ):
        for flow in timeline:
            flow = json.loads(flow)

            # TODO: check IGMP
            if flow["dport_name"] == "IGMP":
                flow["dns_resolution"] = "????"
                flow["dport/proto"] = "????"
                flow["state"] = "????"
                flow["sent"] = "????"
                flow["recv"] = "????"
                flow["tot"] = "????"
                flow["warning"] = "????"
                flow["critical warning"] = "????"

            # TODO: check this logic
            if flow["preposition"] == "from":
                temp = flow["saddr"]
                flow["daddr"] = temp

            data.append(flow)

    return {
        'data': data
    }


@analysis.route("/alerts/<profile>/<timewindow>")
def set_alerts(profile, timewindow):
    """
    Set alerts for chosen profile and timewindow
    """
    data = []
    profile = f"profile_{profile}"
    if alerts := __database__.db.hget("alerts", profile):
        alerts = json.loads(alerts)
        alerts_tw = alerts.get(timewindow, {})
        tws = get_all_tw_with_ts(profile)

        evidence: Dict[str, str] = __database__.db.hgetall(
            f'{profile}_{timewindow}_evidence'
            )

        for alert_id, evidence_id_list in alerts_tw.items():
            evidence_count = len(evidence_id_list)
            evidence_details: dict = json.loads(evidence[alert_id])

            timestamp: str = ts_to_date(
                evidence_details["timestamp"],
                seconds=True
                )

            profile_ip: str = profile.split("_")[1]
            twid: str = tws[timewindow]["name"]

            data.append(
                {
                     "alert": timestamp,
                     "alert_id": alert_id,
                     "profileid": profile_ip,
                     "timewindow": twid,
                     "evidence_count": evidence_count
                    }
            )
    return {"data": data}


@analysis.route("/evidence/<profile>/<timewindow>/<alert_id>")
def set_evidence(profile, timewindow, alert_id):
    """
    Set evidence table for the pressed alert in chosem profile and timewindow
    """

    data = []
    if alerts := __database__.db.hget("alerts", f"profile_{profile}"):
        alerts = json.loads(alerts)
        alerts_tw = alerts[timewindow]
        # get the list of evidence that were part of this alert
        evidence_ids: List[str] = alerts_tw[alert_id]

        profileid = f"profile_{profile}"
        evidence: Dict[str, str] = __database__.db.hgetall(
            f'{profileid}_{timewindow}_evidence'
        )

        for evidence_id in evidence_ids:
            temp_evidence = json.loads(evidence[evidence_id])
            if "source_target_tag" not in temp_evidence:
                temp_evidence["source_target_tag"] = "-"
            data.append(temp_evidence)
    return {"data": data}


@analysis.route("/evidence/<profile>/<timewindow>/")
def set_evidence_general(profile: str, timewindow: str):
    """
    Set an analysis tag with general evidence
    :param profile: the ip
    :param timewindow: timewindowx
    :return: {"data": data} where data is a list of evidences
    """
    data = []
    profile = f"profile_{profile}"

    evidence: Dict[str, str] = __database__.db.hgetall(
            f'{profile}_{timewindow}_evidence'
    )
    if evidence :
        for evidence_details in evidence.values():
            evidence_details: dict = json.loads(evidence_details)
            if "source_target_tag" not in evidence_details:
                evidence_details["source_target_tag"] = "-"
            data.append(evidence_details)
    return {"data": data}


@analysis.route('/')
def index():
    return render_template('analysis.html', title='Slips')
