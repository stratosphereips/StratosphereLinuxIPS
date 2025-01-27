# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from flask import Blueprint
from flask import render_template
import json
from collections import defaultdict
from typing import Dict, List
from ..database.database import db
from slips_files.common.slips_utils import utils

analysis = Blueprint(
    "analysis",
    __name__,
    static_folder="static",
    static_url_path="/analysis/static",
    template_folder="templates",
)


# ----------------------------------------
# HELPER FUNCTIONS
# ----------------------------------------
def ts_to_date(ts, seconds=False):
    if seconds:
        return utils.convert_format(ts, "%Y/%m/%d %H:%M:%S.%f")
    return utils.convert_format(ts, "%Y/%m/%d %H:%M:%S")


def get_all_tw_with_ts(profileid):
    tws = db.get_tws_from_profile(profileid)
    dict_tws = defaultdict(dict)

    for tw_tuple in tws:
        tw_n = tw_tuple[0]
        tw_ts = tw_tuple[1]
        tw_date = ts_to_date(tw_ts)
        dict_tws[tw_n]["tw"] = tw_n
        dict_tws[tw_n]["name"] = (
            "TW " + tw_n.split("timewindow")[1] + ":" + tw_date
        )
        dict_tws[tw_n]["blocked"] = False  # needed to color profiles
    return dict_tws


def get_ip_info(ip):
    """
    Retrieve IP information from database
    :param ip: active IP
    :return: all data about the IP in database
    """
    data = {
        "geocountry": "-",
        "asnorg": "-",
        "reverse_dns": "-",
        "threat_intel": "-",
        "url": "-",
        "down_file": "-",
        "ref_file": "-",
        "com_file": "-",
    }
    if ip_info := db.get_ip_info(ip):
        # Hardcoded decapsulation due to the complexity of data inside.
        # Ex: {"asn":{"asnorg": "CESNET", "timestamp": 0.001}}
        # set geocountry
        geocountry = ip_info.get("geocountry", "-")

        # set asn
        asn = ip_info.get("asn", False)
        asnorg = "-"
        if asn:
            # we have the asn key, do we have the org to display?
            if "org" in asn:
                asnorg = asn["org"]
            elif "number" in asn:
                asnorg = asn["number"]

        reverse_dns = ip_info.get("reverse_dns", "-")

        # set threatintel
        threatintel = ip_info.get("threatintelligence", False)
        threatintel_info = [
            (
                threatintel.get("description", "-")
                + ","
                + threatintel.get("threat_level", "-")
                + " threat level"
                if threatintel
                else "-"
            )
        ]
        # set vt
        vt_scores = ip_info.get("VirusTotal", False)
        url, down_file, ref_file, com_file = "-", "-", "-", "-"
        if vt_scores:
            url = vt_scores.get("URL", "-")
            down_file = vt_scores.get("down_file", "-")
            ref_file = vt_scores.get("ref_file", "-")
            com_file = vt_scores.get("com_file", "-")

        # set data
        data = {
            "geocountry": geocountry,
            "asnorg": asnorg,
            "reverse_dns": reverse_dns,
            "threat_intel": threatintel_info,
            "url": url,
            "down_file": down_file,
            "ref_file": ref_file,
            "com_file": com_file,
        }
    return data


# ----------------------------------------
#
# ----------------------------------------


# ----------------------------------------
# ROUTE FUNCTIONS
# ----------------------------------------
@analysis.route("/profiles_tws")
def set_profile_tws():
    """
    Set profiles and their timewindows into the tree.
    Blocked are highligted in red.
    """
    profiles_dict = {}
    # Fetch profiles
    profiles = db.get_profiles()
    for profileid in profiles:
        profile_word, profile_ip = profileid.split("_")
        profiles_dict[profile_ip] = False

    if blocked_profiles := db.get_malicious_profiles():
        for profile in blocked_profiles:
            blocked_ip = profile.split("_")[-1]
            profiles_dict[blocked_ip] = True

    data = [
        {"profile": profile_ip, "blocked": blocked_state}
        for profile_ip, blocked_state in profiles_dict.items()
    ]
    return {"data": data}


@analysis.route("/info/<ip>")
def set_ip_info(ip):
    """
    Set info about the ip in route /info/<ip> (geocountry, asn, TI)
    :param ip: active IP
    :return: information about IP in database
    """
    ip_info = get_ip_info(ip)
    ip_info["ip"] = ip
    data = [ip_info]

    return {"data": data}


@analysis.route("/tws/<ip>")
def set_tws(ip):
    """
    Set timewindows for selected profile
    :param ip: ip of the profile
    :return:
    """

    # Fetch all profile TWs
    profileid = f"profile_{ip}"
    tws: Dict[str, dict] = get_all_tw_with_ts(profileid)

    blocked_tws: List[str] = []
    for tw_id, twid_details in tws.items():
        is_blocked: bool = db.get_profileid_twid_alerts(profileid, tw_id)
        if is_blocked:
            blocked_tws.append(tw_id)

    for tw in blocked_tws:
        tws[tw]["blocked"] = True

    data = [
        {
            "tw": tw_value["tw"],
            "name": tw_value["name"],
            "blocked": tw_value["blocked"],
        }
        for tw_key, tw_value in tws.items()
    ]
    return {"data": data}


@analysis.route("/intuples/<ip>/<timewindow>")
def set_intuples(ip, timewindow):
    """
    Set intuples of a chosen profile and timewindow.
    :param ip: ip of active profile
    :param timewindow: active timewindow
    :return: (tuple, string, ip_info)
    """
    data = []
    profileid = f"profile_{ip}"
    if intuples := db.get_intuples_from_profile_tw(profileid, timewindow):
        intuples = json.loads(intuples)
        for key, value in intuples.items():
            ip, port, protocol = key.split("-")
            ip_info = get_ip_info(ip)

            outtuple_dict = dict({"tuple": key, "string": value[0]})
            outtuple_dict.update(ip_info)
            data.append(outtuple_dict)

    return {"data": data}


@analysis.route("/outtuples/<ip>/<timewindow>")
def set_outtuples(ip, timewindow):
    """
    Set outtuples of a chosen profile and timewindow.
    :param ip: ip of active profile
    :param timewindow: active timewindow
    :return: (tuple, key, ip_info)
    """

    data = []
    profileid = f"profile_{ip}"
    if outtuples := db.get_outtuples_from_profile_tw(profileid, timewindow):
        outtuples = json.loads(outtuples)
        for key, value in outtuples.items():
            ip, port, protocol = key.split("-")
            ip_info = get_ip_info(ip)
            outtuple_dict = dict({"tuple": key, "string": value[0]})
            outtuple_dict.update(ip_info)
            data.append(outtuple_dict)

    return {"data": data}


@analysis.route("/timeline_flows/<ip>/<timewindow>")
def set_timeline_flows(ip, timewindow):
    """
    Set timeline flows of a chosen profile and timewindow.
    :return: list of timeline flows as set initially in database
    """
    data = []
    profileid = f"profile_{ip}"
    if timeline_flows := db.get_all_flows_in_profileid_twid(
        profileid, timewindow
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

    return {"data": data}


@analysis.route("/timeline/<ip>/<timewindow>")
def set_timeline(
    ip,
    timewindow,
):
    """
    Set timeline data of a chosen profile and timewindow
    :return: list of timeline as set initially in database
    """
    data = []
    profileid = f"profile_{ip}"
    if timeline := db.get_profiled_tw_timeline(profileid, timewindow):
        for flow in timeline:
            flow = json.loads(flow)

            # TODO: check IGMP
            if flow["dport_name"] == "IGMP":
                fields = [
                    "dns_resolution",
                    "dport/proto",
                    "state",
                    "sent",
                    "recv",
                    "tot",
                    "warning",
                    "critical",
                ]
                for field in fields:
                    flow[field] = "????"

            # TODO: check this logic
            if flow["preposition"] == "from":
                temp = flow["saddr"]
                flow["daddr"] = temp

            data.append(flow)

    return {"data": data}


@analysis.route("/alerts/<ip>/<timewindow>")
def set_alerts(ip, timewindow):
    """
    Set alerts for chosen profile and timewindow
    """
    data = []
    profile = f"profile_{ip}"
    if alerts := db.get_profileid_twid_alerts(profile, timewindow):
        alerts_tw = alerts.get(timewindow, {})
        tws = get_all_tw_with_ts(profile)

        evidence: Dict[str, str] = db.get_twid_evidence(profile, timewindow)

        for alert_id, evidence_id_list in alerts_tw.items():
            evidence_count = len(evidence_id_list)
            evidence_details: dict = json.loads(evidence[alert_id])

            timestamp: str = ts_to_date(
                evidence_details["timestamp"], seconds=True
            )

            profile_ip: str = profile.split("_")[1]
            twid: str = tws[timewindow]["name"]

            data.append(
                {
                    "alert": timestamp,
                    "alert_id": alert_id,
                    "profileid": profile_ip,
                    "timewindow": twid,
                    "evidence_count": evidence_count,
                }
            )
    return {"data": data}


@analysis.route("/evidence/<ip>/<timewindow>/<alert_id>")
def set_evidence(ip, timewindow, alert_id: str):
    """
    Set evidence table for the pressed alert in chosen profile and timewindow
    """

    data = []
    profileid = f"profile_{ip}"

    # get the list of evidence that were part of this alert
    evidence_ids: List[str] = db.get_evidence_causing_alert(
        profileid, timewindow, alert_id
    )
    if evidence_ids:
        for evidence_id in evidence_ids:
            # get the actual evidence represented by the id
            evidence: Dict[str, str] = db.get_evidence_by_id(
                profileid, timewindow, evidence_id
            )
            data.append(evidence)
    return {"data": data}


@analysis.route("/evidence/<ip>/<timewindow>/")
def set_evidence_general(ip: str, timewindow: str):
    """
    Set an analysis tag with general evidence
    :param ip: the ip of the profile
    :param timewindow: timewindowx
    :return: {"data": data} where data is a list of evidences
    """
    data = []
    profile = f"profile_{ip}"
    evidence: Dict[str, str] = db.get_twid_evidence(profile, timewindow)
    if evidence:
        for evidence_details in evidence.values():
            evidence_details: str
            evidence_details: dict = json.loads(evidence_details)
            data.append(evidence_details)
    return {"data": data}


@analysis.route("/")
def index():
    return render_template("analysis.html", title="Slips")
