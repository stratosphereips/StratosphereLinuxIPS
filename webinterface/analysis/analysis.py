# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from quart import Blueprint
import json
from collections import defaultdict
from typing import Dict, List
from slips_files.common.slips_utils import utils
from quart import render_template, g


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
        return utils.convert_ts_format(ts, "%Y/%m/%d %H:%M:%S.%f")
    return utils.convert_ts_format(ts, "%Y/%m/%d %H:%M:%S")


async def get_all_tw_with_ts(profileid):
    if g.db_manager is None:
        return defaultdict(dict)

    try:
        tws = await g.db_manager.get_tws_from_profile(profileid)
        dict_tws = defaultdict(dict)

        if tws:
            for tw_tuple in tws:
                tw_n = tw_tuple[0]
                tw_ts = tw_tuple[1]

                # Optimize: Only convert timestamp to date if needed
                # Cache the conversion to avoid repeated calculations
                try:
                    tw_date = ts_to_date(tw_ts)
                except Exception as date_error:
                    print(
                        f"Error converting timestamp {tw_ts} for {tw_n}: {date_error}"
                    )
                    tw_date = "Unknown"

                dict_tws[tw_n]["tw"] = tw_n
                dict_tws[tw_n]["name"] = (
                    "TW " + tw_n.split("timewindow")[1] + ":" + tw_date
                )
                dict_tws[tw_n]["blocked"] = False  # needed to color profiles
        return dict_tws
    except Exception as e:
        print(f"Error getting timewindows for {profileid}: {e}")
        return defaultdict(dict)


async def get_ip_info(ip):
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

    if g.db_manager is None:
        return data

    try:
        if ip_info := await g.db_manager.get_ip_info(ip):
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
    except Exception as e:
        print(f"Error getting IP info for {ip}: {e}")

    return data


# ----------------------------------------
#
# ----------------------------------------


# ----------------------------------------
# ROUTE FUNCTIONS
# ----------------------------------------
@analysis.route("/profiles_tws")
async def set_profile_tws():
    """
    Set profiles and their timewindows into the tree.
    Blocked are highligted in red.
    """
    if g.db_manager is None:
        return {"data": []}

    try:
        profiles_dict = {}
        # Fetch profiles
        profiles = await g.db_manager.get_profiles()
        if profiles:
            for profileid in profiles:
                profile_word, profile_ip = profileid.split("_")
                profiles_dict[profile_ip] = False

        if blocked_profiles := await g.db_manager.get_malicious_profiles():
            for profile in blocked_profiles:
                blocked_ip = profile.split("_")[-1]
                profiles_dict[blocked_ip] = True

        data = [
            {"profile": profile_ip, "blocked": blocked_state}
            for profile_ip, blocked_state in profiles_dict.items()
        ]
        return {"data": data}
    except Exception as e:
        print(f"Error getting profiles: {e}")
        return {"data": []}


@analysis.route("/info/<ip>")
async def set_ip_info(ip):
    """
    Set info about the ip in route /info/<ip> (geocountry, asn, TI)
    :param ip: active IP
    :return: information about IP in database
    """
    ip_info = await get_ip_info(ip)
    ip_info["ip"] = ip
    data = [ip_info]

    return {"data": data}


@analysis.route("/tws/<ip>")
async def set_tws(ip):
    """
    Set timewindows for selected profile
    :param ip: ip of the profile
    :return:
    """

    # Fetch all profile TWs
    profileid = f"profile_{ip}"
    tws: Dict[str, dict] = await get_all_tw_with_ts(profileid)

    if not tws:
        return {"data": []}

    # Optimize: Get all blocked timewindows for this profile in one call
    # instead of checking each timewindow individually
    blocked_tws: List[str] = []
    if g.db_manager is not None:
        try:
            # Get all blocked timewindows for this profile at once
            blocked_profile_tws = (
                await g.db_manager.get_blocked_timewindows_of_profile(
                    profileid
                )
            )
            if blocked_profile_tws:
                blocked_tws = list(blocked_profile_tws.keys())
        except Exception as e:
            print(f"Error getting blocked timewindows for {profileid}: {e}")
            # Fallback to individual checks if batch method fails
            try:
                for tw_id in tws.keys():
                    is_blocked: bool = (
                        await g.db_manager.get_profileid_twid_alerts(
                            profileid, tw_id
                        )
                    )
                    if is_blocked:
                        blocked_tws.append(tw_id)
            except Exception as fallback_error:
                print(
                    f"Fallback error getting blocked timewindows for {profileid}: {fallback_error}"
                )

    # Mark blocked timewindows
    for tw in blocked_tws:
        if tw in tws:
            tws[tw]["blocked"] = True

    # Build response data
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
async def set_intuples(ip, timewindow):
    """
    Set intuples of a chosen profile and timewindow.
    :param ip: ip of active profile
    :param timewindow: active timewindow
    :return: (tuple, string, ip_info)
    """
    if g.db_manager is None:
        return {"data": []}

    data = []
    profileid = f"profile_{ip}"
    try:
        if intuples := await g.db_manager.get_intuples_from_profile_tw(
            profileid, timewindow
        ):
            intuples = json.loads(intuples)
            for key, value in intuples.items():
                ip, port, protocol = key.split("-")
                ip_info = await get_ip_info(ip)

                outtuple_dict = dict({"tuple": key, "string": value[0]})
                outtuple_dict.update(ip_info)
                data.append(outtuple_dict)
    except Exception as e:
        print(f"Error getting intuples for {profileid}/{timewindow}: {e}")

    return {"data": data}


@analysis.route("/outtuples/<ip>/<timewindow>")
async def set_outtuples(ip, timewindow):
    """
    Set outtuples of a chosen profile and timewindow.
    :param ip: ip of active profile
    :param timewindow: active timewindow
    :return: (tuple, key, ip_info)
    """
    if g.db_manager is None:
        return {"data": []}

    data = []
    profileid = f"profile_{ip}"
    try:
        if outtuples := await g.db_manager.get_outtuples_from_profile_tw(
            profileid, timewindow
        ):
            outtuples = json.loads(outtuples)
            for key, value in outtuples.items():
                ip, port, protocol = key.split("-")
                ip_info = await get_ip_info(ip)
                outtuple_dict = dict({"tuple": key, "string": value[0]})
                outtuple_dict.update(ip_info)
                data.append(outtuple_dict)
    except Exception as e:
        print(f"Error getting outtuples for {profileid}/{timewindow}: {e}")

    return {"data": data}


@analysis.route("/timeline_flows/<ip>/<timewindow>")
async def set_timeline_flows(ip, timewindow):
    """
    Set timeline flows of a chosen profile and timewindow.
    :return: list of timeline flows as set initially in database
    """
    if g.db_manager is None:
        print(
            "Warning: No database manager available for timeline flows request"
        )
        return {"data": []}

    data = []
    profileid = f"profile_{ip}"
    print(f"Fetching timeline flows for {profileid}/{timewindow}")

    try:
        timeline_flows = await g.db_manager.get_all_flows_in_profileid_twid(
            profileid, timewindow
        )

        if not timeline_flows:
            print(f"No flows found for {profileid}/{timewindow}")
            return {"data": []}

        print(
            f"Found {len(timeline_flows)} flows for {profileid}/{timewindow}"
        )

        for key, value in timeline_flows.items():
            try:
                # value is already a dict, no need to json.loads
                if isinstance(value, str):
                    value = json.loads(value)

                # convert timestamp to date
                timestamp = value.get("starttime", value.get("ts", "0"))
                if timestamp and timestamp != "0":
                    dt_obj = ts_to_date(float(timestamp), seconds=True)
                    value["ts"] = dt_obj
                else:
                    value["ts"] = "N/A"

                # limit duration decimals
                duration = value.get("dur", 0)
                if duration:
                    try:
                        value["dur"] = "{:.5f}".format(float(duration))
                    except (ValueError, TypeError):
                        value["dur"] = "0.00000"
                else:
                    value["dur"] = "0.00000"

                # Ensure required fields exist for the frontend
                required_fields = [
                    "saddr",
                    "daddr",
                    "sport",
                    "dport",
                    "proto",
                    "state",
                    "pkts",
                    "allbytes",
                    "spkts",
                    "sbytes",
                    "origstate",
                ]
                for field in required_fields:
                    if field not in value:
                        value[field] = "N/A"

                data.append(value)

            except Exception as flow_error:
                print(f"Error processing flow {key}: {flow_error}")
                continue

    except Exception as e:
        print(
            f"Error getting timeline flows for {profileid}/{timewindow}: {e}"
        )
        import traceback

        traceback.print_exc()

    print(f"Returning {len(data)} processed flows")
    return {"data": data}


@analysis.route("/timeline/<ip>/<timewindow>")
async def set_timeline(
    ip,
    timewindow,
):
    """
    Set timeline data of a chosen profile and timewindow
    :return: list of timeline as set initially in database
    """
    if g.db_manager is None:
        print("@@@@@@@@@@@@@@@@ route /timeline/<ip> no dbmanager!")
        return {"data": []}

    data = []
    profileid = f"profile_{ip}"
    try:
        if timeline := await g.db_manager.get_profiled_tw_timeline(
            profileid, timewindow
        ):
            print(f"@@@@@@@@@@@@@@@@ route /timeline/<ip> {timeline}!")
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
        else:
            print(
                f"@@@@@@@@@@@@@@@@ "
                f"{await g.db_manager.get_profiled_tw_timeline(profileid, timewindow)} returned none??"
            )
            print(
                f"@@@@@@@@@@@@@@@@ g.db_manager {g.db_manager} {type(g.db_manager)}"
            )
    except Exception as e:
        print(f"Error getting timeline for {profileid}/{timewindow}: {e}")
    print("@@@@@@@@@@@@@@@@ set_timeline all good!")
    return {"data": data}


@analysis.route("/alerts/<ip>/<timewindow>")
async def set_alerts(ip, timewindow):
    """
    Set alerts for chosen profile and timewindow
    """
    if g.db_manager is None:
        return {"data": []}

    data = []
    profile = f"profile_{ip}"
    try:
        if alerts := await g.db_manager.get_profileid_twid_alerts(
            profile, timewindow
        ):
            alerts_tw = alerts.get(timewindow, {})
            tws = await get_all_tw_with_ts(profile)

            evidence: Dict[str, str] = await g.db_manager.get_twid_evidence(
                profile, timewindow
            )

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
    except Exception as e:
        print(f"Error getting alerts for {profile}/{timewindow}: {e}")

    return {"data": data}


@analysis.route("/evidence/<ip>/<timewindow>/<alert_id>")
async def set_evidence(ip, timewindow, alert_id: str):
    """
    Set evidence table for the pressed alert in chosen profile and timewindow
    """
    if g.db_manager is None:
        return {"data": []}

    data = []
    profileid = f"profile_{ip}"

    try:
        # get the list of evidence that were part of this alert
        evidence_ids: List[str] = (
            await g.db_manager.get_evidence_causing_alert(
                profileid, timewindow, alert_id
            )
        )
        if evidence_ids:
            for evidence_id in evidence_ids:
                # get the actual evidence represented by the id
                evidence: Dict[str, str] = (
                    await g.db_manager.get_evidence_by_id(
                        profileid, timewindow, evidence_id
                    )
                )
                data.append(evidence)
    except Exception as e:
        print(
            f"Error getting evidence for {profileid}/{timewindow}/{alert_id}: {e}"
        )

    return {"data": data}


@analysis.route("/evidence/<ip>/<timewindow>/")
async def set_evidence_general(ip: str, timewindow: str):
    """
    Set an analysis tag with general evidence
    :param ip: the ip of the profile
    :param timewindow: timewindowx
    :return: {"data": data} where data is a list of evidences
    """
    if g.db_manager is None:
        return {"data": []}

    data = []
    profile = f"profile_{ip}"
    try:
        evidence: Dict[str, str] = await g.db_manager.get_twid_evidence(
            profile, timewindow
        )
        if evidence:
            for evidence_details in evidence.values():
                evidence_details: str
                evidence_details: dict = json.loads(evidence_details)
                data.append(evidence_details)
    except Exception as e:
        print(
            f"Error getting general evidence for {profile}/{timewindow}: {e}"
        )

    return {"data": data}


@analysis.route("/")
async def index():
    return await render_template("analysis.html", title="Slips")
