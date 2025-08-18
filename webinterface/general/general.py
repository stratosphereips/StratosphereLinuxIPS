# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from quart import Blueprint
from quart import render_template, g

general = Blueprint(
    "general",
    __name__,
    static_folder="static",
    static_url_path="/general/static",
    template_folder="templates",
)


@general.route("/")
async def index():
    return await render_template("general.html")


@general.route("/blockedProfileTWs")
async def set_blocked_profiles_and_tws():
    """
    Function to set blocked profiles and tws
    blocked here means only blocked through the firewall
    """
    if g.db_manager is None:
        return {"data": []}

    try:
        blocked_profiles_and_tws = (
            await g.db_manager.rdb.get_blocked_profiles_and_timewindows()
        )
        data = []

        if blocked_profiles_and_tws:
            for profile, tws in blocked_profiles_and_tws.items():
                data.append({"blocked": profile + str(tws)})

        return {
            "data": data,
        }
    except Exception as e:
        print(f"Error getting blocked profiles: {e}")
        return {"data": []}
