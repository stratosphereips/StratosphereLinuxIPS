# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from flask import Blueprint
from flask import render_template


from ..database.database import db

general = Blueprint(
    "general",
    __name__,
    static_folder="static",
    static_url_path="/general/static",
    template_folder="templates",
)


@general.route("/")
def index():
    return render_template("general.html")


@general.route("/blockedProfileTWs")
def set_blocked_profiles_and_tws():
    """
    Function to set blocked profiles and tws
    blocked here means only blocked through the firewall
    """
    blocked_profiles_and_tws = db.get_blocked_profiles_and_timewindows()
    data = []

    if blocked_profiles_and_tws:
        for profile, tws in blocked_profiles_and_tws.items():
            data.append({"blocked": profile + str(tws)})

    return {
        "data": data,
    }
