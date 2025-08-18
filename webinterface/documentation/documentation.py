# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from quart import Blueprint
from quart import render_template

documentation = Blueprint(
    "documentation",
    __name__,
    static_folder="static",
    static_url_path="/documentation/static",
    template_folder="templates",
)


@documentation.route("/")
async def index():
    return await render_template("documentation.html")
