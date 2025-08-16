# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from flask import Flask, render_template, g, current_app

from slips_files.common.parsers.config_parser import ConfigParser
from .database.databasefactory import DatabaseFactory, message_sent
from .analysis.analysis import analysis
from .general.general import general
from .documentation.documentation import documentation
from .utils import get_open_redis_ports_in_order


# Global instance of the Database factory helper.
# This is a factory, not the DBManager instance itself.
db_factory = DatabaseFactory()


def get_the_last_used_redis_port() -> None | int:
    ports_info = get_open_redis_ports_in_order()
    if ports_info:
        return ports_info[-1]["redis_port"]


def create_app():
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False  # disable sorting of timewindows

    # Use the last opened port as the initial port for the web interface
    initial_port = get_open_redis_ports_in_order()[-1]["redis_port"]
    app.config["CURRENT_REDIS_PORT"] = initial_port

    return app


app = create_app()


@app.before_request
async def before_request_db_connection():
    """
    Connect to the database before each request and store the
    connection object on Flask's 'g' object.
    """
    redis_port = current_app.config["CURRENT_REDIS_PORT"]
    g.db_manager = await DatabaseFactory().create(port=redis_port)


@app.teardown_appcontext
async def teardown_db_connection(exception):
    """
    Close the Redis connection after each request.
    This function is called even if an exception occurs.
    """
    db_manager = g.pop("db_manager", None)
    if db_manager:
        await db_manager.close_all_dbs()


@app.route("/redis")
async def read_redis_port():
    """
    is called when changing the db from the button at the top right
    prints the available redis dbs and ports for the user to choose ffrom
    """
    res = get_open_redis_ports_in_order()
    return {"data": res}


@app.route("/")
def index():
    return render_template("app.html", title="Slips")


@app.route("/db/<new_port>")
def get_post_javascript_data(new_port):
    """
    is called when the user chooses another db to connect to from the
    button at the top right (from /redis)
    Updates the app's configuration for subsequent requests.
    """
    # Update the app's config so that the next request
    # uses the new port.
    current_app.config["CURRENT_REDIS_PORT"] = int(new_port)
    # This signal might be used by other parts of the system
    # but the Flask app now manages its own state via app.config.
    message_sent.send(int(new_port))
    # It seems the redirect is not needed for a client-side API call
    # return redirect(url_for("index"))
    return {"message": f"Switched to Redis on port {new_port}"}


@app.route("/info")
async def set_pcap_info():
    """
    Set information about the pcap.
    This route is now async and uses the per-request db_manager.
    """
    # Access the DBManager from the global context
    db_manager = g.db_manager

    # Assuming these methods are async and await their Redis operations
    info = await db_manager.get_analysis_info()

    profiles = await db_manager.get_profiles()
    info["num_profiles"] = len(profiles) if profiles else 0

    alerts_number = await db_manager.get_number_of_alerts_so_far()
    info["num_alerts"] = int(alerts_number) if alerts_number else 0

    return info


if __name__ == "__main__":
    app.register_blueprint(analysis, url_prefix="/analysis")
    app.register_blueprint(general, url_prefix="/general")
    app.register_blueprint(documentation, url_prefix="/documentation")
    app.run(host="0.0.0.0", port=ConfigParser().web_interface_port)
