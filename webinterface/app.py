# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import sys
import os

# Add the parent directory to the Python path so we can import slips_files
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import uvicorn
from quart import Quart, render_template, g, current_app
from blinker import signal

from slips_files.common.parsers.config_parser import ConfigParser
from webinterface.database.databasefactory import DatabaseFactory
from webinterface.analysis.analysis import analysis
from webinterface.general.general import general
from webinterface.documentation.documentation import documentation
from webinterface.utils import get_open_redis_ports_in_order

# Create a signal for message sending
message_sent = signal("message-sent")


def get_the_last_used_redis_port() -> None | int:
    ports_info = get_open_redis_ports_in_order()
    if ports_info:
        return ports_info[-1]["redis_port"]


def create_app():
    app = Quart(__name__)
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

    # Ensure required directories exist
    import os

    os.makedirs("/tmp/slips", exist_ok=True)

    try:
        g.db_manager = await DatabaseFactory().create(port=redis_port)
        if g.db_manager is None:
            print(f"Warning: Could not create DBManager for port {redis_port}")
    except Exception as e:
        print(f"Error creating DBManager: {e}")
        g.db_manager = None


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
async def index():
    return await render_template("app.html", title="Slips")


@app.route("/db/<new_port>")
async def get_post_javascript_data(new_port):
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

    # Handle case when db_manager is None
    if db_manager is None:
        return {
            "num_profiles": 0,
            "num_alerts": 0,
            "analysis_start_time": "N/A",
            "analysis_end_time": "N/A",
            "duration": "N/A",
        }

    try:
        # Assuming these methods are async and await their Redis operations
        info = await db_manager.get_analysis_info()
        if info is None:
            info = {}

        profiles = await db_manager.get_profiles()
        info["num_profiles"] = len(profiles) if profiles else 0

        alerts_number = await db_manager.get_number_of_alerts_so_far()
        info["num_alerts"] = int(alerts_number) if alerts_number else 0

        return info
    except Exception as e:
        print(f"Error getting pcap info: {e}")
        return {
            "num_profiles": 0,
            "num_alerts": 0,
            "analysis_start_time": "N/A",
            "analysis_end_time": "N/A",
            "duration": "N/A",
        }


if __name__ == "__main__":
    app.register_blueprint(analysis, url_prefix="/analysis")
    app.register_blueprint(general, url_prefix="/general")
    app.register_blueprint(documentation, url_prefix="/documentation")

    # Quart is natively ASGI, no need for ASGIMiddleware
    host = "0.0.0.0"
    port = ConfigParser().web_interface_port
    uvicorn.run(app, host=host, port=port)
