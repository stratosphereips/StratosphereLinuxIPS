# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import secrets
from pathlib import Path
from typing import Set, Tuple

from flask import Flask, abort, jsonify, render_template, request
from werkzeug.datastructures import FileStorage
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

from slips_files.common.parsers.config_parser import ConfigParser
from .database.database import db, db_obj
from .database.signals import message_sent
from .analysis.analysis import analysis
from .general.general import general
from .documentation.documentation import documentation
from .utils import (
    get_open_redis_ports_in_order,
    has_rdb_extension,
    is_redis_rdb_file,
)

MAX_RDB_UPLOAD_SIZE = 512 * 1024 * 1024
RDB_UPLOAD_DIR = "webinterface/uploaded_rdb"


def create_app() -> Flask:
    """
    Create and configure the Flask web interface.

    Return:
    Configured Flask app.
    """
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False  # disable sorting of timewindows
    app.config["MAX_CONTENT_LENGTH"] = MAX_RDB_UPLOAD_SIZE
    return app


app = create_app()
CSRF_TOKEN = secrets.token_hex(32)


def get_csrf_token() -> str:
    """
    Return the in-memory CSRF token for the DB switch action.
    """
    return CSRF_TOKEN


def get_available_redis_ports() -> Set[int]:
    """
    Return the list of available Redis ports exposed by Slips.
    """
    return {
        int(entry["redis_port"])
        for entry in get_open_redis_ports_in_order()
        if entry.get("redis_port")
    }


def has_valid_csrf_token() -> bool:
    """
    Check the CSRF token from a state-changing request.

    Return:
    True when the request includes the expected CSRF token.
    """
    csrf_token = request.headers.get("X-CSRF-Token")
    return csrf_token == CSRF_TOKEN


def redis_warning_response(
    warning: str, status_code: int
) -> Tuple[object, int]:
    """
    Build a JSON warning response for Redis upload failures.

    Parameters:
    warning: User-facing warning to render in the web interface.
    status_code: HTTP status code for the response.

    Return:
    Flask JSON response and status code.
    """
    return jsonify({"ok": False, "warning": warning}), status_code


def save_uploaded_rdb(uploaded_file: FileStorage) -> str:
    """
    Save an uploaded Redis RDB file under a generated relative path.

    Parameters:
    uploaded_file: Flask file upload object.

    Return:
    Relative path where the upload was saved.
    """
    Path(RDB_UPLOAD_DIR).mkdir(parents=True, exist_ok=True)
    filename = f"{secrets.token_hex(16)}.rdb"
    upload_path = Path(RDB_UPLOAD_DIR) / filename
    uploaded_file.stream.seek(0)
    uploaded_file.save(upload_path)
    return upload_path.as_posix()


def remove_uploaded_rdb(rdb_path: str) -> None:
    """
    Remove a saved uploaded RDB file.

    Parameters:
    rdb_path: Relative path returned by save_uploaded_rdb.

    Return:
    None.
    """
    try:
        Path(rdb_path).unlink()
    except FileNotFoundError:
        return


@app.route("/redis")
def read_redis_port() -> dict:
    """
    is called when changing the db from the button at the top right
    prints the available redis dbs and ports for the user to choose ffrom
    """
    res = get_open_redis_ports_in_order()
    return {"data": res}


@app.errorhandler(RequestEntityTooLarge)
def handle_upload_too_large(
    error: RequestEntityTooLarge,
) -> Tuple[object, int]:
    """
    Return a JSON warning when a Redis database upload is too large.

    Parameters:
    error: Flask exception for oversized requests.

    Return:
    Flask JSON response and HTTP 413 status code.
    """
    return redis_warning_response(
        "The uploaded Redis database is too large.", 413
    )


@app.route("/redis/upload", methods=["POST"])
def upload_redis_database() -> Tuple[object, int]:
    """
    Verify, load, and switch to an uploaded Redis RDB database.

    Return:
    Flask JSON response with the selected Redis port or a warning.
    """
    if not has_valid_csrf_token():
        abort(403)

    uploaded_file = request.files.get("redis_db")
    if uploaded_file is None:
        return redis_warning_response("Choose a Redis RDB file first.", 400)

    filename = secure_filename(uploaded_file.filename or "")
    if not filename:
        return redis_warning_response("Choose a Redis RDB file first.", 400)

    if not has_rdb_extension(filename):
        return redis_warning_response("Only .rdb files are accepted.", 400)

    if not is_redis_rdb_file(uploaded_file.stream):
        return redis_warning_response(
            "The uploaded file is not a valid Redis RDB file.", 400
        )

    rdb_path = save_uploaded_rdb(uploaded_file)
    loaded, warning, redis_port = db_obj.load_uploaded_rdb(rdb_path, filename)
    remove_uploaded_rdb(rdb_path)
    if not loaded:
        return redis_warning_response(warning, 422)

    return jsonify({"ok": True, "redis_port": redis_port}), 200


@app.route("/")
def index() -> str:
    return render_template(
        "app.html", title="Slips", csrf_token=get_csrf_token()
    )


@app.route("/favicon.ico")
def favicon() -> Tuple[str, int]:
    """
    Return an empty favicon response to avoid browser 404 noise.

    Return:
    Empty response body and HTTP 204 status code.
    """
    return "", 204


@app.route("/db/<int:new_port>", methods=["POST"])
def get_post_javascript_data(new_port: int) -> object:
    """
    is called when the user chooses another db to connect to from the
    button at the top right (from /redis)
    should send a msg to update_db() in database.py
    """
    if not has_valid_csrf_token():
        abort(403)

    if new_port not in get_available_redis_ports():
        abort(404)

    responses = message_sent.send(new_port)
    if not responses or not all(response for _, response in responses):
        abort(503)
    return jsonify({"ok": True, "redis_port": new_port})


@app.route("/info")
def set_pcap_info() -> dict:
    """
    Set information about the pcap.
    """
    info = db.get_analysis_info()

    profiles = db.get_profiles()
    info["num_profiles"] = len(profiles) if profiles else 0

    alerts_number = db.get_number_of_alerts_so_far()
    info["num_alerts"] = int(alerts_number) if alerts_number else 0

    return info


if __name__ == "__main__":
    app.register_blueprint(analysis, url_prefix="/analysis")
    app.register_blueprint(general, url_prefix="/general")
    app.register_blueprint(documentation, url_prefix="/documentation")
    app.run(host="127.0.0.1", port=ConfigParser().web_interface_port)
