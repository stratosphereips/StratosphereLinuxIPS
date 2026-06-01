# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from typing import (
    Any,
    Dict,
    Optional,
    Tuple,
)
import os
from pathlib import Path
import secrets
import subprocess
import time

import redis

from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.core.database.database_manager import DBManager
from slips_files.core.output import Output
from slips_files.core.database.redis_db.database import RedisDB
from .signals import message_sent
from webinterface.utils import (
    get_open_redis_ports_in_order,
    get_open_redis_servers,
    is_port_open,
)

LOCALHOST = "127.0.0.1"
IMPORTED_REDIS_OUTPUT_DIR = "webinterface/imported_redis"
IMPORTED_REDIS_START_PORT = 32851
IMPORTED_REDIS_END_PORT = 32950


class Database(object):
    """
    connects to the latest opened redis server on init
    """

    def __init__(self):
        # connect to the db manager
        self.db: DBManager = self.get_db_manager_obj()
        self.imported_redis_ports: set[int] = set()

    def set_db(self, port: int, output_dir: Optional[str] = None) -> bool:
        """
        Change the Redis database used by the web interface.

        Parameters:
        port: Redis port to connect to.
        output_dir: Optional output directory for Redis instances that are not
            listed in running_slips_info.txt.

        Return:
        True when the database connection was switched successfully.
        """
        new_db = self.get_db_manager_obj(port, output_dir=output_dir)
        if new_db is None:
            return False
        self.db = new_db
        return True

    def get_db_manager_obj(
        self, port: Optional[int] = None, output_dir: Optional[str] = None
    ) -> Optional[DBManager]:
        """
        Connects to redis db through the DBManager
        connects to the latest opened redis server if no port is given
        """
        if not port:
            # connect to the last opened port if no port is chosen by the
            # user
            last_opened_port = get_open_redis_ports_in_order()[-1][
                "redis_port"
            ]
            port = last_opened_port

        if output_dir is None:
            dbs: Dict[int, dict] = get_open_redis_servers()
            output_dir = dbs[str(port)]["output_dir"]

        logger = Output(
            stdout=os.path.join(output_dir, "slips.log"),
            stderr=os.path.join(output_dir, "errors.log"),
            slips_logfile=os.path.join(output_dir, "slips.log"),
            create_logfiles=False,
        )
        conf = ConfigParser()
        try:
            return DBManager(
                logger,
                output_dir,
                port,
                conf,
                os.getpid(),  # main_pid doesnt matter here
                start_redis_server=False,
                start_sqlite=True,
                flush_db=False,
            )
        except RuntimeError:
            return

    def load_uploaded_rdb(
        self, rdb_path: str, display_name: str
    ) -> Tuple[bool, str, Optional[int]]:
        """
        Start Redis with an uploaded RDB file and switch the web interface.

        Parameters:
        rdb_path: Relative path to the uploaded RDB file.
        display_name: Sanitized filename to show in Redis metadata.

        Return:
        Tuple of success flag, warning message, and Redis port when available.
        """
        port = self._get_available_import_port()
        if port is None:
            return False, "No local Redis port is available.", None

        output_dir = self._create_import_output_dir()
        started, warning = self._start_redis_from_rdb(
            rdb_path, output_dir, port
        )
        if not started:
            self._shutdown_redis(port)
            self._clear_cached_redis_instance(port)
            return False, warning, None

        if not self.set_db(port, output_dir=output_dir):
            self._shutdown_redis(port)
            self._clear_cached_redis_instance(port)
            return (
                False,
                "Slips could not use the uploaded Redis database.",
                None,
            )

        previous_imported_ports = set(self.imported_redis_ports)
        self.imported_redis_ports = {port}
        self._stop_imported_redis_servers(previous_imported_ports)
        self._set_imported_db_name(display_name)
        return True, "", port

    def _get_available_import_port(self) -> Optional[int]:
        """
        Find an unused localhost port for a web-uploaded Redis database.

        Return:
        An available TCP port, or None if none in the reserved range is free.
        """
        for port in range(
            IMPORTED_REDIS_START_PORT, IMPORTED_REDIS_END_PORT + 1
        ):
            if not is_port_open(port):
                return port
        return None

    def _create_import_output_dir(self) -> str:
        """
        Create an output directory for a web-uploaded Redis database.

        Return:
        Relative output directory path.
        """
        token = secrets.token_hex(16)
        output_dir = os.path.join(IMPORTED_REDIS_OUTPUT_DIR, token)
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        return output_dir

    def _start_redis_from_rdb(
        self, rdb_path: str, output_dir: str, port: int
    ) -> Tuple[bool, str]:
        """
        Start a local Redis server backed by an uploaded RDB file.

        Parameters:
        rdb_path: Relative path to the uploaded RDB file.
        output_dir: Relative directory for Redis logs.
        port: Local TCP port to bind Redis to.

        Return:
        Tuple of success flag and warning message.
        """
        rdb = Path(rdb_path)
        cmd = [
            "redis-server",
            "config/redis.conf.template",
            "--port",
            str(port),
            "--bind",
            LOCALHOST,
            "--daemonize",
            "yes",
            "--dir",
            os.fspath(rdb.parent),
            "--dbfilename",
            rdb.name,
        ]
        process = subprocess.run(
            cmd,
            cwd=os.getcwd(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
        )
        if process.returncode != 0:
            return (
                False,
                "Redis could not start with the uploaded database.",
            )

        if not self._wait_for_redis(port):
            return (
                False,
                "Redis rejected or could not load the uploaded database.",
            )

        return True, ""

    def _wait_for_redis(self, port: int, timeout: float = 5.0) -> bool:
        """
        Wait until Redis accepts commands on a local port.

        Parameters:
        port: Redis port to poll.
        timeout: Maximum number of seconds to wait.

        Return:
        True when Redis responds to PING before the timeout.
        """
        client = redis.StrictRedis(
            host=LOCALHOST,
            port=port,
            db=0,
            socket_connect_timeout=0.2,
            socket_timeout=0.2,
        )
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                return bool(client.ping())
            except redis.exceptions.RedisError:
                time.sleep(0.2)
        return False

    def _set_imported_db_name(self, display_name: str) -> None:
        """
        Store a display name for the uploaded Redis database when supported.

        Parameters:
        display_name: Sanitized filename to show in the web interface.

        Return:
        None.
        """
        try:
            self.db.set_input_metadata({"name": display_name})
        except (AttributeError, redis.exceptions.RedisError, TypeError):
            return

    def _stop_imported_redis_servers(self, ports: set[int]) -> None:
        """
        Stop old Redis servers created from previous web uploads.

        Parameters:
        ports: Imported Redis ports to stop.

        Return:
        None.
        """
        for port in ports:
            self._shutdown_redis(port)
            self._clear_cached_redis_instance(port)

    def _shutdown_redis(self, port: int) -> None:
        """
        Shut down a Redis server without saving data.

        Parameters:
        port: Redis port to stop.

        Return:
        None.
        """
        try:
            client = redis.StrictRedis(host=LOCALHOST, port=port, db=0)
            client.shutdown(save=False)
        except redis.exceptions.RedisError:
            return

    def _clear_cached_redis_instance(self, port: int) -> None:
        """
        Remove a RedisDB singleton cached for a local port.

        Parameters:
        port: Redis port whose cached instance should be removed.

        Return:
        None.
        """
        if port in RedisDB.instances:
            del RedisDB.instances[port]


class DatabaseProxy:
    """
    Delegates database calls to the currently selected DBManager instance.
    """

    def __init__(self, database: Database) -> None:
        """
        Store the mutable database holder.

        Parameters:
        database: Database holder that owns the current DBManager.

        Return:
        None.
        """
        self.database = database

    def __getattr__(self, name: str) -> Any:
        """
        Delegate unknown attributes to the active DBManager.

        Parameters:
        name: Attribute name requested by callers.

        Return:
        Attribute from the active DBManager.
        """
        return getattr(self.database.db, name)


db_obj = Database()
db: DatabaseProxy = DatabaseProxy(db_obj)


@message_sent.connect
def update_db(port: int) -> bool:
    """is called when the user changes the used redis server from the web
    interface"""
    return db_obj.set_db(port)
