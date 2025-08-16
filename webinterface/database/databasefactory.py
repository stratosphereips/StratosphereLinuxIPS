# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from typing import Dict
import os

from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.core.database.database_manager import DBManager
from slips_files.core.output import Output
from webinterface.utils import (
    get_open_redis_servers,
)
from unittest.mock import Mock


class NoneMock(Mock):
    def __getattr__(self, name):
        return None


class DatabaseFactory:
    """
    A factory helper for creating DBManager instances.
    It does not hold a persistent DBManager instance itself.
    """

    async def create(self, port: int = False):
        """
        Connects to redis db through the DBManager and returns the DBManager instance.
        Connects to the last opened redis server if no port is given.
        """
        dbs: Dict[int, dict] = get_open_redis_servers()
        # Ensure the port exists in the list of open servers
        if str(port) not in dbs:
            print(f"Error: Redis port {port} is not among the open servers.")
            return None

        output_dir = dbs[str(port)]["output_dir"]
        logger = Output(
            stdout=os.path.join(output_dir, "slips.log"),
            stderr=os.path.join(output_dir, "errors.log"),
            slips_logfile=os.path.join(output_dir, "slips.log"),
            create_logfiles=False,
        )
        conf = ConfigParser()
        try:
            # Return the DBManager instance directly
            db_manager_instance = await DBManager.create(
                logger=logger,
                output_dir=output_dir,
                redis_port=port,
                conf=conf,
                # we need to be able to init the manager without starting
                # slips (using ./webinterface) and this class is expecting
                # slips args (for reasons not important here) so this is
                # the workaround i could think of
                slips_args=NoneMock(),
                start_redis_server=False,
                start_sqlite=True,
                flush_db=False,
                main_pid=int(os.getppid()),
            )
            return db_manager_instance
        except RuntimeError as e:
            print(f"RuntimeError creating DBManager for port {port}: {e}")
            return None
        except Exception as e:
            print(
                f"An unexpected error occurred creating DBManager for port {port}: {e}"
            )
            return None
