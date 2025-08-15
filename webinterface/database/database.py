# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import asyncio
from typing import (
    Dict,
)
import os

from slips_files.common.parsers.config_parser import ConfigParser
from slips_files.core.database.database_manager import DBManager
from slips_files.core.output import Output
from .signals import message_sent
from webinterface.utils import (
    get_open_redis_ports_in_order,
    get_open_redis_servers,
)


class Database(object):
    """
    connects to the latest opened redis server on init
    """

    async def set_db(self, port):
        """changes the redis db we're connected to"""
        self.db = await self.create(port)

    async def create(self, port: int = False):
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
            self.db = await DBManager.create(
                logger=logger,
                output_dir=output_dir,
                redis_port=port,
                conf=conf,
                slips_args=conf.get_args(),
                start_redis_server=False,
                start_sqlite=True,
                flush_db=False,
                main_pid=int(os.getppid()),
            )
            return self
        except RuntimeError:
            return


db_obj: Database = asyncio.run(Database().create())
db: DBManager = db_obj.db


@message_sent.connect
def update_db(port):
    """is called when the user changes the used redis server from the web
    interface"""
    asyncio.create_task(db_obj.set_db(port))
