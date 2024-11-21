from typing import (
    Dict,
    Optional,
)
import os

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

    def __init__(self):
        # connect to the db manager
        self.db = self.get_db_manager_obj()

    def set_db(self, port):
        """changes the redis db we're connected to"""
        self.db = self.get_db_manager_obj(port)

    def get_db_manager_obj(self, port: int = False) -> Optional[DBManager]:
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
        output_dir = dbs[port]["output_dir"]
        logger = Output(
            stdout=os.path.join(output_dir, "slips.log"),
            stderr=os.path.join(output_dir, "errors.log"),
            slips_logfile=os.path.join(output_dir, "slips.log"),
        )
        try:
            return DBManager(
                logger,
                output_dir,
                port,
                start_redis_server=False,
            )
        except RuntimeError:
            return


db = Database()


@message_sent.connect
def update_db(app, port):
    """is called when the user changes the used redis server from the web
    interface"""
    db.set_db(port)
