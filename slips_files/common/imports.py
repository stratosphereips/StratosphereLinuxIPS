# common imports for all modules
from slips_files.common.abstracts._module import IModule
from slips_files.core.database.redis_db.database import RedisDB
from slips_files.core.database.database_manager import DBManager
from slips_files.common.config_parser import ConfigParser
from slips_files.common.slips_utils import utils
import multiprocessing