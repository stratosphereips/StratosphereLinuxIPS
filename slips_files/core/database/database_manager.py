from slips_files.core.database.redis_db.database import RedisDB
from slips_files.core.database.sqlite_db.database import SQLiteDB

class DBManager():
    """
    This class will be calling methods from the appropriate db.
    each method added to any of the dbs should have a
    handler in here
    """
    _obj = None
    def __new__(cls,  *args, **kwargs):
        if cls._obj is None or not isinstance(cls._obj, cls):
            # these args will only be passed by slips.py
            # the rest of the modules can create an obj of this class without these args,
            # and will get the same obj instatiated by slips.py
            output_dir, output_queue, redis_port = args[0], args[1], args[2]
            cls._obj = super().__new__(DBManager)
            cls.sqlite = SQLiteDB(output_dir)
            cls.rdb = RedisDB(redis_port, output_queue)

        return cls._obj



