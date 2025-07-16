import fcntl
import os
import sqlite3
from abc import ABC
from contextlib import contextmanager
from threading import Lock
from time import sleep


from slips_files.common.slips_utils import utils


class ISQLite(ABC):
    """
    Interface for SQLite database operations.
    Any sqlite db that slips connects to should use thisinterface for
    avoiding common sqlite errors

    PS: if you're gonna use cursor.anything, please always create a new cursor
    to avoid shared-cursor bugs from sqlite.
    and use the conn_lock whenever you're accessing the conn
    """

    # to avoid multi threading errors where multiple threads try to write to
    # the same sqlite db at the same time
    # must be used because we're using check_same_thread=False in
    # sqlite3.connect()
    conn_lock = Lock()

    def __init__(self, name: str, main_pid: int, db_file: str):
        """
        :param name: the name of the sqlite db, used to create a lock file
        :param main_pid: the pid of slips.py, used to create a lock file to
         make sure only 1 lockfile is created per slips run per sqlite db
        """
        # when files are created by a non-root user, root and non-root can
        # access them
        # when they're created by root, non-root can access them
        # so drop privs temporarily to create that file bc we need root and
        # non root slips modules to use this lock. (because some modules
        # drop privs when slips runs with -p and others dont)
        current_user_uid = utils.drop_root_privs_temporarily()
        self._init_flock(name, main_pid, current_user_uid)
        if current_user_uid:
            # because if drop_root_privs_temporarily didnt return a uid,
            # it means we're not running as root, so we don't need to regain
            utils.regain_root_privs()

        self.connect(db_file)
        self._enable_wal_mode()

    def connect(self, db_file: str):
        """creates the sqlite db if it doesn't exist, and connects to it"""
        with self._acquire_flock():
            self.conn = sqlite3.connect(
                db_file, check_same_thread=False, timeout=20
            )

    def _init_flock(self, name: str, main_pid: int, current_user_uid: int):
        # to avoid multi processing errors where multiple processes
        # try to write to the same sqlite db at the same time
        # this name needs to change per sqlite db, meaning trustb should have
        # its own lock file that is different from slips' main sqlite db lockfile
        username = os.getenv("USER") or "unknown"
        # we're using the username and pid to create a unique lock file per
        # slips run, so that multiple instances of slips can run at the
        # same time
        self.lockfile_path = os.path.join(
            utils.slips_locks_dir, f"{username}_{main_pid}_{name}.lock"
        )
        try:
            file_owner_uid = os.stat(self.lockfile_path).st_uid
            lock_file_exists = True
        except FileNotFoundError:
            file_owner_uid = None
            lock_file_exists = False

        # check if the lock file was created by another subprocess of
        # the current slips run
        if not lock_file_exists or file_owner_uid != current_user_uid:
            open(self.lockfile_path, "w").close()
            os.chmod(self.lockfile_path, 0o666)

    def _enable_wal_mode(self):
        """
        Enables Write-Ahead Logging (WAL) and sets synchronous mode to FULL.
        WAL is required for safe multi-process access to the SQLite database,
         to avoid the "DB is locked" error
        FULL synchronous ensures durability and avoids 'database is
        malformed' errors.
        """
        with self._acquire_flock():
            # Don't use self.execute — this must not be in a transaction.
            with self.conn_lock:
                self.conn.execute("PRAGMA journal_mode=WAL;")
                self.conn.execute("PRAGMA synchronous=FULL;")

    @contextmanager
    def _acquire_flock(self):
        """Context manager for acquiring and releasing the file lock."""
        if getattr(self, "_lock_acquired", False):
            yield  # already held
            return

        # to avoid multiprocess issues with sqlite,
        # we use a lock file, if the lock file is acquired by a different
        # proc, the current proc will wait until the lock is released
        self.lockfile_fd = open(self.lockfile_path, "w")
        try:
            fcntl.flock(self.lockfile_fd, fcntl.LOCK_EX)
            self._lock_acquired = True
            yield
        finally:
            self._lock_acquired = False
            try:
                fcntl.flock(self.lockfile_fd, fcntl.LOCK_UN)
                self.lockfile_fd.close()
            except ValueError:
                pass

    def print(self, *args, **kwargs):
        return self.printer.print(*args, **kwargs)

    def get_number_of_tables(self):
        """
        returns the number of tables in the current db
        """
        condition = "type='table'"
        res = self.select(
            "sqlite_master", columns="count(*)", condition=condition, limit=1
        )
        return res[0]

    def create_table(self, table_name, schema):
        query = f"CREATE TABLE IF NOT EXISTS {table_name} ({schema})"
        self.execute(query)

    def insert(self, table_name, values: tuple, columns: str = None):
        if columns:
            placeholders = ", ".join(["?"] * len(values))
            query = (
                f"INSERT INTO {table_name} ({columns}) "
                f"VALUES ({placeholders})"
            )
            self.execute(query, values)
        else:
            query = f"INSERT INTO {table_name} VALUES {values}"  # fallback
            self.execute(query)

    def update(self, table_name, set_clause, condition):
        query = f"UPDATE {table_name} SET {set_clause} WHERE {condition}"
        self.execute(query)

    def delete(self, table_name, condition):
        query = f"DELETE FROM {table_name} WHERE {condition}"
        self.execute(query)

    def select(
        self,
        table_name,
        columns="*",
        condition=None,
        params=(),
        order_by=None,
        limit: int = None,
    ):
        query = f"SELECT {columns} FROM {table_name} "
        if condition:
            query += f" WHERE {condition}"
        if order_by:
            query += f" ORDER BY {order_by}"
        if params:
            cursor = self.execute(query, params)
        else:
            cursor = self.execute(query)

        if not cursor:
            return None

        if limit == 1:
            result = self.fetchone(cursor)
        else:
            result = self.fetchall(cursor)
        return result

    def get_count(self, table, condition=None):
        """
        returns th enumber of matching rows in the given table
        based on a specific contioins
        """
        count = self.select(
            table, columns="COUNT(*)", condition=condition, limit=1
        )
        return count[0] if count else None

    def close(self):
        with self.conn_lock:
            self.conn.close()

    def fetchall(self, cursor):
        """
        wrapper for sqlite fetchall to be able to use a lock
        """
        with self.conn_lock:
            res = cursor.fetchall()
        return res

    def fetchone(self, cursor):
        """
        wrapper for sqlite fetchone to be able to use a lock
        """
        with self.conn_lock:
            res = cursor.fetchone()
        return res

    def log_err(self, query: str, params: tuple, err: str, trial: int):
        self.print(
            f"Error executing query: "
            f"'{query}'. Params: {params}. Error: {err}. "
            f"Retried executing {trial} times but failed. "
            f"Query discarded.",
            0,
            1,
        )

    def execute(self, query: str, params=None) -> None:
        """
        wrapper for sqlite execute() To avoid
         'Recursive use of cursors not allowed' error
         and to be able to use a Lock()

        since sqlite is terrible with multi-process applications
        this function should be used instead of all calls to commit() and
        execute()

        using transactions here is a must.
        Since slips uses python3.10, we can't use autocommit here. we have
        to do it manually
        any conn other than the current one will not see the changes this
        conn did unless they're committed.

        Each call to this function results in 1 sqlite transaction
        """
        trial = 0
        max_trials = 5
        while trial < max_trials:
            try:
                # note that self.conn.in_transaction is not reliable
                # sqlite may change the state internally, on errors for
                # example.
                # if no errors occur, this will be the only transaction in
                # the conn
                # self.conn object is still shared across threads, and SQLite
                # does not allow concurrent use of a single connection without
                # a lock.
                with self.conn_lock:
                    cursor = self.conn.cursor()
                    if self.conn.in_transaction is False:
                        cursor.execute("BEGIN")

                    with self._acquire_flock():
                        if params is None:
                            cursor.execute(query)
                        else:
                            cursor.execute(query, params)

                    # aka END TRANSACTION
                    if self.conn.in_transaction:
                        self.conn.commit()

                return cursor

            except sqlite3.Error as err:
                # no need to manually rollback here
                # sqlite automatically rolls back the tx if an error occurs
                err = str(err)

                if "malformed" in err or "closed database" in err:
                    self.log_err(query, params, err, trial)
                    self.close()
                    return

                trial += 1
                if trial >= max_trials:
                    self.log_err(query, params, err, trial)
                    return

                if "database is locked" in err:
                    sleep(5)
