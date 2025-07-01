import fcntl
import sqlite3
from abc import ABC
from threading import Lock
from time import sleep


class ISQLite(ABC):
    """
    Interface for SQLite database operations.
    Any sqlite db that slips connects to should use thisinterface for
    avoiding common sqlite errors
    """

    # to avoid multi threading errors where multiple threads try to write to
    # the same sqlite db at the same time
    cursor_lock = Lock()

    def __init__(self, name):
        """
        :param name: the name of the sqlite db, used to create a lock file
        """
        # enable write-ahead logging for concurrent reads and writes to
        # avoid the "DB is locked" error
        # to avoid multi processing errors where multiple processes
        # try to write to the same sqlite db at the same time
        # this name needs to change per sqlite db, meaning trustb should have
        # its own lock file that is different from slips' main sqlite db lockfile
        self.lockfile_name = f"/tmp/slips_{name}.lock"
        # important: do not use self.execute here because this query
        # shouldnt be wrapped in a transaction, which is what self.execute(
        # ) does
        self.conn.execute("PRAGMA journal_mode=WAL;")

    def _acquire_flock(self):
        """to avoid multiprocess issues with sqlite,
        we use a lock file, if the lock file is acquired by a different
        proc, the current proc will wait until the lock is released"""
        self.lockfile_fd = open(self.lockfile_name, "w")
        fcntl.flock(self.lockfile_fd, fcntl.LOCK_EX)

    def _release_flock(self):
        try:
            fcntl.flock(self.lockfile_fd, fcntl.LOCK_UN)
            self.lockfile_fd.close()
        except ValueError:
            # to handle trying to release an already released
            # lock "ValueError: I/O operation on closed file"
            pass

    def print(self, *args, **kwargs):
        return self.printer.print(*args, **kwargs)

    def get_number_of_tables(self):
        """
        returns the number of tables in the current db
        """
        query = "SELECT count(*) FROM sqlite_master WHERE type='table';"
        self.execute(query)
        x = self.fetchone()
        return x[0]

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

        self.execute(query, params)
        if limit == 1:
            result = self.fetchone()
        else:
            result = self.fetchall()
        return result

    def get_count(self, table, condition=None):
        """
        returns th enumber of matching rows in the given table
        based on a specific contioins
        """
        query = f"SELECT COUNT(*) FROM {table}"

        if condition:
            query += f" WHERE {condition}"

        self.execute(query)
        return self.fetchone()[0]

    def close(self):
        self.cursor.close()
        self.conn.close()

    def fetchall(self):
        """
        wrapper for sqlite fetchall to be able to use a lock
        """
        with self.cursor_lock:
            res = self.cursor.fetchall()
        return res

    def fetchone(self):
        """
        wrapper for sqlite fetchone to be able to use a lock
        """
        with self.cursor_lock:
            res = self.cursor.fetchone()
        return res

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
                with self.cursor_lock:
                    if self.conn.in_transaction is False:
                        self.cursor.execute("BEGIN")
                    self._acquire_flock()
                    if params is None:
                        self.cursor.execute(query)
                    else:
                        self.cursor.execute(query, params)
                    self._release_flock()

                # aka END TRANSACTION
                if self.conn.in_transaction:
                    self.conn.commit()

                return

            except sqlite3.Error as err:
                self._release_flock()
                # no need to manually rollback here
                # sqlite automatically rolls back the tx if an error occurs
                trial += 1
                if trial >= max_trials:
                    self.print(
                        f"Error executing query: "
                        f"'{query}'. Params: {params}. Error: {err}. "
                        f"Retried executing {trial} times but failed. "
                        f"Query discarded.",
                        0,
                        1,
                    )
                    return

                elif "database is locked" in str(err):
                    sleep(5)
