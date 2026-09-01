import fcntl
import os
from contextlib import contextmanager
from pathlib import Path

SLIPS_LOCKS_DIR = "/tmp/slips"


class SQLiteFlock:
    """Manage the lock file used to serialize SQLite access across processes."""

    @staticmethod
    def prepare_locks_dir():
        """
        Create the shared lock directory with sticky-bit permissions.

        Returns:
        None.
        """
        if not os.path.exists(SLIPS_LOCKS_DIR):
            os.makedirs(SLIPS_LOCKS_DIR, exist_ok=True)
        try:
            os.chmod(SLIPS_LOCKS_DIR, 0o1777)
        except PermissionError:
            # this dir was created by root, so we can't change the permissions
            # but probably root has already set the permissions
            pass

    def __init__(self, name: str, main_pid: int, current_user_uid: int = None):
        """
        Initialize the SQLite flock helper.

        Parameters:
        name: Logical database name used in the lock file name.
        main_pid: Main Slips process PID used to namespace the lock file.
        current_user_uid: Effective uid after temporarily dropping root
            privileges, or None when no privilege drop happened.
        """
        self.lockfile_fd = None
        self._lock_acquired = False
        self.prepare_locks_dir()
        self.lockfile_path = self._build_lockfile_path(name, main_pid)
        self._ensure_lockfile(current_user_uid)

    @staticmethod
    def _build_lockfile_path(name: str, main_pid: int) -> str:
        """
        Build the lock file path for a SQLite database.

        Parameters:
        name: Logical database name used in the lock file name.
        main_pid: Main Slips process PID used to namespace the lock file.

        Returns:
        The full path of the lock file.
        """
        username = os.getenv("USER") or "unknown"
        return os.path.join(
            SLIPS_LOCKS_DIR, f"{username}_{main_pid}_{name}.lock"
        )

    def _ensure_lockfile(self, current_user_uid: int = None):
        """
        Create the lock file when it is missing or owned by a different user.

        Parameters:
        current_user_uid: Effective uid after temporarily dropping root
            privileges, or None when no privilege drop happened.

        Returns:
        None.
        """
        try:
            file_owner_uid = os.stat(self.lockfile_path).st_uid
            lock_file_exists = True
        except FileNotFoundError:
            file_owner_uid = None
            lock_file_exists = False

        if not lock_file_exists or file_owner_uid != current_user_uid:
            # this lock file is shared by every process/module using this
            # db, and close() (see delete_lockfile()) can unlink it at any
            # time from another process. chmod-by-path here would be a
            # TOCTOU race against that unlink; fchmod on the fd we just
            # opened operates on the still-live inode regardless of
            # whether the path gets unlinked out from under us.
            fd = os.open(self.lockfile_path, os.O_WRONLY | os.O_CREAT, 0o600)
            try:
                os.fchmod(fd, 0o600)
            finally:
                os.close(fd)

    @contextmanager
    def acquire(self):
        """
        Acquire and release the inter-process SQLite file lock.

        Returns:
        A context manager that holds the file lock for the duration
            of the context.
        """
        if self._lock_acquired:
            yield
            return

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

    def delete_lockfile(self):
        lockfile = Path(self.lockfile_path)

        try:
            lockfile.unlink()
        except FileNotFoundError:
            pass
