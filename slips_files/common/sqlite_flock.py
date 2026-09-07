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
        current_user_uid: unused, kept for backwards compatibility with
            callers that still pass it.
        """
        self.lockfile_fd = None
        self._lock_acquired = False
        self.prepare_locks_dir()
        self.lockfile_path = self._build_lockfile_path(name, main_pid)
        self._ensure_lockfile()

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

    def _ensure_lockfile(self):
        """
        Create the lock file (or fix up its permissions) so that both root
        and non-root Slips processes/modules can open it, regardless of
        which one created it or which one currently holds it.

        This lock file is only ever used as an flock() mutex - it never
        holds sensitive data - so making it world read/write is safe. That
        also means we don't need to drop root privileges (and rely on the
        kernel restoring DAC_OVERRIDE afterwards, which isn't guaranteed
        across all sudo/kernel configurations) just to create it with the
        right owner.

        We deliberately leave the file's *ownership* alone (whoever
        creates it keeps it - e.g. root, when running under sudo):
        chowning it to another uid has been observed to make root unable
        to reopen its own lock file later on some systems, even though
        the file is 0666 (root not being able to open an 0666 file it
        doesn't own isn't standard POSIX behavior, but it happens here).
        Ownership doesn't matter for cleanup either: each lock file name
        is namespaced by the main pid, so a stale lock from a crashed run
        never collides with a future run's lock file - it's just unused
        clutter in SLIPS_LOCKS_DIR.

        Returns:
        None.
        """
        # this lock file is shared by every process/module using this
        # db, and close() (see delete_lockfile()) can unlink it at any
        # time from another process. chmod-by-path here would be a
        # TOCTOU race against that unlink; fchmod on the fd we just
        # opened operates on the still-live inode regardless of
        # whether the path gets unlinked out from under us.
        fd = self._open_lockfile_for_creation()
        try:
            os.fchmod(fd, 0o666)
        finally:
            os.close(fd)

    def _open_lockfile_for_creation(self) -> int:
        """
        Open (or create) the lock file for the fchmod fixup in
        _ensure_lockfile().

        A stale lock file left behind by a process
        that is neither root nor the file's owner - can't be opened at
        all, so there'd be no chance to fchmod it back to something
        everyone can use. In that case, remove it and create a fresh one
        instead.

        Returns:
        An open file descriptor for the lock file.
        """
        try:
            return os.open(self.lockfile_path, os.O_WRONLY | os.O_CREAT, 0o666)
        except PermissionError:
            try:
                os.remove(self.lockfile_path)
            except FileNotFoundError:
                pass
            return os.open(self.lockfile_path, os.O_WRONLY | os.O_CREAT, 0o666)

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

        try:
            self.lockfile_fd = open(self.lockfile_path, "w")
        except PermissionError:
            try:
                owner_uid = os.stat(self.lockfile_path).st_uid
            except OSError as stat_err:
                owner_uid = f"<stat failed: {stat_err}>"
            print(
                f"[SQLiteFlock] failed to open {self.lockfile_path}: "
                f"lockfile owner uid={owner_uid}, current euid={os.geteuid()}"
            )
            raise

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
        """
        Best-effort removal of the shared lock file.

        Every module of a Slips run shares this same lock file (same
        name + main_pid), and any of them may be the one to call this on
        shutdown. Some modules permanently drop root privileges (e.g.
        with -p) while others (or the main process) stay root, so
        whichever one created the file may not be the one deleting it.
        SLIPS_LOCKS_DIR is sticky, so a non-root/non-owner process can't
        unlink a file it doesn't own (PermissionError) - that's fine to
        ignore here: cleanup isn't required for correctness, since the
        lock file name is namespaced by main_pid and a leftover file
        never collides with or blocks a future Slips run.
        """
        lockfile = Path(self.lockfile_path)

        try:
            lockfile.unlink()
        except (FileNotFoundError, PermissionError):
            pass
