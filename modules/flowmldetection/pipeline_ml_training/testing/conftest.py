# conftest.py - robust capture of both stdout/stderr and pytest terminal reporter output
# Place in: modules/flowmldetection/pipeline_ml_training/testing/conftest.py

import os
import sys
import datetime
import io
import traceback

# --- Ensure pipeline_ml_training importable during collection ---
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# --- Prepare logfile path immediately (so it's available even if collection fails) ---
LOGS_DIR = os.path.join(os.path.dirname(__file__), "test_logs")
try:
    os.makedirs(LOGS_DIR, exist_ok=True)
except Exception as e:
    raise RuntimeError(f"[conftest] Could not create test_logs directory {LOGS_DIR}: {e}")

_dt = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
_logfile_path = os.path.join(LOGS_DIR, f"pytest_cli_{_dt}.log")

# We'll open the file in pytest_configure and keep handle in _log_fh
_log_fh = None

# Small helpers
def _fsync_file(f):
    try:
        f.flush()
        os.fsync(f.fileno())
    except Exception:
        try:
            f.flush()
        except Exception:
            pass

class _TeeIO(io.TextIOBase):
    """Write to both original stream and file handle."""
    def __init__(self, original_stream, filehandle):
        self._orig = original_stream
        self._fh = filehandle
        # preserve encoding/attributes
        self.encoding = getattr(original_stream, "encoding", "utf-8")

    def write(self, s):
        if s is None:
            return
        if not isinstance(s, str):
            s = str(s)
        try:
            self._orig.write(s)
        except Exception:
            pass
        try:
            self._fh.write(s)
        except Exception:
            pass

    def flush(self):
        try:
            self._orig.flush()
        except Exception:
            pass
        try:
            self._fh.flush()
            try:
                os.fsync(self._fh.fileno())
            except Exception:
                pass
        except Exception:
            pass

# Will hold originals for restoring
_original_stdout = None
_original_stderr = None
_original_tr_write = None
_original_tr_tw_write = None
_terminalreporter_patched = False

def _patch_terminal_reporter_write(config, fh):
    """
    Try to patch the terminal reporter so anything written via it is also written to fh.
    We try to wrap both terminalreporter.write(...) and terminalreporter._tw.write(...).
    """
    global _original_tr_write, _original_tr_tw_write, _terminalreporter_patched

    try:
        tr = config.pluginmanager.get_plugin("terminalreporter")
        if tr is None:
            print("[conftest] WARN: terminalreporter plugin not found; may miss some output", file=sys.__stdout__)
            return False

        # Wrap terminalreporter.write (calls may exist)
        if hasattr(tr, "write"):
            try:
                _original_tr_write = tr.write

                def tr_write_wrapped(s, **kwargs):
                    # write to file (no exception propagation)
                    try:
                        fh.write(s)
                        fh.flush()
                    except Exception:
                        pass
                    # call original
                    try:
                        return _original_tr_write(s, **kwargs)
                    except Exception:
                        # if original fails, still avoid crashing tests
                        traceback.print_exc(file=sys.__stderr__)
                tr.write = tr_write_wrapped
            except Exception:
                pass

        # Wrap inner TerminalWriter._tw.write if present
        if hasattr(tr, "_tw") and hasattr(tr._tw, "write"):
            try:
                _original_tr_tw_write = tr._tw.write

                def tr_tw_write_wrapped(s, *a, **kw):
                    # write to file (no exception propagation)
                    try:
                        fh.write(s)
                        fh.flush()
                    except Exception:
                        pass
                    try:
                        return _original_tr_tw_write(s, *a, **kw)
                    except Exception:
                        traceback.print_exc(file=sys.__stderr__)
                tr._tw.write = tr_tw_write_wrapped
            except Exception:
                pass

        _terminalreporter_patched = True
        return True
    except Exception as e:
        print(f"[conftest] WARN: could not patch terminalreporter: {e}", file=sys.__stdout__)
        return False

def _unpatch_terminal_reporter(config):
    global _original_tr_write, _original_tr_tw_write, _terminalreporter_patched
    try:
        tr = config.pluginmanager.get_plugin("terminalreporter")
        if not tr:
            return
        if _original_tr_write is not None and hasattr(tr, "write"):
            try:
                tr.write = _original_tr_write
            except Exception:
                pass
        if _original_tr_tw_write is not None and hasattr(tr, "_tw") and hasattr(tr._tw, "write"):
            try:
                tr._tw.write = _original_tr_tw_write
            except Exception:
                pass
    except Exception:
        pass
    _terminalreporter_patched = False

# pytest hooks
def pytest_configure(config):
    """
    Runs early. Open logfile, tee stdout/stderr and patch terminal reporter write methods.
    """
    global _log_fh, _original_stdout, _original_stderr

    # Open logfile for append (so multiple sessions don't overwrite accidentally)
    try:
        _log_fh = open(_logfile_path, "a", encoding="utf-8", buffering=1)
    except Exception as e:
        print(f"[conftest] FATAL: cannot open logfile {_logfile_path}: {e}", file=sys.__stderr__)
        raise

    # Write header and fsync
    try:
        header = f"[conftest] log started: {_logfile_path}\n"
        _log_fh.write(header)
        _fsync_file(_log_fh)
    except Exception:
        pass

    # Tee stdout/stderr to file + original terminal
    try:
        _original_stdout = sys.stdout
        _original_stderr = sys.stderr
        sys.stdout = _TeeIO(sys.__stdout__, _log_fh)
        sys.stderr = _TeeIO(sys.__stderr__, _log_fh)
    except Exception as e:
        print(f"[conftest] WARN: could not replace stdout/stderr: {e}", file=sys.__stderr__)

    # Patch terminal reporter writes
    patched = _patch_terminal_reporter_write(config, _log_fh)
    if patched:
        print(f"[conftest] patched terminalreporter writes to logfile {_logfile_path}", file=sys.__stdout__)
    else:
        print(f"[conftest] WARN: terminalreporter not patched; some output may be missing", file=sys.__stdout__)

def pytest_unconfigure(config):
    """
    Restore stdout/stderr, unpatch terminal reporter and close the logfile.
    """
    global _log_fh, _original_stdout, _original_stderr

    # Unpatch terminal reporter first
    try:
        _unpatch_terminal_reporter(config)
    except Exception:
        pass

    # Restore stdout/stderr
    try:
        if _original_stdout is not None:
            sys.stdout = _original_stdout
        else:
            sys.stdout = sys.__stdout__
        if _original_stderr is not None:
            sys.stderr = _original_stderr
        else:
            sys.stderr = sys.__stderr__
    except Exception:
        pass

    # Close logfile
    try:
        if _log_fh is not None:
            try:
                _log_fh.write(f"\n[conftest] log closed: {_logfile_path}\n")
                _fsync_file(_log_fh)
            except Exception:
                pass
            try:
                _log_fh.close()
            except Exception:
                pass
            _log_fh = None
    except Exception:
        pass

    # final note on terminal
    try:
        print(f"[conftest] CLI log saved to: {_logfile_path}", file=sys.__stdout__)
    except Exception:
        pass
