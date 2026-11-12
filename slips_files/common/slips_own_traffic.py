# SPDX-License-Identifier: GPL-2.0-only
"""Let Slips recognise its own network traffic in a live capture.

Slips sniffs the interface its own modules (TI feeds, Redis, P2P, etc.) talk
over, so without this it would profile and alert on itself. Each module
process swaps in `TrackedSocket`, which reports the exact 5-tuple of every
connection to Redis so the profiler can skip those flows.
"""

import ipaddress
import socket
from typing import Any


_ORIGINAL_SOCKET = socket.socket
_PENDING_LIMIT = 256


class SlipsTrafficTracker:
    """Collect the 5-tuples of this process's sockets and save them to Redis.

    Hooks `socket.socket` instead of patching callers, so third-party libraries
    (requests, redis-py, ...) are covered without code changes. One tracker lives
    per module process, because sockets and patches don't cross processes.
    """

    def __init__(self) -> None:
        """Prepare a buffer, since sockets open before the module has a DB handle."""
        self.db: Any = None
        self.pending: set[tuple[str, str, int, str, int]] = set()
        self.warned = False

    def install(self) -> None:
        """Replace `socket.socket` so every socket made from now on is tracked."""
        TrackedSocket.tracker = self
        socket.socket = TrackedSocket

    def attach(self, db: Any) -> None:
        """Give the tracker its DB and save connections buffered before it existed.

        Parameters:
            db: This process's database manager (needed to reach Redis).
        """
        self.db = db
        for connection in self.pending:
            self._save(connection)
        self.pending.clear()

    def stop(self) -> None:
        """Undo `install` so sockets made during shutdown/teardown aren't tracked."""
        if socket.socket is TrackedSocket:
            socket.socket = _ORIGINAL_SOCKET
        TrackedSocket.tracker = None

    def _save(self, connection: tuple[str, str, int, str, int]) -> None:
        """Write a tuple to Redis, or buffer it if the DB isn't attached yet.

        The buffer is capped so a module that never attaches can't leak memory.
        Redis errors must never break the module's real network call, so only
        the first failure is reported, to avoid flooding the logs.

        Parameters:
            connection: (protocol, local IP, local port, remote IP, remote port).
        """
        if self.db is None:
            if len(self.pending) < _PENDING_LIMIT:
                self.pending.add(connection)
            return
        try:
            self.db.record_slips_own_connection(self.db.main_pid, *connection)
        except Exception as exc:
            if not self.warned:
                self.warned = True
                self.db.print(
                    f"Unable to mark Slips' own network traffic: {exc}",
                    0,
                    1,
                )

    @staticmethod
    def _normalized_ip(value: Any) -> str:
        """Return a canonical IP string so it matches the profiler's flow IPs.

        The IPv6 zone suffix (`fe80::1%eth0`) is dropped because capture
        files never contain it, and `::ffff:`-style or zero-padded forms are
        unified so lookups compare equal.

        Parameters:
            value: Address part of a socket endpoint.

        Returns:
            Canonical IP, or "" if the value isn't an IP (e.g. a hostname).
        """
        try:
            return str(ipaddress.ip_address(str(value).split("%", 1)[0]))
        except ValueError:
            return ""

    def _connection(
        self, sock: socket.socket, address: Any
    ) -> tuple[str, str, int, str, int] | None:
        """Build the flow 5-tuple the profiler will see on the wire.

        Needs the local port, which the OS only picks at connect/send time,
        so this runs after that call. TCP asks the socket for its peer
        (`address` may be a hostname); UDP has no peer, so `address` is used.
        A wildcard local IP (0.0.0.0/::) would never match a captured flow,
        so a throwaway UDP connect asks the OS which interface IP routes there.

        Parameters:
            sock: Socket that just connected or sent.
            address: Destination passed to connect/sendto.

        Returns:
            The tuple, or None when it can't appear in a capture: non-IP or
            non-TCP/UDP sockets, loopback, or unresolvable endpoints.
        """
        if sock.family not in (socket.AF_INET, socket.AF_INET6):
            return None
        kind = sock.type & 0xF
        proto = (
            "tcp"
            if kind == socket.SOCK_STREAM
            else "udp" if kind == socket.SOCK_DGRAM else ""
        )
        if not proto:
            return None
        try:
            if proto == "tcp":
                try:
                    remote = sock.getpeername()
                except OSError:
                    remote = address
            else:
                remote = address
            local = sock.getsockname()
            remote_ip = self._normalized_ip(remote[0])
            local_ip = self._normalized_ip(local[0])
            remote_port = int(remote[1])
            local_port = int(local[1])
        except (IndexError, OSError, TypeError, ValueError):
            return None
        if not remote_ip or not local_port or not 0 < remote_port <= 65535:
            return None
        if ipaddress.ip_address(remote_ip).is_loopback:
            return None
        if local_ip in ("0.0.0.0", "::"):
            try:
                with _ORIGINAL_SOCKET(sock.family, socket.SOCK_DGRAM) as probe:
                    probe.connect(address)
                    local_ip = self._normalized_ip(probe.getsockname()[0])
            except (OSError, TypeError, ValueError):
                return None
        if not local_ip:
            return None
        return proto, local_ip, local_port, remote_ip, remote_port

    def record(self, sock: socket.socket, address: Any) -> None:
        """Save a socket's tuple, skipping repeats.

        A UDP socket calls sendto thousands of times; remembering what each
        socket already saved (on the socket itself, so it dies with it)
        avoids a Redis write per packet. A new destination is a new tuple.

        Parameters:
            sock: Socket that just connected or sent.
            address: Destination passed to connect/sendto.
        """
        connection = self._connection(sock, address)
        if connection is None:
            return
        recorded = getattr(sock, "_slips_recorded", None)
        if recorded is None:
            recorded = set()
            sock._slips_recorded = recorded
        if connection not in recorded:
            recorded.add(connection)
            self._save(connection)

    def renew(self, sock: socket.socket) -> None:
        """Re-save a socket's tuples on close to restart their Redis TTL.

        Saved tuples expire, but a long connection's flow is only finalised
        by the capture after it ends. Refreshing at close keeps the entry
        alive long enough for the profiler to still match it.

        Parameters:
            sock: Socket about to close.
        """
        for connection in getattr(sock, "_slips_recorded", ()):
            self._save(connection)


class TrackedSocket(_ORIGINAL_SOCKET):
    """Drop-in `socket.socket` that reports each connection it makes.

    The tracker is a class attribute because `install` swaps the class
    itself, so instances can't be given one at construction.
    """

    tracker: SlipsTrafficTracker | None = None

    def connect(self, address: Any) -> None:
        """Connect, then record, even on failure.

        `finally` is deliberate: a non-blocking connect raises while the
        handshake is still in flight, yet the packets (and local port)
        already exist and would otherwise look like foreign traffic.

        Parameters:
            address: Destination socket address.
        """
        try:
            super().connect(address)
        finally:
            if self.tracker is not None:
                self.tracker.record(self, address)

    def connect_ex(self, address: Any) -> int:
        """Like `connect`, but errors come back as a code instead of raising.

        Recorded unconditionally for the same reason as `connect`: an
        in-progress attempt (EINPROGRESS) has already sent its SYN.

        Parameters:
            address: Destination socket address.

        Returns:
            0 on success, otherwise the errno.
        """
        result = super().connect_ex(address)
        if self.tracker is not None:
            self.tracker.record(self, address)
        return result

    def sendto(self, data: bytes, *args: Any) -> int:
        """Send a datagram, then record it (UDP never calls connect).

        The OS assigns the local port only on first send, so recording must
        come after. The destination is always the last positional argument,
        whether or not flags were passed.

        Parameters:
            data: Datagram payload.
            args: `(address)` or `(flags, address)`.

        Returns:
            Number of bytes sent.
        """
        result = super().sendto(data, *args)
        if self.tracker is not None and args:
            self.tracker.record(self, args[-1])
        return result

    def close(self) -> None:
        """Refresh the TTL of this socket's tuples, then close (see `renew`)."""
        if self.tracker is not None:
            self.tracker.renew(self)
        super().close()
