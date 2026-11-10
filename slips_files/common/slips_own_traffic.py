# SPDX-License-Identifier: GPL-2.0-only
"""Mark network connections opened by Slips modules for live capture filtering."""

import ipaddress
import socket
from typing import Any


_ORIGINAL_SOCKET = socket.socket
_PENDING_LIMIT = 256


class SlipsTrafficTracker:
    """Record exact socket tuples without changing the caller's network API."""

    def __init__(self) -> None:
        """Start with a bounded queue for connections opened during module init."""
        self.db: Any = None
        self.pending: set[tuple[str, str, int, str, int]] = set()
        self.warned = False

    def install(self) -> None:
        """Track sockets created in this Slips module process."""
        TrackedSocket.tracker = self
        socket.socket = TrackedSocket

    def attach(self, db: Any) -> None:
        """Flush constructor-time connections to the module's run database.

        Parameters:
            db: Database manager owned by this module process.
        """
        self.db = db
        for connection in self.pending:
            self._save(connection)
        self.pending.clear()

    def stop(self) -> None:
        """Restore the process socket constructor after its module stops."""
        if socket.socket is TrackedSocket:
            socket.socket = _ORIGINAL_SOCKET
        TrackedSocket.tracker = None

    def _save(self, connection: tuple[str, str, int, str, int]) -> None:
        """Store an exact tuple with a TTL, or queue it until DB setup.

        Parameters:
            connection: Protocol, local IP and port, remote IP and port.
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
        """Normalize an IP literal, omitting any IPv6 interface suffix.

        Parameters:
            value: Socket endpoint address.

        Returns:
            Canonical IP literal, or an empty string for other values.
        """
        try:
            return str(ipaddress.ip_address(str(value).split("%", 1)[0]))
        except ValueError:
            return ""

    def _connection(
        self, sock: socket.socket, address: Any
    ) -> tuple[str, str, int, str, int] | None:
        """Read a connected TCP or sent UDP socket's exact flow tuple.

        Parameters:
            sock: Socket that performed the network operation.
            address: Destination supplied to connect or sendto.

        Returns:
            Normalized tuple, or None for loopback and non-IP sockets.
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
        """Persist a socket tuple once after it gets a local port.

        Parameters:
            sock: Socket that made the request.
            address: Destination supplied to connect or sendto.
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
        """Keep a completed long-lived connection visible to the profiler.

        Parameters:
            sock: Socket about to close.
        """
        for connection in getattr(sock, "_slips_recorded", ()):
            self._save(connection)


class TrackedSocket(_ORIGINAL_SOCKET):
    """Socket variant that reports successful Slips-originated IP traffic."""

    tracker: SlipsTrafficTracker | None = None

    def connect(self, address: Any) -> None:
        """Record a TCP or connected UDP endpoint after connecting.

        Parameters:
            address: Destination socket address.
        """
        try:
            super().connect(address)
        finally:
            if self.tracker is not None:
                self.tracker.record(self, address)

    def connect_ex(self, address: Any) -> int:
        """Record a successful non-raising connection attempt.

        Parameters:
            address: Destination socket address.

        Returns:
            Socket error number, zero on success.
        """
        result = super().connect_ex(address)
        if self.tracker is not None:
            self.tracker.record(self, address)
        return result

    def sendto(self, data: bytes, *args: Any) -> int:
        """Record a datagram's tuple after the system assigns its port.

        Parameters:
            data: Datagram payload.
            args: Optional flags and destination address.

        Returns:
            Number of payload bytes sent.
        """
        result = super().sendto(data, *args)
        if self.tracker is not None and args:
            self.tracker.record(self, args[-1])
        return result

    def close(self) -> None:
        """Refresh a tracked tuple before the socket closes."""
        if self.tracker is not None:
            self.tracker.renew(self)
        super().close()
