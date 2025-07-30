from redis.asyncio.connection import Connection
import asyncio


class SafeConnection(Connection):
    """
    Custom Async Redis Connection, to override its disconnect()
    Async redis sometimes returns arbitrary data, happens once every few
    cmds, happens when connection is closed (timeout, cancelled tasks etc.)
    while data is still there in the conn's buffer.
    this disconnect() method will clear the buffer before closing the
    connection.
    """

    async def disconnect(self, nowait=False):
        # Drain any unread data before disconnecting
        if self._reader is not None:
            try:
                # Read and discard any remaining bytes
                while not self._reader.at_eof():
                    data = await asyncio.wait_for(
                        self._reader.read(1024), timeout=0.1
                    )
                    if not data:
                        break
            except asyncio.TimeoutError:
                pass
            except Exception:
                pass
        await super().disconnect(nowait=nowait)
