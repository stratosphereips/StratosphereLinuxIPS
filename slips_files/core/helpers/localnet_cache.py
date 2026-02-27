import json
import multiprocessing
from typing import Dict, List, Tuple


class LocalnetCacheShared:
    """Small shared dict cache stored as JSON in shared memory."""

    def __init__(self, size: int = 8192) -> None:
        self.size = size
        self.buffer = multiprocessing.Array("c", size, lock=False)
        self.lock = multiprocessing.Lock()
        # ensure buffer is nul-terminated
        self.buffer[:] = b"\x00" * size

    def _read_bytes(self) -> bytes:
        raw = bytes(self.buffer[:])
        try:
            end = raw.index(0)
        except ValueError:
            end = len(raw)
        return raw[:end]

    def get(self) -> Dict[str, str]:
        with self.lock:
            raw = self._read_bytes()
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            return {}

    def contains(self, key: str) -> bool:
        return key in self.get()

    def items(self) -> List[Tuple[str, str]]:
        return list(self.get().items())

    def set(self, new_cache: Dict[str, str]) -> bool:
        payload = json.dumps(new_cache, separators=(",", ":")).encode("utf-8")
        if len(payload) >= self.size:
            # refuse to write partial data
            return False
        with self.lock:
            self.buffer[: len(payload)] = payload
            self.buffer[len(payload) :] = b"\x00" * (self.size - len(payload))
        return True
