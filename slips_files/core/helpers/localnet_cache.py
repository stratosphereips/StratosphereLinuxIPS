import json
import multiprocessing
from typing import Dict, Iterator, List, Tuple


class LocalnetCacheShared:
    """Small shared dict cache stored as JSON in shared memory."""

    def __init__(self, size: int = 8192) -> None:
        self.size = size
        self.buffer = multiprocessing.Array("c", size, lock=False)
        self.lock = multiprocessing.Lock()
        # ensure buffer is nul-terminated
        self.buffer[:] = b"\x00" * size

    def _read_bytes(self) -> bytes:
        if self.buffer is None:
            return b""
        raw = bytes(self.buffer[:])
        try:
            end = raw.index(0)
        except ValueError:
            end = len(raw)
        return raw[:end]

    def _get_cache(self) -> Dict[str, str]:
        if self.lock is None:
            return {}
        with self.lock:
            raw = self._read_bytes()
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            return {}

    def get(self, key=None, default=None):
        cache = self._get_cache()
        if key is None:
            return cache
        return cache.get(key, default)

    def contains(self, key: str) -> bool:
        return key in self._get_cache()

    def items(self) -> List[Tuple[str, str]]:
        return list(self._get_cache().items())

    def clear(self) -> bool:
        return self.set({})

    def update(self, updates: Dict[str, str]) -> bool:
        cache = self._get_cache()
        cache.update(updates)
        return self.set(cache)

    def set(self, new_cache: Dict[str, str]) -> bool:
        if self.buffer is None:
            return False
        payload = json.dumps(new_cache, separators=(",", ":")).encode("utf-8")
        if len(payload) >= self.size:
            # refuse to write partial data
            return False
        with self.lock:
            self.buffer[: len(payload)] = payload
            self.buffer[len(payload) :] = b"\x00" * (self.size - len(payload))
        return True

    def shutdown_gracefully(self) -> None:
        if self.buffer is None:
            return
        self.clear()
        self.buffer = None
        self.lock = None

    def __contains__(self, key: str) -> bool:
        return self.contains(key)

    def __getitem__(self, key: str) -> str:
        return self._get_cache()[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._get_cache())

    def __len__(self) -> int:
        return len(self._get_cache())

    def __eq__(self, other) -> bool:
        if isinstance(other, LocalnetCacheShared):
            return self._get_cache() == other._get_cache()
        return self._get_cache() == other
