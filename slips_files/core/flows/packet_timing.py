"""Connection-linked packet timing summaries without payload content."""

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any

from slips_files.core.flows.base_flow import BaseFlow


@dataclass(kw_only=True)
class PacketTiming(BaseFlow):
    """One bounded directional timing window emitted by Zeek."""

    starttime: Any = ""
    uid: str = ""
    saddr: str = ""
    daddr: str = ""
    sport: int | str = ""
    dport: int | str = ""
    proto: str = "tcp"
    is_orig: bool | str = True
    kind: str = "data"
    history: str = ""
    service: Any = ""
    times: Any = field(default_factory=list)
    lengths: Any = field(default_factory=list)
    event_count: int | str = 0
    orig_bytes: int | str = 0
    resp_bytes: int | str = 0
    record_id: str = ""
    type_: str = "packet_timing"

    def __post_init__(self) -> None:
        """Retain the parent UID while assigning each summary a stable identity."""
        if not self.record_id:
            encoded = json.dumps(asdict(self), sort_keys=True, default=str)
            self.record_id = f"{self.uid}:packet:{hashlib.sha256(encoded.encode()).hexdigest()[:32]}"
