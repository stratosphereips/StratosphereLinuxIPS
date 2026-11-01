"""Zeek SMB-related records retaining distinct events on the same connection."""

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any

from slips_files.core.flows.base_flow import BaseFlow


@dataclass(kw_only=True)
class SMBRecord(BaseFlow):
    """Common SMB, authentication and RPC metadata; no payload content."""

    starttime: Any = ""
    uid: str = ""
    saddr: str = ""
    daddr: str = ""
    sport: int | str = ""
    dport: int | str = ""
    path: str = ""
    service: str = ""
    share_type: str = ""
    action: str = ""
    name: str = ""
    prev_name: str = ""
    size: int | str = 0
    fuid: str = ""
    file_id: str = ""
    command: str = ""
    sub_command: str = ""
    status: str = ""
    version: str = ""
    username: str = ""
    domainname: str = ""
    success: bool | str = ""
    endpoint: str = ""
    operation: str = ""
    named_pipe: str = ""
    rtt: float | str = ""
    event_ts: float | str = ""
    write_seen: bool | str = ""
    read_seen: bool | str = ""
    record_id: str = ""
    type_: str = ""

    def __post_init__(self) -> None:
        """Create a stable event ID without replacing the connection UID."""
        if self.event_ts not in ("", "-", None):
            self.starttime = float(self.event_ts)
        if not self.record_id:
            raw = json.dumps(asdict(self), sort_keys=True, default=str)
            self.record_id = f"{self.uid}:smb:{hashlib.sha256(raw.encode()).hexdigest()[:32]}"


@dataclass(kw_only=True)
class SMBMapping(SMBRecord):
    """A server's recorded share mapping."""

    type_: str = "smb_mapping"


@dataclass(kw_only=True)
class SMBFile(SMBRecord):
    """A file action recorded by Zeek."""

    type_: str = "smb_files"


@dataclass(kw_only=True)
class SMBCommand(SMBRecord):
    """An SMB command and its recorded reply status."""

    type_: str = "smb_cmd"


@dataclass(kw_only=True)
class NTLM(SMBRecord):
    """An authentication record with an optional, explicit result."""

    type_: str = "ntlm"


@dataclass(kw_only=True)
class DCERPC(SMBRecord):
    """A remote procedure call; an operation alone does not prove success."""

    type_: str = "dce_rpc"
