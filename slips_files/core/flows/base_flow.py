# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from dataclasses import dataclass, field
from typing import List


@dataclass(kw_only=True)
class BaseFlow:
    """A base class for zeek flows, containing common fields."""

    interface: str = field(default="default")
    flow_tags: List[str] = field(default_factory=list)
