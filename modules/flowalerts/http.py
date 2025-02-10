# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

from slips_files.common.abstracts.flowalerts_analyzer import (
    IFlowalertsAnalyzer,
)
from slips_files.common.slips_utils import utils


class HTTP(IFlowalertsAnalyzer):
    def name(self) -> str:
        return "http_analyzer"

    def init(self): ...

    def analyze(self, msg):
        if utils.is_msg_intended_for(msg, "new_flow"):
            ...
