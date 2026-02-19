# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

from slips_files.core.input.binetflow.binetflow_input import BinetflowInput


class BinetflowTabsInput(BinetflowInput):
    def shutdown_gracefully(self):
        return super().shutdown_gracefully()
