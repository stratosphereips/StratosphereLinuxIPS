# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only


class IInputHandler:
    def __init__(self, input_process):
        self.input = input_process

    def run(self):
        raise NotImplementedError

    def shutdown_gracefully(self):
        raise NotImplementedError
