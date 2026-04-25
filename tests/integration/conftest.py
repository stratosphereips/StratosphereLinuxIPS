# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import importlib.util
import pytest


if importlib.util.find_spec("termcolor") is None:
    pytest.skip(
        "termcolor is required to run integration tests that invoke slips",
        allow_module_level=True,
    )
