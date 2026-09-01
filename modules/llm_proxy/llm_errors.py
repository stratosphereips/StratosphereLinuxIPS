# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Exceptions raised by the shared LLM module."""


class LLMConfigurationError(Exception):
    """Raised when an LLM backend configuration is invalid."""


class LLMRequestError(Exception):
    """Raised when an LLM request cannot be prepared or completed."""
