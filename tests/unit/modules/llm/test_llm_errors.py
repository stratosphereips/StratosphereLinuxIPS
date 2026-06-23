# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only

import pytest

from modules.llm.llm_errors import LLMConfigurationError, LLMRequestError
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "error_cls",
    [
        LLMConfigurationError,
        LLMRequestError,
    ],
)
def test_llm_errors_are_exceptions(error_cls: type[Exception]) -> None:
    llm = ModuleFactory().create_llm_obj()

    error = error_cls("failed")

    assert llm.name == "LLM"
    assert isinstance(error, Exception)
