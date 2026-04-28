# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import importlib.util
import pytest
from tests.common_test_utils import allocate_integration_test_port


if importlib.util.find_spec("termcolor") is None:
    pytest.skip(
        "termcolor is required to run integration tests that invoke slips",
        allow_module_level=True,
    )


@pytest.fixture
def integration_port_factory(request):
    """
    Allocate free ports for an integration test from the shared high-port range.

    :param request: Pytest request object for the current test
    :return: Callable that allocates and prints a labelled port
    """

    def allocate(port_label: str = "service") -> int:
        """
        Allocate a free test port and print it for the current test.

        :param port_label: Label describing the allocated port
        :return: Allocated TCP port
        """
        return allocate_integration_test_port(request.node.nodeid, port_label)

    return allocate
