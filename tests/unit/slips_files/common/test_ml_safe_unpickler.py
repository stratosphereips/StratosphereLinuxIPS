# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
"""Tests for the restricted unpickler used to load ML artifacts safely."""
import builtins
import io
import pickle

import numpy
import pytest

from slips_files.common.ml_safe_unpickler import (
    safe_pickle_load,
    safe_pickle_loads,
)


def test_safe_pickle_loads_allows_allowlisted_module():
    data = pickle.dumps(numpy.array([1, 2, 3]))

    result = safe_pickle_loads(data)

    assert list(result) == [1, 2, 3]


def test_safe_pickle_loads_allows_safe_builtin():
    data = pickle.dumps({"a", "b"})

    result = safe_pickle_loads(data)

    assert result == {"a", "b"}


def test_safe_pickle_load_allows_allowlisted_module():
    data = pickle.dumps(numpy.array([1, 2, 3]))

    result = safe_pickle_load(io.BytesIO(data))

    assert list(result) == [1, 2, 3]


def test_safe_pickle_loads_blocks_unsafe_builtin():
    data = pickle.dumps(eval)

    with pytest.raises(pickle.UnpicklingError):
        safe_pickle_loads(data)


def test_safe_pickle_loads_blocks_unlisted_module():
    data = pickle.dumps(builtins.print)

    with pytest.raises(pickle.UnpicklingError):
        safe_pickle_loads(data)


def test_safe_pickle_loads_blocks_os_system(monkeypatch):
    """
    the canonical pickle RCE payload: a reduce tuple that calls
    os.system on load. must be rejected before it ever runs.
    """
    import os

    class Exploit:
        def __reduce__(self):
            return (os.system, ("echo pwned",))

    data = pickle.dumps(Exploit())

    with pytest.raises(pickle.UnpicklingError):
        safe_pickle_loads(data)
