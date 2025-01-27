# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import pytest
from datetime import timedelta
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "now_ts, last_ts, last_last_ts, tto, tt1, tt2, tt3, expected_result",
    [
        # testcase1: Strongly periodic
        (
            3000.0,
            2000.0,
            1000.0,
            timedelta(seconds=3600),
            1.05,
            1.3,
            5.0,
            (1, "", 1000.0),
        ),
        # testcase2: Weakly periodic
        (
            3000.0,
            2000.0,
            1000.0,
            timedelta(seconds=3600),
            1.0,
            1.5,
            5.0,
            (1, "", 1000.0),
        ),
        # testcase3: Weakly not periodic
        (
            4000.0,
            2000.0,
            1000.0,
            timedelta(seconds=3600),
            1.0,
            1.3,
            5.0,
            (3, "", 2000.0),
        ),
        # testcase4: Strongly not periodic
        (
            6000.0,
            2000.0,
            1000.0,
            timedelta(seconds=3600),
            1.0,
            1.3,
            4.0,
            (3, "0", 4000.0),
        ),
        # testcase5: With timeout and zeros
        (
            7000.0,
            2000.0,
            1000.0,
            timedelta(seconds=3600),
            1.0,
            1.3,
            5.0,
            (3, "0", 5000.0),
        ),
    ],
)
def test_compute_periodicity(
    now_ts, last_ts, last_last_ts, tto, tt1, tt2, tt3, expected_result
):
    symbol_handler = ModuleFactory().create_symbol_handler_obj()

    profileid = "test_profile"
    tupleid = "test_tuple"

    result = symbol_handler.compute_periodicity(
        now_ts, last_ts, last_last_ts, tto, tt1, tt2, tt3, profileid, tupleid
    )

    assert result[:3] == expected_result


@pytest.mark.parametrize(
    "current_duration, td1, td2, expected_result",
    [
        # testcase1: Short duration
        (0.05, 0.1, 10.0, 1),
        # testcase2: Medium duration
        (5.0, 0.1, 10.0, 2),
        # testcase3: Long duration
        (15.0, 0.1, 10.0, 3),
    ],
)
def test_compute_duration(current_duration, td1, td2, expected_result):
    symbol_handler = ModuleFactory().create_symbol_handler_obj()
    result = symbol_handler.compute_duration(current_duration, td1, td2)
    assert result == expected_result


@pytest.mark.parametrize(
    "current_size, ts1, ts2, expected_result",
    [
        # testcase1: Small size
        (100, 250.0, 1100.0, 1),
        # testcase2: Medium size
        (500, 250.0, 1100.0, 2),
        # testcase3: Large size
        (1500, 250.0, 1100.0, 3),
    ],
)
def test_compute_size(current_size, ts1, ts2, expected_result):
    symbol_handler = ModuleFactory().create_symbol_handler_obj()
    result = symbol_handler.compute_size(current_size, ts1, ts2)
    assert result == expected_result


@pytest.mark.parametrize(
    "periodicity, size, duration, expected_result",
    [
        # testcase1: No periodicity, small size, short duration
        (-1, 1, 1, "1"),
        # testcase2: Strong periodicity, medium size,
        # medium duration
        (1, 2, 2, "e"),
        # testcase3: Weak periodicity,
        # large size, long duration
        (2, 3, 3, "I"),
        # testcase4: Weakly not periodic,
        # small size, short duration
        (3, 1, 1, "r"),
        # testcase5: Strongly not periodic,
        # large size, long duration
        (4, 3, 3, "Z"),
    ],
)
def test_compute_letter(periodicity, size, duration, expected_result):
    symbol_handler = ModuleFactory().create_symbol_handler_obj()
    result = symbol_handler.compute_letter(periodicity, size, duration)
    assert result == expected_result


@pytest.mark.parametrize(
    "T2, expected_result",
    [
        # testcase1: Very short time difference
        (3, "."),
        # testcase2: Short time difference
        (30, ","),
        # testcase3: Medium time difference
        (200, "+"),
        # testcase4: Long time difference
        (2000, "*"),
        # testcase5: Very long time difference
        (5000, ""),
    ],
)
def test_compute_timechar(T2, expected_result):
    symbol_handler = ModuleFactory().create_symbol_handler_obj()
    result = symbol_handler.compute_timechar(T2)
    assert result == expected_result


@pytest.mark.parametrize(
    "flow_data, twid, tuple_key, expected_symbol",
    [
        # testcase1: Normal flow
        (
            {
                "saddr": "192.168.1.1",
                "daddr": "10.0.0.1",
                "dport": 80,
                "proto": 6,
                "starttime": 3000.0,
                "dur": 0.05,
                "bytes": 100,
            },
            "1000",
            "InTuples",
            "a*",
        ),
        # testcase2: Flow with timeout
        (
            {
                "saddr": "192.168.1.1",
                "daddr": "10.0.0.1",
                "dport": 80,
                "proto": 6,
                "starttime": 7000.0,
                "dur": 5.0,
                "bytes": 500,
            },
            "1000",
            "OutTuples",
            "0v",
        ),
        # testcase3: Flow with large size and duration
        (
            {
                "saddr": "192.168.1.1",
                "daddr": "10.0.0.1",
                "dport": 80,
                "proto": 6,
                "starttime": 4000.0,
                "dur": 15.0,
                "bytes": 1500,
            },
            "1000",
            "InTuples",
            "z*",
        ),
    ],
)
def test_compute(mocker, flow_data, twid, tuple_key, expected_symbol):
    mock_flow = mocker.Mock(**flow_data)
    symbol_handler = ModuleFactory().create_symbol_handler_obj()
    result, _ = symbol_handler.compute(mock_flow, twid, tuple_key)
    assert result == expected_symbol
