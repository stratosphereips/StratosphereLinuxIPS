# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import pytest
from unittest.mock import Mock, patch
import numpy as np
import json
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "pre_behavioral_model, expected_confidence",
    [
        # testcase1: Length greater than or equal to threshold
        ("a" * 100, 1),
        # testcase2: Length less than threshold
        ("a" * 50, 0.5),
        # testcase3: Empty string
        ("", 0),
    ],
)
def test_get_confidence(pre_behavioral_model, expected_confidence):
    cc_detection = ModuleFactory().create_rnn_detection_object()
    result = cc_detection.get_confidence(pre_behavioral_model)
    assert result == expected_confidence


@pytest.mark.parametrize(
    "msg_data, expected_profileid, expected_twid",
    [  # Test Case 1: Standard IPv4 profile and time window
        (
            "profile_192.168.1.1_timewindow1",
            "profile_192.168.1.1",
            "timewindow1",
        ),
        # Test Case 2: Different IPv4 profile and larger time window number
        ("profile_10.0.0.1_timewindow10", "profile_10.0.0.1", "timewindow10"),
        # Test Case 3: IPv6 profile with a high time window number
        ("profile_fe80::1_timewindow999", "profile_fe80::1", "timewindow999"),
    ],
)
def test_handle_tw_closed(msg_data, expected_profileid, expected_twid):
    cc_detection = ModuleFactory().create_rnn_detection_object()
    msg = {"data": msg_data}

    with patch.object(cc_detection.exporter, "export") as mock_export:
        cc_detection.handle_tw_closed(msg)

        mock_export.assert_called_once_with(expected_profileid, expected_twid)


@pytest.mark.parametrize(
    "score, confidence, uid, timestamp, tupleid, profileid, twid, expected_calls",
    [
        # testcase1: Basic test with all parameters
        (
            0.95,
            0.8,
            "uid123",
            "2023-01-01 12:00:00",
            "192.168.1.1-80-TCP",
            "profile_10.0.0.1",
            "timewindow1",
            2,
        ),
        # testcase2: Test with minimum required parameters
        (
            0.85,
            0.7,
            "uid456",
            "2023-01-02 13:00:00",
            "10.0.0.1-443-UDP",
            "profile_192.168.1.1",
            "timewindow2",
            2,
        ),
    ],
)
def test_set_evidence_cc_channel(
    score,
    confidence,
    uid,
    timestamp,
    tupleid,
    profileid,
    twid,
    expected_calls,
):
    cc_detection = ModuleFactory().create_rnn_detection_object()
    cc_detection.db.get_port_info.return_value = "HTTP"
    cc_detection.db.get_ip_identification.return_value = "Some IP info"

    with patch(
        "slips_files.common.slips_utils.utils.convert_format",
        return_value=timestamp,
    ):
        cc_detection.set_evidence_cc_channel(
            score, confidence, uid, timestamp, tupleid, profileid, twid
        )

    assert cc_detection.db.set_evidence.call_count == expected_calls


@pytest.mark.parametrize(
    "pre_behavioral_model, expected_first_values, expected_shape",
    [
        # testcase1: Short input
        (
            "88*y*y*h*h*h*h*h*h*h*y*y*h*h*h*y*y*",
            [43.0, 43.0, 49.0, 25.0, 49.0],
            (1, 500, 1),
        ),
        # testcase2: Long input (should be truncated)
        ("a" * 1000, [0.0] * 5, (1, 500, 1)),
        # testcase3: Empty input
        ("", [45.0] * 5, (1, 500, 1)),
    ],
)
def test_convert_input_for_module(
    pre_behavioral_model, expected_first_values, expected_shape
):
    cc_detection = ModuleFactory().create_rnn_detection_object()
    result = cc_detection.convert_input_for_module(pre_behavioral_model)

    assert isinstance(result, np.ndarray)
    assert result.shape == expected_shape
    np.testing.assert_array_almost_equal(
        result[0, :5, 0], expected_first_values
    )
    assert np.all((result >= 0) & (result <= 49))


@pytest.mark.parametrize(
    "side_effect, expected_c1, expected_c2, expected_channels",
    [
        # Testcase 1: Successful subscriptions
        (
            ["channel1", "channel2"],
            "channel1",
            "channel2",
            {"new_letters": "channel1", "tw_closed": "channel2"},
        ),
        # Testcase 2: One subscription fails (returns None)
        (
            ["channel1", None],
            "channel1",
            None,
            {"new_letters": "channel1", "tw_closed": None},
        ),
        # Testcase 3: Both subscriptions fail
        ([None, None], None, None, {"new_letters": None, "tw_closed": None}),
    ],
)
def test_subscribe_to_channels(
    side_effect, expected_c1, expected_c2, expected_channels
):
    cc_detection = ModuleFactory().create_rnn_detection_object()
    cc_detection.db.subscribe.side_effect = side_effect

    cc_detection.subscribe_to_channels()

    assert cc_detection.c1 == expected_c1
    assert cc_detection.c2 == expected_c2
    assert cc_detection.channels == expected_channels
    cc_detection.db.subscribe.assert_any_call("new_letters")
    cc_detection.db.subscribe.assert_any_call("tw_closed")


def test_handle_new_letters_valid_tcp_high_score():
    cc_detection = ModuleFactory().create_rnn_detection_object()

    cc_detection.tcpmodel = Mock()
    cc_detection.set_evidence_cc_channel = Mock()
    cc_detection.print = Mock()

    cc_detection.db.detect_data_type.return_value = "ip"

    msg_data = {
        "new_symbol": "abc",
        "profileid": "profile_192.168.1.1",
        "twid": "timewindow1",
        "tupleid": "10.0.0.1-80-TCP",
        "flow": {
            "state": "established",
            "starttime": "2023-01-01 12:00:00",
            "daddr": "10.0.0.1",
        },
        "uid": "uid123",
    }

    with patch.object(
        cc_detection,
        "convert_input_for_module",
        return_value=np.array([[[0]]]),
    ):
        # to exceed the 0.99 threshold in the function
        cc_detection.tcpmodel.predict.return_value = np.array([[0.995]])

        cc_detection.handle_new_letters({"data": json.dumps(msg_data)})

        cc_detection.convert_input_for_module.assert_called_once_with(
            msg_data["new_symbol"]
        )
        cc_detection.tcpmodel.predict.assert_called_once()
        cc_detection.print.assert_called()
        cc_detection.set_evidence_cc_channel.assert_called_once()

        cc_detection.db.publish.assert_called_once()
        call_args = cc_detection.db.publish.call_args
        assert call_args[0][0] == "check_jarm_hash"
        published_data = json.loads(call_args[0][1])
        assert published_data == {
            "attacker_type": "ip",
            "profileid": msg_data["profileid"],
            "twid": msg_data["twid"],
            "flow": msg_data["flow"],
        }


def test_handle_new_letters_valid_tcp_low_score():
    cc_detection = ModuleFactory().create_rnn_detection_object()

    cc_detection.tcpmodel = Mock()
    cc_detection.set_evidence_cc_channel = Mock()
    cc_detection.print = Mock()

    msg_data = {
        "new_symbol": "def",
        "profileid": "profile_192.168.1.2",
        "twid": "timewindow2",
        "tupleid": "10.0.0.2-443-TCP",
        "flow": {
            "state": "established",
            "starttime": "2023-01-02 12:00:00",
            "daddr": "10.0.0.2",
        },
        "uid": "uid456",
    }

    with patch.object(
        cc_detection,
        "convert_input_for_module",
        return_value=np.array([[[0]]]),
    ):
        # less than the 0.99 threshold in the function
        cc_detection.tcpmodel.predict.return_value = np.array([[0.5]])

        cc_detection.handle_new_letters({"data": json.dumps(msg_data)})

        cc_detection.convert_input_for_module.assert_called_once_with(
            msg_data["new_symbol"]
        )
        cc_detection.tcpmodel.predict.assert_called_once()
        cc_detection.print.assert_called()
        cc_detection.set_evidence_cc_channel.assert_not_called()
        cc_detection.db.publish.assert_not_called()


def test_handle_new_letters_udp():
    cc_detection = ModuleFactory().create_rnn_detection_object()

    cc_detection.tcpmodel = Mock()
    cc_detection.set_evidence_cc_channel = Mock()
    cc_detection.print = Mock()

    msg_data = {
        "new_symbol": "ghi",
        "profileid": "profile_192.168.1.3",
        "twid": "timewindow3",
        "tupleid": "10.0.0.3-53-UDP",
        "flow": {
            "state": "established",
            "starttime": "2023-01-03 12:00:00",
            "daddr": "10.0.0.3",
        },
        "uid": "uid789",
    }

    with patch.object(
        cc_detection, "convert_input_for_module"
    ) as mock_convert:
        cc_detection.handle_new_letters({"data": json.dumps(msg_data)})

        mock_convert.assert_not_called()
        cc_detection.tcpmodel.predict.assert_not_called()
        cc_detection.set_evidence_cc_channel.assert_not_called()
        cc_detection.db.publish.assert_not_called()


def test_handle_new_letters_tcp_not_established():
    cc_detection = ModuleFactory().create_rnn_detection_object()

    cc_detection.tcpmodel = Mock()
    cc_detection.set_evidence_cc_channel = Mock()
    cc_detection.print = Mock()

    msg_data = {
        "new_symbol": "jkl",
        "profileid": "profile_192.168.1.4",
        "twid": "timewindow4",
        "tupleid": "10.0.0.4-8080-TCP",
        "flow": {
            "state": "closed",
            "starttime": "2023-01-04 12:00:00",
            "daddr": "10.0.0.4",
        },
        "uid": "uid101112",
    }

    with patch.object(
        cc_detection, "convert_input_for_module"
    ) as mock_convert:
        cc_detection.handle_new_letters({"data": json.dumps(msg_data)})

        mock_convert.assert_not_called()
        cc_detection.tcpmodel.predict.assert_not_called()
        cc_detection.set_evidence_cc_channel.assert_not_called()
        cc_detection.db.publish.assert_not_called()
