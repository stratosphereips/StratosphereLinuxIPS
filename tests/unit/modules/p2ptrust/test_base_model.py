# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
import pytest
from unittest.mock import Mock
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "ipaddr, reports, expected_score, expected_confidence",
    [  # testcase1:  get opinion with one report
        ("192.168.1.1", [(0.8, 0.9, 0.7, 0.8, 0.9)], 0.8, 0.9),
        # testcase2: get opinion with multiple reports
        (
            "172.16.0.1",
            [(0.6, 0.7, 0.8, 0.7, 0.8), (0.7, 0.8, 0.9, 0.8, 0.9)],
            0.65,
            0.75,
        ),
    ],
)
def test_get_opinion_on_ip_with_reports(
    ipaddr, reports, expected_score, expected_confidence
):
    base_model = ModuleFactory().create_base_model_obj()
    base_model.trustdb.get_opinion_on_ip.return_value = reports
    base_model.assemble_peer_opinion = Mock(
        return_value=(expected_score, expected_confidence)
    )

    score, confidence = base_model.get_opinion_on_ip(ipaddr)

    base_model.trustdb.get_opinion_on_ip.assert_called_once_with(ipaddr)
    base_model.assemble_peer_opinion.assert_called_once_with(reports)
    base_model.trustdb.update_cached_network_opinion.assert_called_once_with(
        "ip", ipaddr, expected_score, expected_confidence, 0
    )
    assert score == expected_score
    assert confidence == expected_confidence


def test_get_opinion_on_ip_no_reports():
    base_model = ModuleFactory().create_base_model_obj()
    base_model.trustdb.get_opinion_on_ip.return_value = []

    base_model.assemble_peer_opinion = Mock()
    base_model.trustdb.update_cached_network_opinion = Mock()

    ipaddr = "10.0.0.1"
    score, confidence = base_model.get_opinion_on_ip(ipaddr)

    base_model.trustdb.get_opinion_on_ip.assert_called_once_with(ipaddr)
    base_model.assemble_peer_opinion.assert_not_called()
    base_model.trustdb.update_cached_network_opinion.assert_not_called()
    assert score is None
    assert confidence is None


@pytest.mark.parametrize(
    "reliability, score, confidence, expected_trust",
    [
        # testcase1: compute peer trust with normal values
        (0.8, 0.9, 0.7, 0.595),
        # testcase2: compute peer trust with mid-range values
        (0.5, 0.6, 0.8, 0.415),
        # testcase3: compute peer trust with maximum values
        (1.0, 1.0, 1.0, 0.85),
        # testcase4: compute peer trust with minimum values
        (0.0, 0.0, 0.0, 0.0),
    ],
)
def test_compute_peer_trust(reliability, score, confidence, expected_trust):
    base_model = ModuleFactory().create_base_model_obj()
    result = base_model.compute_peer_trust(reliability, score, confidence)
    assert pytest.approx(result, 0.001) == expected_trust


@pytest.mark.parametrize(
    "data, expected_score, expected_confidence",
    [
        # testcase1: assemble opinion with one report
        ([(0.8, 0.9, 0.7, 0.8, 0.9)], 0.8, 0.5445),
        # testcase2: assemble opinion with multiple reports
        (
            [(0.6, 0.7, 0.8, 0.7, 0.8), (0.7, 0.8, 0.9, 0.8, 0.9)],
            0.6517774343122101,
            0.46599999999999997,
        ),
        # testcase3: assemble opinion with diverse reports
        (
            [
                (0.9, 0.8, 0.6, 0.7, 0.8),
                (0.5, 0.6, 0.9, 0.8, 0.7),
                (0.3, 0.4, 0.7, 0.6, 0.5),
            ],
            0.5707589285714285,
            0.30233333333333334,
        ),
    ],
)
def test_assemble_peer_opinion(data, expected_score, expected_confidence):
    base_model = ModuleFactory().create_base_model_obj()

    score, confidence = base_model.assemble_peer_opinion(data)

    assert pytest.approx(score, 0.0001) == expected_score
    assert pytest.approx(confidence, 0.0001) == expected_confidence


@pytest.mark.parametrize(
    "peers, expected_weighted_trust",
    [
        # testcase1: normalize single peer reputation
        ([0.5], [1.0]),
        # testcase2: normalize multiple peer reputations
        (
            [0.7, 0.3, -0.2],
            [0.4473684210526316, 0.34210526315789475, 0.2105263157894737],
        ),
        # testcase3: normalize peer reputations including extremes
        ([1.0, 0.0, -1.0], [0.6666666666666666, 0.3333333333333333, 0.0]),
        # testcase4: normalize peer reputations with all negative values
        (
            [-0.2, -0.5, -0.8],
            [0.5333333333333333, 0.3333333333333333, 0.1333333333333333],
        ),
    ],
)
def test_normalize_peer_reputations(peers, expected_weighted_trust):
    base_model = ModuleFactory().create_base_model_obj()

    weighted_trust = base_model.normalize_peer_reputations(peers)

    assert len(weighted_trust) == len(expected_weighted_trust)
    for calculated, expected in zip(weighted_trust, expected_weighted_trust):
        assert pytest.approx(calculated, 0.0001) == expected

    assert pytest.approx(sum(weighted_trust), 0.0001) == 1.0
