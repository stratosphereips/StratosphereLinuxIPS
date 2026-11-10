"""Batched ML inference retains labels, protocol filtering and evidence attribution."""

import json
from unittest.mock import Mock, call

import numpy
import pytest

from modules.ml_linear_model.ml_linear_model import MLLinearModel
from modules.ml_online_model.ml_online_model import MLOnlineModel
from slips_files.common.abstracts.ml_module_base import BENIGN, MALICIOUS
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize("backend", [MLLinearModel, MLOnlineModel])
def test_batch_predictions_keep_filtered_flow_and_window_alignment(backend: type) -> None:
    """Attribute predictions to original records after an unsupported protocol is removed.

    Parameters:
        backend: Real feature processor for either enabled ML detector.
    """
    _factory = ModuleFactory()
    module = backend.__new__(backend)
    module.print = Mock()
    module.ground_truth_config_label = BENIGN
    module.detect = Mock(return_value=numpy.asarray([MALICIOUS, BENIGN, MALICIOUS]))
    module.set_evidence_malicious_flow = Mock()
    module.store_testing_results = Mock()
    records = [({"uid": str(n), "proto": proto, "state": "Not Established",
                 "sport": 50000, "dport": 22, "ground_truth_label": BENIGN},
                f"timewindow{n}", f"profile_{n}")
               for n, proto in enumerate(("tcp", "icmp", "udp", "tcp"))]
    module._test_flow_batch(records)
    assert module.detect.call_count == 1
    assert len(module.detect.call_args.args[0]) == 3
    assert module.set_evidence_malicious_flow.call_args_list == [
        call(records[0][0], "timewindow0"), call(records[3][0], "timewindow3")]
    assert module.store_testing_results.call_args_list == [
        call(BENIGN, MALICIOUS), call(BENIGN, BENIGN), call(BENIGN, MALICIOUS)]


@pytest.mark.parametrize("count", [1, 32, 35])
def test_inference_drains_ready_messages_without_waiting(count: int) -> None:
    """Bound each pass while promptly handling sparse traffic and excluded messages.

    Parameters:
        count: Available input messages before the queue becomes empty.
    """
    _factory = ModuleFactory()
    module = MLLinearModel.__new__(MLLinearModel)
    module.mode = "test"
    module.ground_truth_config_label = BENIGN
    module.db = Mock()
    module.db.is_p2p_related_flow.side_effect = lambda src, *args: src == "own-peer"
    module._test_flow_batch = Mock()
    messages = [{"data": json.dumps({"twid": "timewindow1", "profileid": f"profile_{n}",
        "interpreted_state": "Not Established", "label": "benign", "module_labels": {},
        "flow": {"uid": str(n), "saddr": "own-peer" if n == 2 else "192.0.2.1",
                 "ground_truth_label": "Background" if n == 3 else BENIGN}})} for n in range(count)]
    module.get_msg = Mock(side_effect=[*messages, None])
    module.main()
    assert module.get_msg.call_count == min(count+1, 32)
    rows = module._test_flow_batch.call_args.args[0]
    assert [row[0]["uid"] for row in rows] == [str(n) for n in range(min(count, 32)) if n not in (2, 3)]
    if count > 32:
        module.main()
        assert [row[0]["uid"] for row in module._test_flow_batch.call_args.args[0]] == ["32", "33", "34"]
