import pytest
from unittest.mock import MagicMock, patch
from modules.fidesModule.messaging.network_bridge import NetworkBridge
from modules.fidesModule.messaging.queue import Queue
from modules.fidesModule.messaging.message_handler import MessageHandler
from modules.fidesModule.messaging.network_bridge import NetworkMessage
from modules.fidesModule.model.aliases import PeerId, Target
from modules.fidesModule.model.threat_intelligence import ThreatIntelligence

@pytest.fixture
def mock_queue():
    return MagicMock(spec=Queue)

@pytest.fixture
def network_bridge(mock_queue):
    return NetworkBridge(queue=mock_queue)

@pytest.fixture
def mock_handler():
    return MagicMock(spec=MessageHandler)

def test_initialization(network_bridge, mock_queue):
    assert network_bridge._NetworkBridge__queue == mock_queue
    assert network_bridge.version == 1

def test_listen_success(network_bridge, mock_handler, mock_queue):
    mock_queue.listen = MagicMock()
    mock_handler.on_message = MagicMock()

    network_bridge.listen(mock_handler)

    mock_queue.listen.assert_called_once()
    # Simulate a valid message being received
    message = '{"type": "test", "version": 1, "data": {}}'
    callback = mock_queue.listen.call_args[0][0]
    callback(message)

    mock_handler.on_message.assert_called_once()

def test_listen_failure(network_bridge, mock_handler, mock_queue):
    mock_queue.listen = MagicMock()
    mock_handler.on_error = MagicMock()

    network_bridge.listen(mock_handler)

    # Simulate an invalid message being received
    message = "invalid json"
    callback = mock_queue.listen.call_args[0][0]
    callback(message)

    mock_handler.on_error.assert_called_once()

def test_send_intelligence_response(network_bridge, mock_queue):
    mock_queue.send = MagicMock()
    target = Target("test_target")
    intelligence = ThreatIntelligence(score=85, confidence=0.9)
    network_bridge.send_intelligence_response("req_123", target, intelligence)

    mock_queue.send.assert_called_once()
    sent_message = mock_queue.send.call_args[0][0]
    assert "tl2nl_intelligence_response" in sent_message

def test_send_recommendation_request(network_bridge, mock_queue):
    mock_queue.send = MagicMock()
    recipients = [PeerId("peer1"), PeerId("peer2")]
    peer = PeerId("test_peer")
    network_bridge.send_recommendation_request(recipients, peer)

    mock_queue.send.assert_called_once()
    sent_message = mock_queue.send.call_args[0][0]
    assert "tl2nl_recommendation_request" in sent_message

def test_send_exception_handling(network_bridge, mock_queue):
    mock_queue.send = MagicMock(side_effect=Exception("send failed"))
    with pytest.raises(Exception, match="send failed"):
        network_bridge._NetworkBridge__send(NetworkMessage(type="test", version=1, data={}))

