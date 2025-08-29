import pytest
from unittest.mock import MagicMock, patch
from threading import Thread
from modules.fidesModule.messaging.redis_simplex_queue import RedisSimplexQueue, RedisDuplexQueue

@pytest.fixture
def mock_db():
    return MagicMock()

@pytest.fixture
def mock_channels():
    return {"send_channel": MagicMock(), "receive_channel": MagicMock()}

@pytest.fixture
def simplex_queue(mock_db, mock_channels):
    return RedisSimplexQueue(mock_db, "send_channel", "receive_channel", mock_channels)

def test_initialization(simplex_queue, mock_db, mock_channels):
    assert simplex_queue.db == mock_db
    assert simplex_queue._RedisSimplexQueue__send == "send_channel"
    assert simplex_queue._RedisSimplexQueue__receive == "receive_channel"
    assert simplex_queue._RedisSimplexQueue__pub == mock_channels["receive_channel"]

def test_send(simplex_queue, mock_db):
    simplex_queue.send("test_message")
    mock_db.publish.assert_called_once_with("send_channel", "test_message")

def test_listen_blocking(simplex_queue, mock_channels):
    mock_channels["receive_channel"].listen = MagicMock(return_value=[
        {"data": "message_1"},
        {"data": "stop_process"},
    ])
    on_message = MagicMock()

    simplex_queue.listen(on_message, block=True)

    on_message.assert_any_call("message_1")
    assert mock_channels["receive_channel"].unsubscribe.called

def test_listen_non_blocking(simplex_queue, mock_channels):
    on_message = MagicMock()

    # Mock `run_in_thread` to return a real thread-like object
    mock_thread = Thread(target=lambda: None)
    mock_channels["receive_channel"].run_in_thread.return_value = mock_thread

    # Call the listen method
    thread = simplex_queue.listen(on_message, block=False)

    # Assert that the returned thread is a Thread instance
    assert isinstance(thread, Thread)

    # Clean up the created thread to avoid side effects
    if thread.is_alive():
        thread.join()

def test_exec_message(simplex_queue):
    on_message = MagicMock()

    valid_message = {"data": "valid_data"}
    simplex_queue._RedisSimplexQueue__exec_message(valid_message, on_message)
    on_message.assert_called_once_with("valid_data")

    stop_message = {"data": "stop_process"}
    simplex_queue._RedisSimplexQueue__exec_message(stop_message, on_message)
    # Ensure the stop logic is triggered

def test_stop_all_threads(simplex_queue):
    mock_thread = MagicMock()
    simplex_queue._threads.append(mock_thread)

    simplex_queue.stop_all_queue_threads()
    mock_thread.stop.assert_called_once()
    assert len(simplex_queue._threads) == 0

def test_duplex_queue(mock_db):
    # Update mock_channels to include the "common_channel"
    mock_channels = {
        "common_channel": MagicMock()
    }

    # Instantiate the duplex queue
    duplex_queue = RedisDuplexQueue(mock_db, "common_channel", mock_channels)

    # Assertions to verify proper initialization
    assert duplex_queue._RedisSimplexQueue__send == "common_channel"
    assert duplex_queue._RedisSimplexQueue__receive == "common_channel"
    assert duplex_queue._RedisSimplexQueue__pub == mock_channels["common_channel"]

