import pytest
from unittest.mock import Mock, patch
from multiprocessing import Event
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "initial_value, update_count, expected_final_value, total_flows",
    [
        # testcase1: Normal update
        (0, 1, 1, 100),
        # testcase2: Multiple updates
        (50, 5, 55, 100),
    ],
)
def test_update_bar_normal(
    initial_value, update_count, expected_final_value, total_flows
):
    pbar = ModuleFactory().create_progress_bar_obj()
    pbar.slips_mode = "interactive"
    pbar.total_flows = total_flows
    pbar.pbar_finished = Event()

    mock_progress_bar = Mock()
    mock_progress_bar.n = initial_value
    pbar.progress_bar = mock_progress_bar

    def update_side_effect(amount):
        mock_progress_bar.n += amount

    mock_progress_bar.update.side_effect = update_side_effect

    for _ in range(update_count):
        pbar.update_bar()

    assert mock_progress_bar.update.call_count == update_count
    assert mock_progress_bar.n == expected_final_value


def test_update_bar_termination():
    pbar = ModuleFactory().create_progress_bar_obj()
    pbar.slips_mode = "normal"
    pbar.total_flows = 100
    pbar.pbar_finished = Event()
    mock_progress_bar = Mock()
    mock_progress_bar.n = 99
    pbar.progress_bar = mock_progress_bar

    def update_side_effect(amount):
        mock_progress_bar.n += amount

    mock_progress_bar.update.side_effect = update_side_effect

    pbar.update_bar()

    assert mock_progress_bar.update.call_count == 1
    assert mock_progress_bar.n == 100


def test_update_bar_no_progress_bar():
    pbar = ModuleFactory().create_progress_bar_obj()
    pbar.slips_mode = "normal"

    assert not hasattr(pbar, "progress_bar")

    try:
        pbar.update_bar()
    except AttributeError:
        pytest.fail("update_bar() raised AttributeError unexpectedly")

    assert not hasattr(pbar, "progress_bar")


def test_update_bar_daemonized_mode():
    pbar = ModuleFactory().create_progress_bar_obj()
    pbar.slips_mode = "daemonized"
    pbar.progress_bar = Mock()

    pbar.update_bar()

    pbar.progress_bar.update.assert_not_called()


@pytest.mark.parametrize(
    "msg, expected_output",
    [
        # testcase1: Normal message
        ({"txt": "Test message"}, "Test message"),
        # testcase2: Empty message
        ({"txt": ""}, ""),
        # testcase3: Message with special characters
        (
            {"txt": "Test\nmessage\twith\rspecial\fcharacters"},
            "Test\nmessage\twith\rspecial\fcharacters",
        ),
    ],
)
def test_print_to_cli(
    msg,
    expected_output,
):
    pbar = ModuleFactory().create_progress_bar_obj()

    with patch("tqdm.auto.tqdm.write") as mock_write:
        pbar.print_to_cli(msg)

        mock_write.assert_called_once_with(expected_output)


@pytest.mark.parametrize(
    "msg, expected_stats",
    [
        # testcase1: Normal stats
        ({"stats": "Processing: 50%"}, "Processing: 50%"),
        # testcase2: Empty stats
        ({"stats": ""}, ""),
        # testcase3: Stats with special characters
        ({"stats": "CPU: 80%\nRAM: 4GB"}, "CPU: 80%\nRAM: 4GB"),
    ],
)
def test_update_stats(
    msg,
    expected_stats,
):
    pbar = ModuleFactory().create_progress_bar_obj()
    mock_progress_bar = Mock()
    pbar.progress_bar = mock_progress_bar

    pbar.update_stats(msg)

    (
        mock_progress_bar.set_postfix_str.assert_called_once_with(
            expected_stats, refresh=True
        )
    )


def test_shutdown_gracefully_event_not_set():
    pbar = ModuleFactory().create_progress_bar_obj()
    pbar.progress_bar = Mock()
    pbar.pbar_finished = Event()
    pbar.shutdown_gracefully()
    assert pbar.pbar_finished.is_set()


def test_shutdown_gracefully_event_already_set():
    pbar = ModuleFactory().create_progress_bar_obj()
    pbar.progress_bar = Mock()
    pbar.pbar_finished = Event()
    pbar.pbar_finished.set()
    pbar.shutdown_gracefully()
    assert pbar.pbar_finished.is_set()


def test_remove_stats():
    pbar = ModuleFactory().create_progress_bar_obj()
    mock_progress_bar = Mock()
    pbar.progress_bar = mock_progress_bar

    pbar.remove_stats()

    (
        mock_progress_bar.set_postfix_str.assert_called_once_with(
            "", refresh=True
        )
    )


@pytest.mark.parametrize(
    "total_flows, current_n",
    [
        # testcase1: Normal case
        (100, 100),
        # testcase2: Edge case - zero flows
        (0, 0),
        # testcase3: Large number of flows
        (1000000, 1000000),
    ],
)
def test_shutdown_gracefully(
    total_flows,
    current_n,
):
    pbar = ModuleFactory().create_progress_bar_obj()
    pbar.total_flows = total_flows
    pbar.pbar_finished = Event()

    mock_progress_bar = Mock()
    mock_progress_bar.n = current_n
    pbar.progress_bar = mock_progress_bar

    with patch.object(pbar, "remove_stats") as mock_remove_stats, patch(
        "tqdm.auto.tqdm.write"
    ) as mock_write:
        pbar.shutdown_gracefully()

        mock_remove_stats.assert_called_once()
        mock_write.assert_called_once_with(
            "Profiler is done reading all flows. "
            "Slips is now processing them."
        )
        assert pbar.pbar_finished.is_set()
