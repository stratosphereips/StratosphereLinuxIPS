import inspect
from pathlib import Path
from unittest.mock import Mock, mock_open, patch

import pytest

from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "asset_name, expected_text",
    [
        ("index.html", 'id="drawer-resize"'),
        ("index.html", 'id="drawer-back"'),
        ("index.html", 'id="alerts-view"'),
        ("index.html", 'id="evidence-view"'),
        ("app.js", "function initializeRanges(run)"),
        ("app.js", "function configureTable(name, layout, headers, loader)"),
        ("app.js", "function bindView(name, loader)"),
        ("app.js", "function renderDnsDetails(dns)"),
        ("app.js", "function protocolFlowCard(record)"),
        ("app.js", "Related protocol flows"),
        ("app.js", "Query type"),
        ("app.js", "View complete ${label} record (JSON)"),
        ("app.js", "async function inspectHost(ip)"),
        ("app.js", "function backDrawer()"),
        ("app.js", "scrollTop: body.scrollTop"),
        ("style.css", ".flow-path"),
        ("style.css", ".protocol-card"),
        ("style.css", "cursor: ew-resize"),
    ],
)
def test_investigation_panel_assets(
    asset_name: str,
    expected_text: str,
) -> None:
    """Verify investigation assets retain resize, labels, and host navigation."""
    module_factory = ModuleFactory()
    module = module_factory.create_web_interface_obj()
    asset_dir = Path(inspect.getfile(type(module))).parent

    assert expected_text in (asset_dir / asset_name).read_text()


def test_pre_main_starts_server_for_current_run() -> None:
    module_factory = ModuleFactory()
    module = module_factory.create_web_interface_obj()
    module.parent_output_dir = "output/current_run"
    module.redis_port = 32768
    process = Mock(pid=1234)

    with (
        patch.object(module, "_replace_stale_server", return_value=True),
        patch.object(
            module,
            "get_module_specific_output_path",
            return_value="output/current_run/web_interface/server.log",
        ),
        patch("modules.web_interface.web_interface.HistoryCollector") as collector,
        patch("modules.web_interface.web_interface.utils.start_thread") as start_thread,
        patch("modules.web_interface.web_interface.utils.drop_root_privs_permanently"),
        patch("builtins.open", mock_open()),
        patch(
            "modules.web_interface.web_interface.subprocess.Popen",
            return_value=process,
        ) as popen,
    ):
        result = module.pre_main()

    assert result is False
    command = popen.call_args.args[0]
    assert command[-3:] == [
        "32768",
        "--output-dir",
        "output/current_run",
    ]
    assert "modules.web_interface.server" in command
    collector.return_value.snapshot_hosts.assert_called_once_with()
    collector.return_value.backfill_detections.assert_not_called()
    assert start_thread.call_count == 2
    module.db.store_pid.assert_any_call("Web Interface", 1234)


def test_detection_backfill_runs_outside_live_collector() -> None:
    """Run durable recovery in its own stoppable worker loop."""
    module = ModuleFactory().create_web_interface_obj()
    module.history_collector = Mock()
    module.history_stop = Mock()
    module.history_stop.is_set.side_effect = [False, True]

    module._backfill_history()

    module.history_collector.backfill_detections.assert_called_once_with()
    module.history_stop.wait.assert_called_once_with(30)


def test_pre_main_rejects_used_port() -> None:
    module_factory = ModuleFactory()
    module = module_factory.create_web_interface_obj()

    with (
        patch.object(type(module), "_port_is_available", return_value=False),
        patch.object(type(module), "_listener_pid", return_value=None),
        patch("modules.web_interface.web_interface.utils.drop_root_privs_permanently"),
    ):
        result = module.pre_main()

    assert result is True
    module.print.assert_called_once()


def test_main_reports_stopped_server() -> None:
    module_factory = ModuleFactory()
    module = module_factory.create_web_interface_obj()
    module.server_process = Mock(returncode=7)
    module.server_process.poll.return_value = 7

    with patch("modules.web_interface.web_interface.time.sleep"):
        result = module.main()

    assert result is True
    assert "exit code 7" in module.print.call_args.args[0]


@pytest.mark.parametrize(
    "owned_server, expected",
    [
        (True, True),
        (False, False),
    ],
)
def test_stop_verified_server_only_stops_owned_listener(
    owned_server: bool, expected: bool
) -> None:
    """
    Test shutdown never terminates an unrelated listener.

    Parameters:
        owned_server: Whether listener verification accepts the process.
        expected: Expected stop result.
    """
    module = ModuleFactory().create_web_interface_obj()
    process = Mock()

    with (
        patch.object(
            type(module),
            "_port_is_available",
            side_effect=[False, True] if owned_server else [False],
        ),
        patch.object(type(module), "_listener_pid", return_value=1234),
        patch.object(type(module), "_is_owned_web_server", return_value=owned_server),
        patch(
            "modules.web_interface.web_interface.psutil.Process",
            return_value=process,
        ),
    ):
        result = module.stop_verified_server(55000)

    assert result is expected
    if owned_server:
        process.terminate.assert_called_once_with()
        process.wait.assert_called_once_with(timeout=3)
    else:
        process.terminate.assert_not_called()
