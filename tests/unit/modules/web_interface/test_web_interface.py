from unittest.mock import Mock, mock_open, patch

from tests.module_factory import ModuleFactory


def test_pre_main_starts_server_for_current_run() -> None:
    module_factory = ModuleFactory()
    module = module_factory.create_web_interface_obj()
    module.parent_output_dir = "output/current_run"
    module.redis_port = 32768
    process = Mock(pid=1234)

    with (
        patch.object(module, "_port_is_available", return_value=True),
        patch.object(
            module,
            "get_module_specific_output_path",
            return_value="output/current_run/web_interface/server.log",
        ),
        patch(
            "modules.web_interface.web_interface.utils." "drop_root_privs_permanently"
        ),
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
    module.db.store_pid.assert_called_once_with("Web Interface", 1234)


def test_pre_main_rejects_used_port() -> None:
    module_factory = ModuleFactory()
    module = module_factory.create_web_interface_obj()

    with (
        patch.object(module, "_port_is_available", return_value=False),
        patch(
            "modules.web_interface.web_interface.utils." "drop_root_privs_permanently"
        ),
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
