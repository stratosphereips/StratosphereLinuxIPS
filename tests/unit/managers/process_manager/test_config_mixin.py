# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from unittest.mock import Mock, patch

import pytest

from managers.process_manager.config_mixin import ConfigMixin
from modules.supported_module_names import Modules
from slips_files.common.input_type import InputType
from tests.module_factory import ModuleFactory


def test_process_manager_includes_config_mixin() -> None:
    process_manager = ModuleFactory().create_process_manager_obj()

    assert isinstance(process_manager, ConfigMixin)


@pytest.mark.parametrize(
    "module_name, modules_to_ignore, expected",
    [
        # Test case 1: Module name not in ignore list
        ("test_module", ["ignore_module"], False),
        # Test case 2: Exact match in ignore list
        ("ignore_module", ["ignore_module"], True),
        # Test case 3: Partial match in ignore list
        ("test_ignore_module", ["ignore_module"], True),
        # Test case 4: Module name with spaces, not in ignore list
        ("test module", ["ignore module"], False),
        # Test case 5: Module name with hyphens, not in ignore list
        ("test-module", ["ignore-module"], False),
    ],
)
def test_is_disabled_module(module_name, modules_to_ignore, expected):
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.user_disabled_modules = set(modules_to_ignore)
    process_manager.slips_disabled_modules = set()
    assert process_manager.is_disabled_module(module_name) == expected


def test_get_disabled_modules_uses_disabled_module_helpers() -> None:
    """Test disabled modules are returned from the dedicated helper methods."""
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.get_user_disabled_modules = Mock(return_value={Modules.TEMPLATE})
    process_manager.get_runtime_disabled_modules = Mock(return_value={Modules.BLOCKING})

    disabled_modules = process_manager.get_disabled_modules()

    assert disabled_modules == ({Modules.TEMPLATE}, {Modules.BLOCKING})
    assert process_manager.user_disabled_modules == {Modules.TEMPLATE}
    assert process_manager.slips_disabled_modules == {Modules.BLOCKING}
    process_manager.get_user_disabled_modules.assert_called_once_with()
    process_manager.get_runtime_disabled_modules.assert_called_once_with()


@pytest.mark.parametrize(
    "configured_modules, expected_modules",
    [
        ([" template ", "custom_module"], {Modules.TEMPLATE, "custom_module"}),
        (
            [" template ", " feeds_update_manager "],
            {Modules.TEMPLATE, Modules.FEEDS_UPDATE_MANAGER},
        ),
        ([], set()),
    ],
)
def test_get_user_disabled_modules(
    configured_modules: list, expected_modules: set
) -> None:
    """Test user-disabled modules are read from config and stripped."""
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.main.conf.llm_enabled.return_value = True
    process_manager.main.conf.alert_summary_enabled.return_value = True
    process_manager.main.conf.regex_generator_enabled.return_value = True
    process_manager.main.conf.read_configuration.reset_mock()
    process_manager.main.conf.read_configuration.side_effect = None
    process_manager.main.conf.read_configuration.return_value = configured_modules

    disabled_modules = process_manager.get_user_disabled_modules()

    assert disabled_modules == expected_modules
    process_manager.main.conf.read_configuration.assert_called_once_with(
        "modules", "disable", ["template"]
    )


def test_get_runtime_disabled_modules_recomputes_from_current_settings() -> None:
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.main.args.clearblocking = False
    process_manager.main.args.blocking = False
    process_manager.main.conf.send_to_warden.return_value = True
    process_manager.slips_disabled_modules = {Modules.CESNET}

    disabled_modules = process_manager.get_runtime_disabled_modules()

    assert Modules.BLOCKING in disabled_modules
    assert Modules.ARP_POISONER in disabled_modules
    assert Modules.CESNET not in disabled_modules


@pytest.mark.parametrize(
    "input_type, export_to, expected_user, expected_slips",
    [
        (
            InputType.PCAP,
            [],
            {Modules.TEMPLATE, "custom_module"},
            {
                Modules.EXPORTING_ALERTS,
                Modules.P2P_TRUST,
                Modules.FIDES,
                Modules.IRIS,
                Modules.CESNET,
                Modules.BLOCKING,
                Modules.ARP_POISONER,
                Modules.CYST,
            },
        ),
        (
            InputType.ZEEK,
            ["stix"],
            {Modules.TEMPLATE, "custom_module"},
            {
                Modules.P2P_TRUST,
                Modules.FIDES,
                Modules.IRIS,
                Modules.CESNET,
                Modules.BLOCKING,
                Modules.ARP_POISONER,
                Modules.LEAK_DETECTOR,
                Modules.CYST,
            },
        ),
    ],
)
def test_get_disabled_modules(
    input_type: InputType,
    export_to: list,
    expected_user: set,
    expected_slips: set,
) -> None:
    """Test disabled modules are split by user and Slips runtime rules."""
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.main.conf.llm_enabled.return_value = True
    process_manager.main.conf.alert_summary_enabled.return_value = True
    process_manager.main.conf.regex_generator_enabled.return_value = True
    process_manager.main.input_type = input_type
    process_manager.main.args.clearblocking = False
    process_manager.main.args.blocking = False
    process_manager.main.conf.read_configuration.side_effect = (
        lambda section, name, default_value: (
            [" template ", "custom_module"]
            if (section, name) == ("modules", "disable")
            else default_value
        )
    )
    process_manager.main.conf.export_to.return_value = export_to

    user_disabled_modules, slips_disabled_modules = (
        process_manager.get_disabled_modules()
    )

    assert user_disabled_modules == expected_user
    assert slips_disabled_modules == expected_slips


@pytest.mark.parametrize(
    "llm_enabled, alert_summary_enabled, regex_generator_enabled, expected",
    [
        (False, True, True, {Modules.LLM_PROXY}),
        (True, False, True, {Modules.ALERT_SUMMARY}),
        (True, True, False, {Modules.REGEX_GENERATOR}),
        (
            False,
            False,
            False,
            {
                Modules.LLM_PROXY,
                Modules.ALERT_SUMMARY,
                Modules.REGEX_GENERATOR,
            },
        ),
    ],
)
def test_get_user_disabled_modules_includes_feature_toggled_modules(
    llm_enabled: bool,
    alert_summary_enabled: bool,
    regex_generator_enabled: bool,
    expected: set[Modules],
) -> None:
    """Test dedicated enabled flags disable LLM-related modules at startup."""
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.main.conf.read_configuration.side_effect = None
    process_manager.main.conf.read_configuration.return_value = []
    process_manager.main.conf.llm_enabled.return_value = llm_enabled
    process_manager.main.conf.alert_summary_enabled.return_value = alert_summary_enabled
    process_manager.main.conf.regex_generator_enabled.return_value = (
        regex_generator_enabled
    )

    assert process_manager.get_user_disabled_modules() == expected


def test_get_runtime_disabled_modules_uses_runtime_rules() -> None:
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.main.db.is_running_non_stop.return_value = False
    process_manager.main.conf.export_to.return_value = []
    process_manager.main.conf.use_local_p2p.return_value = False
    process_manager.main.conf.use_global_p2p.return_value = False
    process_manager.main.conf.send_to_warden.return_value = False
    process_manager.main.conf.receive_from_warden.return_value = False
    process_manager.main.args.clearblocking = False
    process_manager.main.args.blocking = False
    process_manager.main.input_type = InputType.ZEEK
    process_manager.main.args.input_module = ""
    process_manager.slips_disabled_modules = set()

    assert process_manager.get_runtime_disabled_modules() == {
        Modules.EXPORTING_ALERTS,
        Modules.P2P_TRUST,
        Modules.FIDES,
        Modules.IRIS,
        Modules.CESNET,
        Modules.BLOCKING,
        Modules.ARP_POISONER,
        Modules.LEAK_DETECTOR,
        Modules.CYST,
    }


def test_get_runtime_disabled_modules_disables_flow_alerts_for_zeek_log_file() -> (
    None
):
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.main.db.is_running_non_stop.return_value = False
    process_manager.main.conf.export_to.return_value = []
    process_manager.main.conf.use_local_p2p.return_value = False
    process_manager.main.conf.use_global_p2p.return_value = False
    process_manager.main.conf.send_to_warden.return_value = False
    process_manager.main.conf.receive_from_warden.return_value = False
    process_manager.main.args.clearblocking = False
    process_manager.main.args.blocking = False
    process_manager.main.input_type = InputType.ZEEK_LOG_FILE
    process_manager.main.args.input_module = ""
    process_manager.slips_disabled_modules = set()

    assert (
        Modules.FLOW_ALERTS in process_manager.get_runtime_disabled_modules()
    )


def test_get_runtime_disabled_modules_keeps_flow_alerts_enabled_otherwise() -> (
    None
):
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.main.db.is_running_non_stop.return_value = False
    process_manager.main.conf.export_to.return_value = []
    process_manager.main.conf.use_local_p2p.return_value = False
    process_manager.main.conf.use_global_p2p.return_value = False
    process_manager.main.conf.send_to_warden.return_value = False
    process_manager.main.conf.receive_from_warden.return_value = False
    process_manager.main.args.clearblocking = False
    process_manager.main.args.blocking = False
    process_manager.main.input_type = InputType.ZEEK
    process_manager.main.args.input_module = ""
    process_manager.slips_disabled_modules = set()

    assert (
        Modules.FLOW_ALERTS
        not in process_manager.get_runtime_disabled_modules()
    )


def test_get_disabled_modules_keeps_unrelated_modules_enabled() -> None:
    """Test disabling regex_generator does not disable unrelated modules."""
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.main.conf.read_configuration.side_effect = (
        lambda section, name, default_value: (
            [Modules.REGEX_GENERATOR]
            if (section, name) == ("modules", "disable")
            else default_value
        )
    )

    _, slips_disabled_modules = process_manager.get_disabled_modules()

    assert Modules.T_CELL not in slips_disabled_modules
    assert Modules.T_CELL not in process_manager.slips_disabled_modules


@pytest.mark.parametrize(
    "disabled_modules, enabled_value, expected",
    [
        ({Modules.LLM_PROXY}, True, True),
        (set(), False, False),
        (set(), True, False),
    ],
)
def test_has_missing_dependency_respects_disabled_and_configured_dependencies(
    disabled_modules: set[Modules],
    enabled_value: bool,
    expected: bool,
) -> None:
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.main.conf.read_configuration.side_effect = (
        lambda section, name, default_value: (
            enabled_value
            if section == "llmproxy" and name == "enabled"
            else default_value
        )
    )

    assert (
        process_manager._has_missing_dependency(
            Modules.REGEX_GENERATOR, disabled_modules
        )
        is expected
    )


def test_read_config_parses_module_dependencies() -> None:
    module_factory = ModuleFactory()
    process_manager = module_factory.create_process_manager_obj()

    assert process_manager.module_dependencies == {
        Modules.LLM_PROXY: (),
        Modules.REGEX_GENERATOR: (Modules.LLM_PROXY,),
        Modules.ALERT_SUMMARY: (Modules.LLM_PROXY,),
    }


@pytest.mark.parametrize(
    "module_name, expected_dependencies",
    [
        (Modules.LLM_PROXY, ()),
        ("regex_generator", (Modules.LLM_PROXY,)),
        (
            "modules.alert_summary.alert_summary",
            (Modules.LLM_PROXY,),
        ),
        ("unknown_module", ()),
    ],
)
def test_get_module_dependencies(
    module_name: str, expected_dependencies: tuple
) -> None:
    module_factory = ModuleFactory()
    process_manager = module_factory.create_process_manager_obj()

    assert process_manager.get_module_dependencies(module_name) == expected_dependencies


def test_get_dependency_disabled_modules_disables_llm_dependents() -> None:
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.user_disabled_modules = {Modules.LLM_PROXY}
    process_manager.main.conf.read_configuration.side_effect = (
        lambda section, name, default_value: default_value
    )

    assert process_manager._get_dependency_disabled_modules(set()) == {
        Modules.REGEX_GENERATOR,
        Modules.ALERT_SUMMARY,
    }


def test_get_dependency_disabled_modules_ignores_disabled_dependents() -> None:
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.user_disabled_modules = {
        Modules.LLM_PROXY,
        Modules.REGEX_GENERATOR,
        Modules.ALERT_SUMMARY,
    }
    process_manager.main.conf.read_configuration.side_effect = (
        lambda section, name, default_value: default_value
    )

    with patch.object(process_manager.main, "print") as mock_print:
        assert process_manager._get_dependency_disabled_modules(set()) == set()

    mock_print.assert_not_called()


@pytest.mark.parametrize(
    "bootstrapping_node, use_global_p2p, expected",
    [
        (True, True, True),
        (True, False, False),
        (False, True, False),
    ],
)
def test_is_bootstrapping_node(bootstrapping_node, use_global_p2p, expected):
    """Test P2P bootstrapping is enabled only when both flags are set."""
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.bootstrapping_node = bootstrapping_node
    process_manager.use_global_p2p = use_global_p2p
    process_manager.main.db.is_running_non_stop.return_value = True

    assert process_manager.is_bootstrapping_node() is expected


def test_reading_flows_from_cyst_uses_supported_module_name() -> None:
    """Test CYST input detection relies on the shared module-name enum."""
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.main.args.input_module = Modules.CYST.value

    assert process_manager._reading_flows_from_cyst() is True


@pytest.mark.parametrize(
    "cli_enabled, config_enabled, expected_disabled",
    [
        (False, False, True),
        (False, True, False),
        (True, False, False),
    ],
)
def test_web_interface_feature_toggle(
    cli_enabled: bool,
    config_enabled: bool,
    expected_disabled: bool,
) -> None:
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.main.args.webinterface = cli_enabled
    process_manager.main.conf.web_interface_enabled.return_value = config_enabled

    disabled = process_manager._get_feature_toggled_disabled_modules()

    assert (Modules.WEB_INTERFACE in disabled) is expected_disabled
