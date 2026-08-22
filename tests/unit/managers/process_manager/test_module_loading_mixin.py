from unittest.mock import Mock, call

import pytest

from managers.process_manager.module_loading_mixin import ModuleLoadingMixin
from modules.supported_module_names import Modules
from tests.module_factory import ModuleFactory


def test_process_manager_includes_module_loading_mixin() -> None:
    process_manager = ModuleFactory().create_process_manager_obj()

    assert isinstance(process_manager, ModuleLoadingMixin)


def test_get_modules() -> None:
    process_manager = ModuleFactory().create_process_manager_obj()
    skipped_module = "modules.skipped.skipped"
    failed_module = "modules.failed.failed"
    loaded_module_name = "modules.arp.arp"
    loaded_module = Mock(name="loaded_module")
    discovered_plugins = {
        Modules.ARP: {
            "obj": Mock(name="arp_class"),
            "description": "ARP detections",
        }
    }
    reordered_plugins = dict(discovered_plugins)
    user_disabled_modules = {"skipped"}
    slips_disabled_modules = {Modules.ML_LINEAR_MODEL}
    process_manager.get_disabled_modules = Mock(
        return_value=(user_disabled_modules, slips_disabled_modules)
    )
    process_manager._discover_module_names = Mock(
        return_value=(skipped_module, failed_module, loaded_module_name)
    )
    process_manager._should_load_module = Mock(side_effect=(False, True, True))
    process_manager._import_module = Mock(side_effect=(None, loaded_module))
    process_manager._load_valid_classes_from_module = Mock(
        return_value=discovered_plugins
    )
    process_manager._reorder_modules = Mock(return_value=reordered_plugins)

    plugins, failed_to_load_modules = process_manager.get_modules()

    assert plugins == reordered_plugins
    assert failed_to_load_modules == 1
    assert process_manager.user_disabled_modules == user_disabled_modules
    assert process_manager.slips_disabled_modules == slips_disabled_modules
    process_manager.get_disabled_modules.assert_called_once_with()
    process_manager._discover_module_names.assert_called_once_with()
    assert process_manager._should_load_module.call_args_list == [
        call(skipped_module),
        call(failed_module),
        call(loaded_module_name),
    ]
    assert process_manager._import_module.call_args_list == [
        call(failed_module),
        call(loaded_module_name),
    ]
    process_manager._load_valid_classes_from_module.assert_called_once_with(
        loaded_module, {}
    )
    process_manager._reorder_modules.assert_called_once_with(
        discovered_plugins
    )


@pytest.mark.parametrize(
    "should_bootstrap, module_name, disabled_modules, expected",
    [
        (True, "modules.fides.fides", [], True),
        (True, "modules.flow_alerts.flow_alerts", [], False),
        (False, "modules.flow_alerts.flow_alerts", ["flow_alerts"], False),
        (False, "modules.fides.fides", [], True),
    ],
)
def test_should_load_module(
    should_bootstrap, module_name, disabled_modules, expected
):
    """Test module loading respects bootstrapping and disabled modules."""
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.bootstrapping_modules = ["fides", "iris"]
    process_manager.user_disabled_modules = set(disabled_modules)
    process_manager.slips_disabled_modules = set()
    process_manager.is_bootstrapping_node = Mock(return_value=should_bootstrap)

    assert process_manager._should_load_module(module_name) is expected
