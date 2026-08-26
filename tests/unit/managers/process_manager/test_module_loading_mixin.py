from unittest.mock import Mock, call, patch

import pytest

from managers.process_manager.module_loading_mixin import ModuleLoadingMixin
from modules.supported_module_names import Modules
from tests.module_factory import ModuleFactory


def test_process_manager_includes_module_loading_mixin() -> None:
    process_manager = ModuleFactory().create_process_manager_obj()

    assert isinstance(process_manager, ModuleLoadingMixin)


def test_get_enabled_module_names() -> None:
    process_manager = ModuleFactory().create_process_manager_obj()
    skipped_module = "modules.skipped.skipped"
    loaded_module_name = "modules.arp.arp"
    user_disabled_modules = {"skipped"}
    slips_disabled_modules = {Modules.ML_LINEAR_MODEL}
    reordered_module_names = [loaded_module_name]
    process_manager.get_disabled_modules = Mock(
        return_value=(user_disabled_modules, slips_disabled_modules)
    )
    process_manager._discover_module_names = Mock(
        return_value=(skipped_module, loaded_module_name)
    )
    process_manager._should_load_module = Mock(side_effect=(False, True))
    process_manager._reorder_module_names = Mock(
        return_value=reordered_module_names
    )

    enabled_module_names = process_manager.get_enabled_module_names()

    assert enabled_module_names == reordered_module_names
    assert process_manager.user_disabled_modules == user_disabled_modules
    assert process_manager.slips_disabled_modules == slips_disabled_modules
    process_manager.get_disabled_modules.assert_called_once_with()
    process_manager._discover_module_names.assert_called_once_with()
    assert process_manager._should_load_module.call_args_list == [
        call(skipped_module),
        call(loaded_module_name),
    ]
    process_manager._reorder_module_names.assert_called_once_with(
        [loaded_module_name]
    )


def test_load_modules_starts_a_process_per_enabled_module() -> None:
    process_manager = ModuleFactory().create_process_manager_obj()
    process_manager.get_enabled_module_names = Mock(
        return_value=["modules.arp.arp"]
    )
    process_manager.termination_event = Mock(name="termination_event")

    with patch(
        "managers.process_manager.module_loading_mixin.Process"
    ) as mock_process_class:
        mock_process = Mock(pid=1234)
        mock_process_class.return_value = mock_process

        process_manager.load_modules()

        mock_process_class.assert_called_once_with(
            target=process_manager._run_module,
            name="arp",
            args=(
                "modules.arp.arp",
                process_manager.main.logger,
                process_manager.main.args.output,
                process_manager.main.redis_port,
                process_manager.termination_event,
                process_manager.main.args,
                process_manager.main.conf,
                process_manager.main.pid,
                process_manager.main.bloom_filters_man,
            ),
        )
        mock_process.start.assert_called_once_with()
        process_manager.main.db.store_pid.assert_called_once_with("arp", 1234)


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
