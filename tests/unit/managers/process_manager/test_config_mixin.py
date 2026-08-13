from managers.process_manager.config_mixin import ConfigMixin
from tests.module_factory import ModuleFactory


def test_process_manager_includes_config_mixin() -> None:
    process_manager = ModuleFactory().create_process_manager_obj()

    assert isinstance(process_manager, ConfigMixin)
