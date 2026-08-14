from managers.process_manager.module_loading_mixin import ModuleLoadingMixin
from tests.module_factory import ModuleFactory


def test_process_manager_includes_module_loading_mixin() -> None:
    process_manager = ModuleFactory().create_process_manager_obj()

    assert isinstance(process_manager, ModuleLoadingMixin)
