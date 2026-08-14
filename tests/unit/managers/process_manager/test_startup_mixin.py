from managers.process_manager.startup_mixin import StartupMixin
from tests.module_factory import ModuleFactory


def test_process_manager_includes_startup_mixin() -> None:
    process_manager = ModuleFactory().create_process_manager_obj()

    assert isinstance(process_manager, StartupMixin)
