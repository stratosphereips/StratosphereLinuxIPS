from managers.process_manager.shutdown_mixin import ShutdownMixin
from tests.module_factory import ModuleFactory


def test_process_manager_includes_shutdown_mixin() -> None:
    process_manager = ModuleFactory().create_process_manager_obj()

    assert isinstance(process_manager, ShutdownMixin)
