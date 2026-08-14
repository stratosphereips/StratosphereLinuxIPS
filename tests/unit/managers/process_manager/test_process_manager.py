from managers.process_manager.process_manager import ProcessManager
from tests.module_factory import ModuleFactory


def test_nested_process_manager_module_instantiates_process_manager() -> None:
    process_manager = ModuleFactory().create_process_manager_obj()

    assert isinstance(process_manager, ProcessManager)
    assert process_manager.__class__.__module__ == (
        "managers.process_manager.process_manager"
    )
