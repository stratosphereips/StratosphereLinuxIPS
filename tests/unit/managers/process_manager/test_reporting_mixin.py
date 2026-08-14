from managers.process_manager.reporting_mixin import ReportingMixin
from tests.module_factory import ModuleFactory


def test_process_manager_includes_reporting_mixin() -> None:
    process_manager = ModuleFactory().create_process_manager_obj()

    assert isinstance(process_manager, ReportingMixin)
