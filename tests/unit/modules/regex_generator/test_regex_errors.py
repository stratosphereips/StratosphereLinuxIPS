from modules.regex_generator.regex_errors import _NullTimeout, _SignalTimeout
from tests.module_factory import ModuleFactory


def test_regex_timeout_helpers_are_instantiable() -> None:
    regex_generator = ModuleFactory().create_regex_generator_obj()

    assert regex_generator is not None
    assert _NullTimeout().__enter__() is None
    assert _SignalTimeout(1).timeout_seconds == 1
