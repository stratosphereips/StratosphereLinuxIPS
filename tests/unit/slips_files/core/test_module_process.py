"""Check that modules cross a spawn boundary holding only configuration."""
import multiprocessing
import pickle
from unittest.mock import Mock, patch

from modules.template.template import Template
from slips_files.core.aid_manager import AIDManager
from tests.module_factory import ModuleFactory


def make_module(**kwargs):
    """Build an unstarted Template module with picklable arguments."""
    return Template(
        "logger",
        "output",
        6379,
        None,
        "args",
        "conf",
        1,
        "bloom",
        **kwargs,
    )


def test_constructor_defers_resources_to_the_child() -> None:
    """The parent must not build the database or run init()."""
    module = make_module(startup_total=3)

    assert not hasattr(module, "db")
    assert module.startup_total == 3
    assert module.name == "template"
    assert module.description == "Template module"


def test_deferred_module_state_is_picklable() -> None:
    """Spawn pickles the module, so its stored state must pickle."""
    module = make_module()
    state = {k: v for k, v in vars(module).items() if k != "_config"}

    assert pickle.loads(pickle.dumps(state))["redis_port"] == 6379


def test_spawn_is_the_default_start_method() -> None:
    """Slips relies on spawn on every OS."""
    assert multiprocessing.get_start_method() == "spawn"


def test_run_prepares_child_then_executes() -> None:
    """run() builds resources, tracks sockets and stops them on exit."""
    module = make_module(startup_total=2)
    module._setup = Mock(
        side_effect=lambda: setattr(module, "db", Mock(name="db"))
    )
    module._execute = Mock()
    module._announce_startup = Mock()
    tracker = Mock()
    with patch(
        "slips_files.common.abstracts.imodule.parent_process",
        return_value=Mock(),
    ), patch(
        "slips_files.common.slips_own_traffic.SlipsTrafficTracker",
        return_value=tracker,
    ), patch(
        "managers.process_manager.worker_lifecycle.start_parent_watchdog"
    ) as watchdog, patch("signal.signal"):
        module.run()

    tracker.install.assert_called_once_with()
    tracker.attach.assert_called_once_with(module.db)
    module._announce_startup.assert_called_once_with()
    module._execute.assert_called_once_with()
    watchdog.return_value.set.assert_called_once_with()
    tracker.stop.assert_called_once_with()


def test_aid_shutdown_waits_for_storage() -> None:
    """Wait for AID storage before the profiler can exit."""
    factory = ModuleFactory()

    manager = AIDManager.for_queue(factory.profiler_queue)
    manager._process = Mock()
    manager.shutdown()
    assert factory.profiler_queue.get(timeout=2) == "stop"
    manager._process.join.assert_called_once_with()
