"""Exercise shutdown with real detached descendants and unrelated processes."""

import multiprocessing
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

import psutil
import pytest

from managers.process_manager.owned_processes import OwnedProcesses
from tests.module_factory import ModuleFactory


def detached_worker(connection: Any, finish: Any) -> None:
    """Start a stubborn separate-session subprocess and wait for release.

    Parameters:
        connection: Pipe reporting the detached subprocess identity.
        finish: Event permitting the worker to exit before its subprocess.
    """
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    child = subprocess.Popen(
        [sys.executable, "-c", "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); print('ready',flush=True); time.sleep(90)"],
        start_new_session=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    assert child.stdout.readline().strip() == "ready"
    connection.send(child.pid)
    finish.wait(90)


@pytest.mark.parametrize("method", ["spawn", "forkserver"])
@pytest.mark.parametrize("parent_exited", [False, True])
def test_detached_descendant_is_stopped_after_parent_exit(method: str, parent_exited: bool) -> None:
    """Keep detached descendants in scope after their parent disappears.

    Parameters:
        method: Multiprocessing startup mechanism.
        parent_exited: Exit the worker before performing forced cleanup.
    """
    factory = ModuleFactory()
    context = multiprocessing.get_context(method)
    receiver, sender = context.Pipe(duplex=False)
    finish = context.Event()
    worker = context.Process(target=detached_worker, args=(sender, finish))
    owned = OwnedProcesses()
    outsider = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(90)"], start_new_session=True)
    detached = None
    try:
        worker.start()
        assert receiver.poll(20)
        detached = psutil.Process(receiver.recv())
        owned.remember(worker.pid)
        assert detached.pid in owned.processes
        if parent_exited:
            finish.set()
            worker.join(5)
            assert not worker.is_alive()
        before = time.monotonic()
        owned.stop(grace_seconds=.05)
        assert time.monotonic() - before < 5
        worker.join(2)
        assert not worker.is_alive()
        assert not detached.is_running() or detached.status() == psutil.STATUS_ZOMBIE
        assert outsider.poll() is None
        assert factory.logger is not None
    finally:
        owned.stop()
        if worker.is_alive():
            worker.kill()
        worker.join(5)
        outsider.kill()
        outsider.wait(5)
        receiver.close()
        sender.close()
        worker.close()


def test_web_exclusion_is_temporary_and_non_owned_roots_are_rejected() -> None:
    """Retain only the selected web process until final cleanup."""
    factory = ModuleFactory()
    owned = OwnedProcesses()
    owned.remember(os.getpid())
    owned.remember(os.getppid())
    owned.remember(1)
    assert owned.processes == {}
    web = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(90)"])
    try:
        owned.remember(web.pid)
        owned.stop(frozenset({web.pid}))
        assert web.poll() is None
        owned.stop()
        assert web.wait(3) is not None
        assert factory.logger is not None
    finally:
        if web.poll() is None:
            web.kill()
            web.wait(3)


def test_refresh_retains_late_descendants() -> None:
    """Record a subprocess created after its worker was first registered."""
    factory = ModuleFactory()
    owned = OwnedProcesses()
    parent, child = Mock(pid=123), Mock(pid=456)
    parent.is_running.return_value = True
    parent.children.return_value = [child]
    owned.processes[parent.pid] = parent
    owned.refresh()
    assert owned.processes[child.pid] is child
    assert factory.logger is not None


@pytest.mark.parametrize("running", [False, True])
def test_cleanup_checks_identity_and_reports_survivors(running: bool) -> None:
    """Never signal a reused PID or claim an unkillable process stopped.

    Parameters:
        running: Whether the retained identity still represents a live process.
    """
    factory = ModuleFactory()
    owned = OwnedProcesses()
    process = Mock(pid=123)
    process.is_running.return_value = running
    process.status.return_value = psutil.STATUS_RUNNING
    process.children.return_value = []
    owned.processes[123] = process
    with patch.object(owned, "_wait_for_exit", return_value=[process] if running else []):
        if running:
            with pytest.raises(RuntimeError, match="123"):
                owned.stop()
            process.send_signal.assert_called_once_with(signal.SIGKILL)
        else:
            owned.stop()
            process.send_signal.assert_not_called()
    assert factory.logger is not None


def test_only_owned_real_zeek_is_stopped(tmp_path: Path) -> None:
    """Stop a real Zeek waiting for PCAP input while another Zeek survives.

    Parameters:
        tmp_path: Isolated Zeek log directory, without live capture data.
    """
    factory = ModuleFactory()
    binary = shutil.which("zeek") or shutil.which("bro")
    if not binary:
        pytest.skip("Zeek is not installed")
    owned = OwnedProcesses()
    processes = []
    try:
        for _ in range(2):
            processes.append(subprocess.Popen([binary, "-r", "-"], cwd=tmp_path,
                stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        owned.remember(processes[0].pid)
        assert all(process.poll() is None for process in processes)
        owned.stop(grace_seconds=.1)
        assert processes[0].wait(3) is not None
        assert processes[1].poll() is None
        assert factory.logger is not None
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
            process.wait(5)
            process.stdin.close()


def shutdown_coordinator(connection: Any, double_interrupt: bool) -> None:
    """Run the real shutdown coordinator with isolated services and workers.

    Parameters:
        connection: Pipe reporting the worker tree to the test.
        double_interrupt: Interrupt the normal wait with another Ctrl-C.
    """
    manager = ModuleFactory().create_process_manager_obj()
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    finish = context.Event()
    worker = context.Process(target=detached_worker, args=(sender, finish), name="shutdown-probe")
    worker.start()
    assert receiver.poll(20)
    detached_pid = receiver.recv()
    manager.processes = [worker]
    manager.main.pid = os.getpid()
    manager.main.args.blocking = False
    manager.main.conf.wait_for_modules_to_finish.return_value = .1 / 60
    manager.main.conf.export_labeled_flows.return_value = False
    manager.get_hitlist_in_order = Mock(return_value=([worker], []))
    manager._generate_plots = Mock()
    manager._handle_firewall_after_analysis = Mock()
    manager._handle_web_interface_after_analysis = Mock()
    manager.get_analysis_time = Mock(return_value=(.1, "2026/10/26 12:00:00"))
    if double_interrupt:
        manager.shutdown_interactive = Mock(side_effect=KeyboardInterrupt())
    signal.signal(signal.SIGINT, signal.default_int_handler)
    connection.send((worker.pid, detached_pid))
    try:
        signal.pause()
    except KeyboardInterrupt:
        manager.handle_keyboard_interrupt()
    manager.shutdown_gracefully()
    connection.send("stopped")
    worker.join(2)
    worker.close()


@pytest.mark.parametrize("double_interrupt", [False, True])
def test_ctrl_c_reaps_modules_and_detached_subprocesses(double_interrupt: bool) -> None:
    """Verify Ctrl-C reaches the coordinator's final verified cleanup.

    Parameters:
        double_interrupt: Also interrupt the coordinator's grace-period wait.
    """
    factory = ModuleFactory()
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    coordinator = context.Process(target=shutdown_coordinator, args=(sender, double_interrupt))
    tree = []
    try:
        coordinator.start()
        assert receiver.poll(25)
        tree = [psutil.Process(pid) for pid in receiver.recv()]
        os.kill(coordinator.pid, signal.SIGINT)
        assert receiver.poll(15), "shutdown did not finish"
        assert receiver.recv() == "stopped"
        coordinator.join(5)
        assert coordinator.exitcode == 0
        assert all(not child.is_running() or child.status() == psutil.STATUS_ZOMBIE for child in tree)
        assert factory.logger is not None
    finally:
        for child in tree:
            try:
                if child.is_running():
                    child.kill()
            except psutil.NoSuchProcess:
                pass
        if coordinator.is_alive():
            coordinator.kill()
        coordinator.join(5)
        coordinator.close()
        receiver.close()
        sender.close()
