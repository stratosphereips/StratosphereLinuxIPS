# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
# ModuleLoadingMixin groups module discovery, filtering, ordering, and
# startup of detection modules for ProcessManager.
import importlib
import inspect
import os
import pkgutil
import traceback
from multiprocessing import Process
from types import ModuleType
from typing import List, Any, Dict, Iterator, Optional

import modules
from modules.supported_module_names import Modules
from slips_files.common.abstracts.imodule import IModule
from slips_files.core.evidence_handler import DEFAULT_EVIDENCE_HANDLER_WORKERS
from slips_files.core.worker_manager_mixin import (
    NUM_INITIAL_PROFILER_WORKERS,
)

PluginMap = Dict[Modules, Dict[str, Any]]


class ModuleLoadingMixin:
    """Provide helpers for discovery and startup of detection modules."""

    def is_abstract_module(self, obj: type) -> bool:
        """
        Check whether a discovered class is an abstract module base.

        Parameters:
            obj: Discovered class object.

        Returns:
            True when the class is one of the abstract module bases.
        """
        return obj.name in ("imodule", "iasync_module")

    def _discover_module_names(self) -> Iterator[str]:
        """
        Walk recursively through all importable modules in modules/.
        Doesn't import anything, just looks at file/dir names.

        Returns:
            Iterator of fully qualified module names to consider.
        """
        # __path__ is the current path of this python program
        look_for_modules_in = modules.__path__
        prefix = f"{modules.__name__}."

        for _, module_name, ispkg in pkgutil.walk_packages(
            look_for_modules_in, prefix
        ):
            if ispkg:
                continue  # skip if current item is a package

            module_parts = module_name.split(".")
            if len(module_parts) < 3:
                continue

            dir_name, file_name = module_parts[1:3]
            # to avoid loading everything in the dir,
            # only load modules that have the same name as the dir name
            if dir_name == file_name:
                yield module_name

    def _should_load_module(self, module_name: str) -> bool:
        """
        Decide whether a discovered module should be loaded.

        Parameters:
            module_name: Fully qualified module name.

        Returns:
            True when the module should be imported and started.
        """
        if self.is_bootstrapping_node():
            # in this node slips only runs bootstrapping-necessary modules,
            # no detection modules are started.
            if not self.is_bootstrapping_module(module_name):
                return False
        elif self.is_disabled_module(module_name):
            return False
        return True

    def _short_name(self, module_name: str) -> str:
        """
        Get a module's short name from its fully qualified name, e.g.
        "modules.arp.arp" -> "arp". Cheap: no import needed, the
        dir_name == file_name discovery convention guarantees this
        matches the module's Modules enum value.

        Parameters:
            module_name: Fully qualified module name.

        Returns:
            The module's short/directory name.
        """
        return module_name.split(".")[1]

    def get_enabled_module_names(self) -> List[str]:
        """
        Discover the fully qualified names of every module Slips should
        start, in startup order.

        Filtering and ordering only need module *names*, so this never
        imports any module.

        Returns:
            Fully qualified names of the modules to start, in order.
        """
        (
            self.user_disabled_modules,
            self.slips_disabled_modules,
        ) = self.get_disabled_modules()

        enabled_module_names = [
            module_name
            for module_name in self._discover_module_names()
            if self._should_load_module(module_name)
        ]
        return self._reorder_module_names(enabled_module_names)

    def _reorder_module_names(self, module_names: List[str]) -> List[str]:
        """
        Apply module ordering rules before startup.

        Parameters:
            module_names: Fully qualified names of enabled modules.

        Returns:
            Reordered list of fully qualified module names.
        """
        module_names = self._prioritize_blocking_modules(module_names)
        module_names = self._change_cyst_module_order(module_names)
        return module_names

    def _prioritize_blocking_modules(
        self, module_names: List[str]
    ) -> List[str]:
        """
        Move blocking modules to the beginning of the startup order.

        Parameters:
            module_names: Fully qualified names of enabled modules.

        Returns:
            Reordered list of fully qualified module names.
        """
        blocking_module_names = {
            Modules.BLOCKING.value,
            Modules.ARP_POISONER.value,
        }
        if not any(
            self._short_name(module_name) in blocking_module_names
            for module_name in module_names
        ):
            return module_names

        # put the blocking modules at the top to start first
        front = [
            module_name
            for module_name in module_names
            if self._short_name(module_name) in blocking_module_names
        ]
        rest = [
            module_name
            for module_name in module_names
            if self._short_name(module_name) not in blocking_module_names
        ]
        return front + rest

    def _change_cyst_module_order(self, module_names: List[str]) -> List[str]:
        """
        Move the CYST module to the end of the startup order.

        Parameters:
            module_names: Fully qualified names of enabled modules.

        Returns:
            Reordered list of fully qualified module names.
        """
        # when cyst starts first, as soon as slips connects to cyst,
        # cyst sends slips the flows,
        # but the inputprocess didn't even start yet so the flows are lost
        # to fix this, change the order of the CYST module (load it last)
        cyst = [
            module_name
            for module_name in module_names
            if self._short_name(module_name) == Modules.CYST.value
        ]
        if not cyst:
            return module_names

        rest = [
            module_name
            for module_name in module_names
            if self._short_name(module_name) != Modules.CYST.value
        ]
        return rest + cyst

    def _import_module(self, module_name: str) -> Optional[ModuleType]:
        """
        Import a module by name.

        Parameters:
            module_name: Fully qualified module name.

        Returns:
            Imported module, or None when import failed.
        """
        try:
            return importlib.import_module(module_name)
        except ImportError as error:
            print(
                # try to import the module, otherwise return None
                "Something wrong happened while importing the module "
                f"{module_name}: {error}"
            )
            print(traceback.format_exc())
            return None

    def _find_module_class(self, module: ModuleType) -> Optional[type]:
        """
        Find the concrete IModule subclass defined in an imported module.
        The discovery convention (dir_name == file_name) guarantees each
        module file that reaches this point defines exactly one.

        Parameters:
            module: Imported Python module.

        Returns:
            The module's IModule subclass, or None if it doesn't have one.
        """
        for _, member_object in inspect.getmembers(module):
            if inspect.isclass(member_object):
                if issubclass(
                    member_object, IModule
                ) and not self.is_abstract_module(member_object):
                    return member_object
        return None

    def _run_module(
        self,
        module_name: str,
        logger: Any,
        output_dir: str,
        redis_port: int,
        termination_event: Any,
        slips_args: Any,
        conf: Any,
        ppid: int,
        bloom_filters_manager: Any,
    ) -> None:
        """
        Entry point that runs inside a module's own (already forked)
        process. Imports the module and constructs+runs its class here
        instead of in the main process, so every module's import cost
        is paid in parallel across processes instead of serially
        blocking the rest of Slips startup. The module announces its
        own startup once it knows its own description and real PID.

        Parameters:
            module_name: Fully qualified module name to import and run.
            logger, output_dir, redis_port, termination_event,
            slips_args, conf, ppid, bloom_filters_manager: Regular
                IModule constructor arguments.
        """
        imported_module = self._import_module(module_name)
        if imported_module is None:
            return

        module_class = self._find_module_class(imported_module)
        if module_class is None:
            return

        instance = module_class(
            logger,
            output_dir,
            redis_port,
            termination_event,
            slips_args,
            conf,
            ppid,
            bloom_filters_manager,
        )
        # each module announces itself from its own process, so the
        # only way to know how many have started so far is a counter
        # shared through the db, not local process state. uses this
        # module's own db connection - the one on self.main.db was
        # inherited across the fork and isn't safe to share.
        self.announce_started(
            Modules(module_class.name),
            os.getpid(),
            module_class.description,
            instance.db,
        )
        instance.run()

    def set_total_processes_to_start(self, will_load_modules: bool) -> None:
        """
        Compute and cache how many processes slips will start this run,
        detection modules plus the fixed set of core processes and the
        profiler/evidence workers they start, so each one can announce
        itself with an accurate running count. Workers don't get their
        own separate counter - they count towards this same total.
        Must be called before any process/module announces itself.

        Parameters:
            will_load_modules: False when slips was started with a
                .rdb file and skips starting detection modules
                entirely.
        """
        module_count = (
            len(self.get_enabled_module_names()) if will_load_modules else 0
        )
        self.total_processes_to_start = (
            module_count
            + self.NUM_CORE_PROCESSES
            + NUM_INITIAL_PROFILER_WORKERS
            + DEFAULT_EVIDENCE_HANDLER_WORKERS
        )
        # from here until the last process/module announces itself,
        # queue every other printed message instead of letting it
        # interleave with the startup progress report
        self.main.logger.begin_startup_announcements()

    def load_modules(self) -> None:
        """
        Start all enabled modules discovered in the modules directory.
        """
        enabled_module_names = self.get_enabled_module_names()
        for module_name in enabled_module_names:
            short_name = self._short_name(module_name)
            process = Process(
                target=self._run_module,
                name=short_name,
                args=(
                    module_name,
                    self.main.logger,
                    self.main.args.output,
                    self.main.redis_port,
                    self.termination_event,
                    self.main.args,
                    self.main.conf,
                    self.main.pid,
                    self.main.bloom_filters_man,
                ),
            )
            process.start()
            self.main.db.store_pid(short_name, int(process.pid))
