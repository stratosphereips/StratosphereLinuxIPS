# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
# ModuleLoadingMixin groups module discovery, import, filtering, ordering,
# and startup of detection modules for ProcessManager.
import importlib
import inspect
import pkgutil
import traceback
from collections import OrderedDict
from types import ModuleType
from typing import Any, Dict, Iterator, Optional, Tuple

import modules
from modules.supported_module_names import Modules
from slips_files.common.abstracts.imodule import IModule


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

    def get_modules(self) -> Tuple[PluginMap, int]:
        """
        Discover and load valid modules from the modules package.

        Returns:
            Loaded plugin mapping and number of import failures.
        """
        (
            self.user_disabled_modules,
            self.slips_disabled_modules,
        ) = self.get_disabled_modules()

        plugins: PluginMap = {}
        failed_to_load_modules = 0
        for module_name in self._discover_module_names():
            if not self._should_load_module(module_name):
                continue

            module = self._import_module(module_name)
            if not module:
                failed_to_load_modules += 1
                continue

            plugins = self._load_valid_classes_from_module(module, plugins)

        plugins = self._reorder_modules(plugins)
        return plugins, failed_to_load_modules

    def _reorder_modules(self, plugins: PluginMap) -> PluginMap:
        """
        Apply module ordering rules before startup.

        Parameters:
            plugins: Loaded plugin mapping.

        Returns:
            Reordered plugin mapping.
        """
        plugins = self._prioritize_blocking_modules(plugins)
        plugins = self._change_cyst_module_order(plugins)
        return plugins

    def _discover_module_names(self) -> Iterator[str]:
        """
        Walk recursively through all importable modules in modules/.

        Returns:
            Iterator of module names to consider.
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

    def _load_valid_classes_from_module(
        self, module: ModuleType, plugins: PluginMap
    ) -> PluginMap:
        """
        Load valid IModule subclasses from an imported module.

        Parameters:
            module: Imported Python module.
            plugins: Current plugin mapping.

        Returns:
            Updated plugin mapping.
        """
        for _, member_object in inspect.getmembers(module):
            if inspect.isclass(member_object):
                if issubclass(
                    member_object, IModule
                ) and not self.is_abstract_module(member_object):
                    module_name = Modules(member_object.name)
                    plugins[module_name] = {
                        "obj": member_object,
                        "description": member_object.description,
                    }
        return plugins

    def _prioritize_blocking_modules(self, plugins: PluginMap) -> PluginMap:
        """
        Move blocking modules to the beginning of the startup order.

        Parameters:
            plugins: Loaded plugin mapping.

        Returns:
            Reordered plugin mapping.
        """
        blocking_modules = (Modules.BLOCKING, Modules.ARP_POISONER)
        if not any(module in plugins for module in blocking_modules):
            return plugins

        # put the blocking modules at the top to start first
        ordered = OrderedDict(plugins)
        for module in blocking_modules:
            if module in plugins:
                # last=False to move to the beginning of the dict
                ordered.move_to_end(module, last=False)

        plugins.clear()
        plugins.update(ordered)
        return plugins

    def _change_cyst_module_order(self, plugins: PluginMap) -> PluginMap:
        """
        Move the CYST module to the end of the startup order.

        Parameters:
            plugins: Loaded plugin mapping.

        Returns:
            Reordered plugin mapping.
        """
        if Modules.CYST not in plugins:
            return plugins

        # when cyst starts first, as soon as slips connects to cyst,
        # cyst sends slips the flows,
        # but the inputprocess didn't even start yet so the flows are lost
        # to fix this, change the order of the CYST module (load it last)
        ordered = OrderedDict(plugins)
        # last=True to move to the end of the dict
        ordered.move_to_end(Modules.CYST, last=True)
        plugins.clear()
        plugins.update(ordered)
        return plugins

    def load_modules(self) -> None:
        """
        Start all enabled modules discovered in the modules directory.
        """
        modules_to_call = self.get_modules()[0]
        for module_name in modules_to_call:
            module_class = modules_to_call[module_name]["obj"]
            module = module_class(
                self.main.logger,
                self.main.args.output,
                self.main.redis_port,
                self.termination_event,
                self.main.args,
                self.main.conf,
                self.main.pid,
                self.main.bloom_filters_man,
            )
            module.start()
            self.main.db.store_pid(module_name, int(module.pid))
            self.print_started_module(
                module_name,
                module.pid,
                modules_to_call[module_name]["description"],
            )
