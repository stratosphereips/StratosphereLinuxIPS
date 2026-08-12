# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
# ConfigMixin groups configuration reads, feature gating, and module
# enable/disable decisions for ProcessManager.
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set

import yaml

from modules.supported_module_names import Modules
from slips_files.common.input_type import InputType


ModuleDependencyMap = Dict[Modules, Tuple[Modules, ...]]


class ConfigMixin:
    """Provide configuration and module selection helpers."""

    def read_config(self) -> None:
        """
        Read process-manager configuration values from the main config.
        """
        self.bootstrapping_modules = self.main.conf.get_bootstrapping_modules()
        self.bootstrapping_node = self.main.conf.read_configuration(
            "global_p2p", "bootstrapping_node", False
        )
        self.use_global_p2p = self.main.conf.read_configuration(
            "global_p2p", "use_global_p2p", False
        )
        self.module_dependencies = self._read_module_dependencies()

    def _read_module_dependencies(self) -> ModuleDependencyMap:
        """
        parses modules/dependencies.yaml

        Returns:
            Mapping of module names to the tuple of modules they depend on.
        """
        dependencies_path = Path("modules") / "dependencies.yaml"
        try:
            with dependencies_path.open(encoding="utf-8") as source:
                dependency_data = yaml.safe_load(source) or {}
        except (FileNotFoundError, TypeError, yaml.YAMLError):
            return {}

        raw_modules = dependency_data.get("modules", {})
        if not isinstance(raw_modules, dict):
            return {}

        module_dependencies: ModuleDependencyMap = {}
        for module_name, module_config in raw_modules.items():
            if not isinstance(module_name, str):
                continue

            supported_module_name = self._convert_to_modules_enum_member(
                module_name
            )
            if not supported_module_name:
                continue

            depends_on: List[Modules] = []
            if isinstance(module_config, dict):
                raw_dependencies = module_config.get("depends_on", [])
                if isinstance(raw_dependencies, list):
                    for dependency in raw_dependencies:
                        if not isinstance(dependency, str):
                            continue

                        stripped_dependency = dependency.strip()
                        if not stripped_dependency:
                            continue

                        supported_dependency = (
                            self._convert_to_modules_enum_member(
                                stripped_dependency
                            )
                        )
                        if supported_dependency:
                            depends_on.append(supported_dependency)

            module_dependencies[supported_module_name] = tuple(depends_on)

        return module_dependencies

    def _reading_flows_from_cyst(self) -> bool:
        """
        Check whether the selected input module is CYST.

        Returns:
            True when CYST is configured as the input module.
        """
        custom_flows = self.main.args.input_module
        return Modules.CYST in str(custom_flows)

    def _normalize_module_name(self, module_name: str) -> str:
        """
        removes _, - and spaces from the given module name, and converts it
        to lowercase
        """
        return (
            module_name.replace(" ", "")
            .replace("_", "")
            .replace("-", "")
            .lower()
        )

    def _convert_to_modules_enum_member(
        self, module_name: str
    ) -> Optional[Modules]:
        """
        converts the given module name to a Modules enum member

        Parameters:
            module_name: Module name from config or runtime input.

        Returns:
            Matching supported module enum value, if one exists.
        """
        normalized_module_name = self._normalize_module_name(module_name)
        for supported_module in Modules:
            if (
                self._normalize_module_name(supported_module)
                == normalized_module_name
            ):
                return supported_module
        return None

    def get_user_disabled_modules(self) -> Set[Modules]:
        """
        Get modules disabled by the user configuration.

        Returns:
            User-disabled module names as supported module enums when
            available, otherwise stripped strings.
        """
        config_user_disabled_modules: List[str] = (
            self.main.conf.read_configuration(
                "modules", "disable", ["template"]
            )
        )
        user_disabled_modules: Set[Modules] = set()
        for module_name in config_user_disabled_modules:
            stripped_module_name: str = module_name.strip()
            supported_module: Modules = self._convert_to_modules_enum_member(
                stripped_module_name
            )
            user_disabled_modules.add(supported_module)

        return user_disabled_modules

    def get_runtime_disabled_modules(self) -> Set[Modules]:
        """
        Get modules disabled by Slips runtime rules.

        Returns:
            Supported module enums disabled by Slips runtime conditions and
            by dependency resolution.
        """
        is_running_non_stop = self.main.db.is_running_non_stop()
        runtime_disabled_modules: Set[Modules] = set()

        if not self._is_exporting_module_enabled():
            runtime_disabled_modules.add(Modules.EXPORTING_ALERTS)

        use_p2p = self.main.conf.use_local_p2p()
        if not (use_p2p and is_running_non_stop):
            runtime_disabled_modules.add(Modules.P2P_TRUST)

        use_global_p2p = self.main.conf.use_global_p2p()
        if not (use_global_p2p and is_running_non_stop):
            runtime_disabled_modules.add(Modules.FIDES)
            runtime_disabled_modules.add(Modules.IRIS)

        if not (
            self.main.conf.send_to_warden()
            or self.main.conf.receive_from_warden()
        ):
            runtime_disabled_modules.add(Modules.CESNET)

        if not (self.main.args.clearblocking or self.main.args.blocking):
            runtime_disabled_modules.add(Modules.BLOCKING)
            runtime_disabled_modules.add(Modules.ARP_POISONER)

        if self.main.input_type != InputType.PCAP:
            runtime_disabled_modules.add(Modules.LEAK_DETECTOR)

        if not self._reading_flows_from_cyst():
            runtime_disabled_modules.add(Modules.CYST)

        dependency_disabled_modules: Set[Modules] = (
            self._get_dependency_disabled_modules(runtime_disabled_modules)
        )

        return runtime_disabled_modules | dependency_disabled_modules

    def _get_dependency_disabled_modules(
        self, runtime_disabled_modules: Set[Modules]
    ) -> Set[Modules]:
        """
        Resolve transitive disables caused by missing module dependencies.

        Parameters:
            runtime_disabled_modules: modules slips decided to disable
            based on runtime rules.

        Returns:
            Set of canonical module names disabled by dependency rules.
        """
        dependency_disabled_modules: Set[Modules] = set()
        all_disabled_modules: Set[Modules] = (
            set(self.user_disabled_modules) | runtime_disabled_modules
        )

        for module in self.module_dependencies:
            if self._has_missing_dependency(module, all_disabled_modules):
                dependency_disabled_modules.add(module)
        self._print_dependency_disabled_modules(
            dependency_disabled_modules, all_disabled_modules
        )

        return dependency_disabled_modules

    def _print_dependency_disabled_modules(
        self,
        dependency_disabled_modules: Set[Modules],
        disabled_modules: Set[Modules],
    ) -> None:
        """
        Print modules disabled because one of their dependencies is disabled.
        """
        if self.disabled_warning_printed:
            return
        if not dependency_disabled_modules:
            return
        self.disabled_warning_printed = True

        disabled_dependencies = "\n".join(
            f"  - {module} -> requires {dependency}"
            for module in sorted(dependency_disabled_modules)
            if (
                dependency := self._get_disabled_dependency(
                    module, disabled_modules
                )
            )
        )
        self.main.print(
            "Warning: The following modules are disabled due"
            " to missing dependencies:\n"
            f"{disabled_dependencies}"
        )

    def _has_missing_dependency(
        self,
        module_name: Modules,
        disabled_modules: Set[Modules],
    ) -> bool:
        """
        Check whether any dependency of the given module is disabled in
        slips.yaml or by slips runtime.

        Parameters:
            module: module name to check its dependencies
            disabled_modules: user and runtime disable modules

        Returns:
            True when at least one dependency is unavailable.
        """
        for dependency in self.module_dependencies[module_name]:
            if dependency in disabled_modules:
                return True

            dependency = dependency.strip().lower()
            enabled = bool(
                self.main.conf.read_configuration(dependency, "enabled", True)
            )
            if not enabled:
                return True

        return False

    def _get_disabled_dependency(
        self,
        module_name: Modules,
        disabled_modules: Set[Modules],
    ) -> Optional[Modules]:
        """
        Get the first disabled dependency for a module.

        Parameters:
            module_name: Module name to inspect.
            disabled_modules: User and runtime disabled modules.

        Returns:
            First disabled dependency that caused the module to be disabled.
        """
        for dependency in self.module_dependencies[module_name]:
            if dependency in disabled_modules:
                return dependency

            enabled = bool(
                self.main.conf.read_configuration(
                    dependency.strip().lower(), "enabled", True
                )
            )
            if not enabled:
                return dependency

        return None

    def get_disabled_modules(
        self,
    ) -> Tuple[Set[Modules], Set[Modules]]:
        """
        returns user-disabled modules and Slips-disabled modules.
        """
        self.user_disabled_modules: Set[Modules] = (
            self.get_user_disabled_modules()
        )
        self.slips_disabled_modules: Set[Modules] = (
            self.get_runtime_disabled_modules()
        )
        return self.user_disabled_modules, self.slips_disabled_modules

    def _is_exporting_module_enabled(self) -> bool:
        """
        Check whether alert exporting is configured.

        Returns:
            True when at least one supported alert exporter is enabled.
        """
        export_to = self.main.conf.export_to()
        return len(export_to) != 0

    def get_user_and_runtime_disabled_modules(self) -> Set[Modules]:
        return self.user_disabled_modules | self.slips_disabled_modules

    def is_disabled_module(self, module_name: str) -> bool:
        """
        Check whether a module is disabled by the user or runtime rules.

        Parameters:
            module_name: Fully qualified module name.

        Returns:
            True when the module is disabled.
        """
        normalized_module_name = self._normalize_module_name(module_name)
        for ignored_module in self.get_user_and_runtime_disabled_modules():
            normalized_ignored_module = self._normalize_module_name(
                ignored_module
            )
            # this version of the module name wont contain
            # _ or spaces so we can
            # easily match it with the ignored module name
            if normalized_ignored_module in normalized_module_name:
                return True
        return False

    def is_bootstrapping_module(self, module_name: str) -> bool:
        """
        Check whether a module is required on a bootstrap node.

        Parameters:
            module_name: Fully qualified module name.

        Returns:
            True when the module should run on a bootstrap node.
        """
        normalized_module_name = self._normalize_module_name(module_name)
        for bootstrap_module in self.bootstrapping_modules:
            normalized_bootstrap_module = self._normalize_module_name(
                bootstrap_module
            )
            if normalized_bootstrap_module in normalized_module_name:
                return True

        disabled_module_name = module_name.split(".")[-1]
        disabled_module = self._convert_to_modules_enum_member(
            disabled_module_name
        )
        if (
            disabled_module
            and disabled_module not in self.slips_disabled_modules
        ):
            self.slips_disabled_modules.append(disabled_module)
        return False

    def is_bootstrapping_node(self) -> bool:
        """
        Check whether this Slips instance should run as a P2P bootstrap node.

        Returns:
            True when both bootstrapping and global P2P are enabled.
        """
        if not self.main.db.is_running_non_stop():
            return False

        return self.bootstrapping_node and self.use_global_p2p
