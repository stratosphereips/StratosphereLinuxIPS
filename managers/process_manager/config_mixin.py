# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
# ConfigMixin groups configuration reads, feature gating, and module
# enable/disable decisions for ProcessManager.
from typing import Callable, List, Tuple

from modules.supported_module_names import Modules
from slips_files.common.input_type import InputType


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
        Normalize a module name for fuzzy matching.

        Parameters:
            module_name: Module name to normalize.

        Returns:
            Lower-cased module name without spaces, underscores, or hyphens.
        """
        return (
            module_name.replace(" ", "")
            .replace("_", "")
            .replace("-", "")
            .lower()
        )

    def get_user_disabled_modules(self) -> List[str]:
        """
        Get modules disabled by the user configuration.

        Returns:
            User-disabled module names stripped of surrounding whitespace.
        """
        user_disabled_modules: List[str] = self.main.conf.read_configuration(
            "modules", "disable", ["template"]
        )
        return [module.strip() for module in user_disabled_modules]

    def get_runtime_disabled_modules(self) -> List[str]:
        """
        Get modules disabled by Slips runtime rules.

        Returns:
            Module names disabled by Slips runtime conditions.
        """
        is_running_non_stop = self.main.db.is_running_non_stop()
        slips_disabled_modules: List[str] = []

        if not self._is_exporting_module_enabled():
            slips_disabled_modules.append(Modules.EXPORTING_ALERTS)

        use_p2p = self.main.conf.use_local_p2p()
        if not (use_p2p and is_running_non_stop):
            slips_disabled_modules.append(Modules.P2P_TRUST)

        use_global_p2p = self.main.conf.use_global_p2p()
        if not (use_global_p2p and is_running_non_stop):
            slips_disabled_modules.extend((Modules.FIDES, Modules.IRIS))

        if not (
            self.main.conf.send_to_warden()
            or self.main.conf.receive_from_warden()
        ):
            slips_disabled_modules.append(Modules.CESNET)

        if not (self.main.args.clearblocking or self.main.args.blocking):
            slips_disabled_modules.extend(
                (Modules.BLOCKING, Modules.ARP_POISONER)
            )

        if self.main.input_type != InputType.PCAP:
            slips_disabled_modules.append(Modules.LEAK_DETECTOR)

        if not self._reading_flows_from_cyst():
            slips_disabled_modules.append(Modules.CYST)

        if not self._is_llm_proxy_enabled_and_configured():
            self._warn_about_llm_dependency_misconfiguration()
            for module in (
                Modules.LLM_PROXY,
                Modules.T_CELL,
                Modules.ALERT_SUMMARY,
                Modules.REGEX_GENERATOR,
            ):
                slips_disabled_modules.append(module)

        return slips_disabled_modules

    def _is_llm_proxy_enabled_and_configured(self) -> bool:
        """
        Check whether llm_proxy is enabled and has backend configuration.

        Returns:
            True when llm_proxy is enabled and at least one backend is
            configured.
        """
        backends = self.main.conf.llm_backends()
        if not isinstance(backends, dict):
            return False

        return self.main.conf.llm_enabled() and any(
            isinstance(alias, str) and alias.strip()
            for alias in backends.keys()
        )

    def _get_enabled_llm_dependent_modules(self) -> List[str]:
        """
        Get enabled modules that rely on llm_proxy configuration.

        Returns:
            Enabled modules that depend on llm_proxy.
        """
        enabled_modules: List[str] = []
        # these modules wont be able to work without the llm proxy
        # configuration
        llm_dependents: Tuple[Tuple[str, Callable[[], bool]], ...] = (
            (
                Modules.ALERT_SUMMARY,
                self.main.conf.alert_summary_enabled,
            ),
            (
                Modules.REGEX_GENERATOR,
                self.main.conf.regex_generator_enabled,
            ),
            (Modules.T_CELL, self.main.conf.t_cell_enabled),
        )

        for module_name, is_enabled in llm_dependents:
            if is_enabled():
                enabled_modules.append(module_name)

        return enabled_modules

    def _warn_about_llm_dependency_misconfiguration(self) -> None:
        """
        Warn once when LLM-dependent modules are enabled without llm_proxy.
        """
        if self.llm_dependency_warning_printed:
            return

        enabled_modules = self._get_enabled_llm_dependent_modules()
        if not enabled_modules:
            return

        self.main.print(
            "Warning: The following modules are enabled in the config, "
            "but llm_proxy is not enabled and configured: "
            f"{enabled_modules}"
        )
        self.llm_dependency_warning_printed = True

    def get_disabled_modules(self) -> Tuple[List[str], List[str]]:
        """
        Get user-disabled modules and Slips-disabled modules.

        Returns:
            User-disabled modules and modules disabled by runtime rules.
        """
        return (
            self.get_user_disabled_modules(),
            self.get_runtime_disabled_modules(),
        )

    def _is_exporting_module_enabled(self) -> bool:
        """
        Check whether alert exporting is configured.

        Returns:
            True when at least one supported alert exporter is enabled.
        """
        export_to = self.main.conf.export_to()
        return len(export_to) != 0

    def get_all_disabled_modules(self) -> List[str]:
        """
        Get all disabled modules as a single list.

        Returns:
            User-disabled modules followed by Slips-disabled modules.
        """
        return list(
            set(self.user_disabled_modules + self.slips_disabled_modules)
        )

    def is_disabled_module(self, module_name: str) -> bool:
        """
        Check whether a module is disabled by the user or runtime rules.

        Parameters:
            module_name: Fully qualified module name.

        Returns:
            True when the module is disabled.
        """
        normalized_module_name = self._normalize_module_name(module_name)
        for ignored_module in self.get_all_disabled_modules():
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

        disabled_module = module_name.split(".")[-1]
        if disabled_module not in self.slips_disabled_modules:
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
