"""Start modules with only configuration and IPC state crossing processes."""

import os
from multiprocessing import Process, Value
from typing import Any

from slips_files.common.startup_report import format_started_line


class ModuleProcess(Process):
    """Construct a module in its child, where its threads and databases live."""

    def __init__(
        self,
        module: type | str,
        *args: Any,
        startup_total: int = 0,
        **kwargs: Any,
    ) -> None:
        """Save construction arguments without initializing module resources.

        Parameters:
            module: Core class or import path of a detection module.
            args: Positional module constructor arguments.
            startup_total: Detection startup announcement total, or zero.
            kwargs: Keyword module constructor arguments.
        """
        name = (
            module.split(".")[-1] if isinstance(module, str) else module.name
        )
        super().__init__(name=name)
        self.module = module
        self.module_args = args
        self.module_kwargs = kwargs
        self.startup_total = startup_total
        self.description = getattr(module, "description", "")
        self._received_lines = Value("Q", 0)

    @property
    def received_lines(self) -> int:
        """Return the worker's shared count of consumed input lines."""
        return self._received_lines.value

    def run(self) -> None:
        """Initialize and run the module entirely inside this process."""
        module_class = self.module
        if isinstance(module_class, str):
            from managers.process_manager.module_loading_mixin import (
                ModuleLoadingMixin,
            )

            loader = ModuleLoadingMixin()
            imported = loader._import_module(module_class)
            if imported is None:
                raise ImportError(f"Cannot load {module_class}")
            module_class = loader._find_module_class(imported)
            if module_class is None:
                raise ImportError(f"No detection module in {self.module}")

        instance = module_class(*self.module_args, **self.module_kwargs)
        if instance.name.startswith("profiler_worker_process_"):
            instance._received_lines = self._received_lines
        if self.startup_total:
            count = instance.db.increment_modules_started_count()
            instance.print(
                format_started_line(
                    module_class.name,
                    count,
                    self.startup_total,
                    os.getpid(),
                    module_class.description,
                    category="module",
                ),
                1,
                0,
                suppress_sender=True,
                is_final_startup_announcement=count >= self.startup_total,
            )
        instance.run()
