# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from managers.process_manager.process_manager import ProcessManager
from tests.module_factory import ModuleFactory


def test_nested_process_manager_module_instantiates_process_manager() -> None:
    process_manager = ModuleFactory().create_process_manager_obj()

    assert isinstance(process_manager, ProcessManager)
    assert process_manager.__class__.__module__ == (
        "managers.process_manager.process_manager"
    )


def test_init_starts_with_unset_live_update_event() -> None:
    process_manager = ModuleFactory().create_process_manager_obj()

    assert process_manager.is_slips_live_updating_event.is_set() is False
