from pathlib import Path

from slips_files.core.database.sqlite_db.t_cell_db import TCellStorage
from tests.module_factory import ModuleFactory


def test_t_cell_storage_creates_store_dir(tmp_path) -> None:
    t_cell = ModuleFactory().create_t_cell_obj()
    t_cell.conf.t_cell_store_dir.return_value = "output/t_cell"
    storage = TCellStorage(
        t_cell.logger,
        t_cell.conf,
        str(tmp_path / "run_output"),
        12345,
    )

    assert Path(storage.store_dir).exists()
    storage.close()
