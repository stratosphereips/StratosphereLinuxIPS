from pathlib import Path

from slips_files.core.database.sqlite_db.regex_generator_db import (
    RegexGeneratorStorage,
)
from tests.module_factory import ModuleFactory


def test_regex_generator_storage_creates_store_dir(tmp_path) -> None:
    regex_generator = ModuleFactory().create_regex_generator_obj()
    regex_generator.conf.regex_generator_store_dir.return_value = (
        "output/regex_generator"
    )
    storage = RegexGeneratorStorage(
        regex_generator.logger,
        regex_generator.conf,
        str(tmp_path / "run_output"),
        12345,
    )

    assert Path(storage.store_dir).exists()
    storage.close()
