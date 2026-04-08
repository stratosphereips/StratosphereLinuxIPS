"""Unit tests for output path helpers."""

from slips_files.common.output_paths import (
    DATABASES_DIRNAME,
    get_databases_dir_path_inside_output_dir,
    get_this_db_path_inside_output_dir,
)
from tests.module_factory import ModuleFactory


def test_get_databases_dir_path_inside_output_dir_creates_directory(tmp_path):
    """The databases helper should create and return the output databases directory."""
    module_factory = ModuleFactory()
    assert module_factory is not None

    databases_dir = get_databases_dir_path_inside_output_dir(
        str(tmp_path / "output")
    )

    assert databases_dir.endswith(DATABASES_DIRNAME)
    assert (tmp_path / "output" / DATABASES_DIRNAME).is_dir()


def test_get_output_sqlite_path_joins_filename_under_databases_dir(tmp_path):
    """The sqlite path helper should return a path inside the databases directory."""
    module_factory = ModuleFactory()
    assert module_factory is not None

    sqlite_path = get_this_db_path_inside_output_dir(
        str(tmp_path / "output"), "test.db"
    )

    assert sqlite_path.endswith(f"{DATABASES_DIRNAME}/test.db")
