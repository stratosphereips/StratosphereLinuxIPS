import os


DATABASES_DIRNAME = "databases"


def get_output_databases_dir(output_dir: str) -> str:
    databases_dir = os.path.join(output_dir or ".", DATABASES_DIRNAME)
    os.makedirs(databases_dir, exist_ok=True)
    return databases_dir


def get_output_sqlite_path(output_dir: str, filename: str) -> str:
    return os.path.join(get_output_databases_dir(output_dir), filename)
