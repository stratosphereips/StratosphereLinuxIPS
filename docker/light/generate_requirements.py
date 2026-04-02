#!/usr/bin/env python3
"""Generate docker/light/requirements.txt from install/requirements.txt
with excluding docker/light/excluded_libs.txt."""

from __future__ import annotations

from pathlib import Path
import re


ROOT_DIR = Path(__file__).resolve().parents[2]
SOURCE_FILE = ROOT_DIR / "install" / "requirements.txt"
EXCLUDED_FILE = ROOT_DIR / "docker" / "light" / "excluded_libs.txt"
OUTPUT_FILE = ROOT_DIR / "docker" / "light" / "requirements.txt"

VERSION_SEPARATORS = ("==", ">=", "<=", "~=", "!=", ">", "<", "===")
NAME_SPLIT_RE = re.compile(r"[\s\[@;]")


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def extract_requirement_name(line: str) -> str | None:
    requirement = line.strip()
    if not requirement or requirement.startswith("#"):
        return None
    if requirement.startswith(("-r", "--requirement")):
        return None
    if requirement.startswith(("-c", "--constraint")):
        return None
    if requirement.startswith(("-", "--")):
        return None
    if "#egg=" in requirement:
        return requirement.rsplit("#egg=", maxsplit=1)[-1].strip() or None

    name_part = requirement
    for separator in VERSION_SEPARATORS:
        if separator in name_part:
            name_part = name_part.split(separator, maxsplit=1)[0]
            break

    name_part = NAME_SPLIT_RE.split(name_part, maxsplit=1)[0]
    return name_part.strip() or None


def load_excluded_names() -> set[str]:
    excluded_names = set()
    for raw_line in EXCLUDED_FILE.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        excluded_names.add(normalize_name(line))
    return excluded_names


def main() -> None:
    excluded_names = load_excluded_names()
    filtered_lines = []

    for raw_line in SOURCE_FILE.read_text().splitlines():
        requirement_name = extract_requirement_name(raw_line)
        if (
            requirement_name
            and normalize_name(requirement_name) in excluded_names
        ):
            continue
        filtered_lines.append(raw_line)

    OUTPUT_FILE.write_text("\n".join(filtered_lines) + "\n")


if __name__ == "__main__":
    main()
