"""
Fail if any GitHub Actions workflow references an external action by a
mutable tag or branch instead of a pinned 40-character commit SHA.

This guards against SLP-015 (GitHub Actions use mutable version tags)
regressing: a tag like @v7 can be repointed by the action's owner at any
time, so every external `uses:` reference must be pinned to a full commit
SHA, with the human-readable version kept as a trailing comment.
"""

import re
import sys
from pathlib import Path
from typing import List, Tuple

WORKFLOWS_DIR = Path(".github/workflows")
USES_RE = re.compile(r"^\s*(?:-\s*)?uses:\s*(\S+)")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def find_workflow_files() -> List[Path]:
    """
    Find every workflow and composite/reusable action file under .github/workflows.

    Returns:
        List[Path]: Sorted list of .yml/.yaml files to check.
    """
    files = list(WORKFLOWS_DIR.rglob("*.yml")) + list(
        WORKFLOWS_DIR.rglob("*.yaml")
    )
    return sorted(set(files))


def check_file(path: Path) -> List[Tuple[int, str, str]]:
    """
    Find unpinned external action references in a single workflow file.

    Parameters:
        path: Path to the workflow/action YAML file to check.

    Returns:
        List[Tuple[int, str, str]]: (line number, uses target, reason) for
        every `uses:` reference that is not pinned to a 40-character commit SHA.
    """
    violations = []
    for lineno, line in enumerate(path.read_text().splitlines(), start=1):
        match = USES_RE.match(line)
        if not match:
            continue
        target = match.group(1)

        # local reusable workflows/actions and container image references
        # don't involve a mutable git ref, so they're not in scope here.
        if target.startswith("./") or target.startswith("docker://"):
            continue

        if "@" not in target:
            violations.append((lineno, target, "missing @ref"))
            continue

        ref = target.rsplit("@", 1)[1]
        if not SHA_RE.match(ref):
            violations.append(
                (
                    lineno,
                    target,
                    f"ref '{ref}' is not a 40-character commit SHA",
                )
            )

    return violations


def main() -> None:
    """
    Check every workflow file for unpinned external GitHub Actions and exit
    non-zero if any are found.
    """
    workflow_files = find_workflow_files()
    all_violations = []
    for path in workflow_files:
        for lineno, target, reason in check_file(path):
            all_violations.append(f"{path}:{lineno}: {target} -> {reason}")

    if all_violations:
        print("Found unpinned GitHub Actions (SLP-015 regression):")
        for violation in all_violations:
            print(f"  {violation}")
        print()
        print(
            "Pin every external action to its full 40-character commit SHA, "
            "keeping the version as a trailing comment, e.g.:"
        )
        print(
            "  uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
            " # v7.0.1"
        )
        sys.exit(1)

    print(
        f"All external actions across {len(workflow_files)} workflow "
        "file(s) are pinned to commit SHAs."
    )


if __name__ == "__main__":
    main()
