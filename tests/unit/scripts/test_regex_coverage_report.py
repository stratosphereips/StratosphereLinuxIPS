import pytest

from scripts.regex_coverage_report import (
    filename_from_uri,
    normalize_domain,
    ratio_text,
)
from tests.module_factory import ModuleFactory


@pytest.mark.parametrize(
    "domain, expected",
    [
        ("Example.COM.", "example.com"),
        (" sub.example.org ", "sub.example.org"),
    ],
)
def test_normalize_domain_strips_dot_and_lowercases(
    domain: str, expected: str
) -> None:
    """Verify domain normalization trims common formatting noise.

    Parameters:
        domain: Domain value to normalize.
        expected: Expected normalized domain.

    Return value:
        None.
    """
    module_factory = ModuleFactory()

    assert module_factory
    assert normalize_domain(domain) == expected


@pytest.mark.parametrize(
    "uri, expected",
    [
        ("https://example.com/download/file.exe?x=1", "file.exe"),
        ("/path/no_extension", ""),
    ],
)
def test_filename_from_uri_extracts_only_file_names(
    uri: str, expected: str
) -> None:
    """Verify filenames are extracted only when an extension is present.

    Parameters:
        uri: URI or path to inspect.
        expected: Expected filename value.

    Return value:
        None.
    """
    module_factory = ModuleFactory()

    assert module_factory
    assert filename_from_uri(uri) == expected


def test_ratio_text_formats_none_and_percentages() -> None:
    """Verify ratio formatting handles empty and numeric values.

    Return value:
        None.
    """
    module_factory = ModuleFactory()

    assert module_factory
    assert ratio_text(None) == "n/a"
    assert ratio_text(0.125) == "12.5%"
