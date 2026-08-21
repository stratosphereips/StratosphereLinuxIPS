# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from termcolor import colored


def green(txt):
    """
    returns the text in green
    """
    return colored(txt, "green")


def red(txt):
    """
    returns the text in green
    """
    return colored(txt, "red")


def cyan(txt):
    """
    returns the text in green
    """
    return colored(txt, "cyan")


def yellow(txt):
    return colored(txt, "yellow")


def blue(txt):
    """
    returns the text in blue
    """
    return colored(txt, "blue")


def grey(txt):
    """
    returns the text dimmed, used for de-emphasized details
    """
    return colored(txt, "dark_grey")


# width of the label column in slips' startup header lines (Logs, Redis,
# Host IP, Gateway IP..), shared so every line lines up regardless of
# which module prints it
HEADER_LABEL_WIDTH = 12


def header_line(label: str, value) -> str:
    """
    Format one line of slips' startup header: a dim, left-aligned label
    followed by a plain value, e.g. "Redis       localhost:6379".
    """
    return f"{grey(label.ljust(HEADER_LABEL_WIDTH))}{value}"


def separator_line() -> str:
    """
    Build the dim horizontal rule used to divide sections of slips'
    startup output.
    """
    return grey("─" * 35)


def print_separator() -> None:
    """
    Print a dim horizontal rule used to divide sections of slips'
    startup output.
    """
    print(separator_line())
