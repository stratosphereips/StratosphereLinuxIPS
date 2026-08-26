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


def light_yellow(txt):
    return colored(txt, "light_yellow")


def normal(txt):
    return txt


def light_magenta(txt):
    return colored(txt, "light_magenta")


def blue(txt):
    """
    returns the text in blue
    """
    return colored(txt, "blue")


def navy_blue(txt):
    """
    returns the text in a vivid dodger blue, bright enough to stay
    readable on a black terminal background
    """
    return colored(txt, (30, 144, 255))


def grey(txt):
    """
    returns the text dimmed, used for de-emphasized details
    """
    return colored(txt, "dark_grey")


def purple(txt):
    """
    returns the text in a bright neon purple
    """
    return colored(txt, (191, 0, 255))


def pink(txt):
    """
    returns the text in a bright neon pink
    """
    return colored(txt, (255, 20, 147))


def orange(txt):
    """
    returns the text in a bright neon orange
    """
    return colored(txt, (255, 140, 0))


def neon_green(txt):
    """
    returns the text in a bright neon green
    """
    return colored(txt, (57, 255, 20))


def electric_blue(txt):
    """
    returns the text in a bright neon/electric blue
    """
    return colored(txt, (31, 224, 255))


def neon_yellow(txt):
    """
    returns the text in a bright neon yellow
    """
    return colored(txt, (255, 255, 20))


def neon_red(txt):
    """
    returns the text in a bright neon red
    """
    return colored(txt, (255, 8, 0))


def hot_magenta(txt):
    """
    returns the text in a bright neon magenta
    """
    return colored(txt, (255, 0, 230))


def electric_lime(txt):
    """
    returns the text in a bright neon lime
    """
    return colored(txt, (204, 255, 0))


def neon_teal(txt):
    """
    returns the text in a bright neon teal
    """
    return colored(txt, (0, 255, 209))


def electric_violet(txt):
    """
    returns the text in a bright neon violet
    """
    return colored(txt, (143, 0, 255))


def neon_coral(txt):
    """
    returns the text in a bright neon coral
    """
    return colored(txt, (255, 83, 73))


def laser_lemon(txt):
    """
    returns the text in a bright neon lemon
    """
    return colored(txt, (255, 250, 100))


def pastel_pink(txt):
    """
    returns the text in a soft pastel pink
    """
    return colored(txt, (255, 182, 193))


def pastel_blue(txt):
    """
    returns the text in a soft pastel blue
    """
    return colored(txt, (174, 214, 241))


def pastel_purple(txt):
    """
    returns the text in a soft pastel purple
    """
    return colored(txt, (216, 191, 216))


def pastel_yellow(txt):
    """
    returns the text in a soft pastel yellow
    """
    return colored(txt, (255, 253, 150))


def neon_fuchsia(txt):
    """
    returns the text in a bright neon fuchsia
    """
    return colored(txt, (255, 20, 163))


def leaf_green(txt):
    """
    returns the text in a deep leaf green
    """
    return colored(txt, (34, 197, 94))


def pastel_green(txt):
    """
    returns the text in a soft pastel green
    """
    return colored(txt, (119, 221, 119))


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
