# Customize --help in argparse.

import os
import sys
import argparse
import textwrap

class ArgumentParser(argparse.ArgumentParser):

    def __init__(self, *args, **kwargs):
        super(ArgumentParser, self).__init__(*args, **kwargs)
        self.program = { key: kwargs[key] for key in kwargs }
        self.options = []

    def add_argument(self, *args, **kwargs):
        super(ArgumentParser, self).add_argument(*args, **kwargs)
        option = {}
        option["flags"] = [ item for item in args ]
        for key in kwargs:
            option[key] = kwargs[key]
        self.options.append(option)

    def print_help(self):
        wrapper = textwrap.TextWrapper(width=160)

        # Print description
        if "description" in self.program:
            print(self.program["description"])
            print()

        # Print usage
        if "usage" in self.program:
            print("Usage: %s" % self.program["usage"])
        else:
            usage = []
            for option in self.options:
                usage += [ "[%s|%s]" % (item, option["metavar"]) if "metavar" in option else "[%s|%s]" % (item, option["dest"].upper()) if "dest" in option else "[%s]" % item for item in option["flags"] ]
            wrapper.initial_indent = "Usage: %s " % os.path.basename(sys.argv[0])
            wrapper.subsequent_indent = len(wrapper.initial_indent) * " "
            output = str.join(" ", usage)
            output = wrapper.fill(output)
            print(output)
        print()

        # Print options
        print("Options:")
        maxlen = 0
        for option in self.options:
            option["flags2"] =" ".join(["|".join([item for item in option["flags"]]), option["metavar"] if "metavar" in option else ""])

            if len(option["flags2"]) > maxlen:
                maxlen = len(option["flags2"])
        for option in self.options:
            template = " %-" + str(maxlen) + "s  | "
            wrapper.initial_indent = template % option["flags2"]
            wrapper.subsequent_indent = len(wrapper.initial_indent) * " "
            if "help" in option and "default" in option:
                output = option["help"]
                output += " (default: '%s')" % option["default"] if isinstance(option["default"], str) else " (default: %s)" % str(option["default"])
                output = wrapper.fill(output)
            elif "help" in option:
                output = option["help"]
                output = wrapper.fill(output)
            elif "default" in option:
                output = "Default: '%s'" % option["default"] if isinstance(option["default"], str) else "Default: %s" % str(option["default"])
                output = wrapper.fill(output)
            else:
                output = wrapper.initial_indent
            print(output)
