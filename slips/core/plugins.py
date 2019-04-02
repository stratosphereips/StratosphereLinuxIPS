# This file is partially based on Viper - https://github.com/botherder/viper

import pkgutil
import inspect
import modules
import importlib

# The template module is loaded from Module.
from slips.common.abstracts import Module

def load_modules():
    """
    Import modules and loads the modules from the 'modules' folder. Is very relative to the starting position of slips
    """

    plugins = dict()

    # Walk recursively through all modules and packages found on the . folder.
    # __path__ is the current path of this python program
    for loader, module_name, ispkg in pkgutil.walk_packages(modules.__path__, modules.__name__ + '.'):
        # If current item is a package, skip.
        if ispkg:
            continue

        # Try to import the module, otherwise skip.
        try:
            # "level specifies whether to use absolute or relative imports. The default is -1 which 
            # indicates both absolute and relative imports will be attempted. 0 means only perform 
            # absolute imports. Positive values for level indicate the number of parent 
            # directories to search relative to the directory of the module calling __import__()."
            module = importlib.import_module(module_name)
        except ImportError as e:
            print("Something wrong happened while importing the module {0}: {1}".format(module_name, e))
            continue

        # Walk through all members of currently imported modules.
        for member_name, member_object in inspect.getmembers(module):
            # Check if current member is a class.
            if inspect.isclass(member_object):
                if issubclass(member_object, Module) and member_object is not Module:
                    plugins[member_object.name] = dict(obj=member_object, description=member_object.description)

    return plugins

__modules__ = load_modules()
