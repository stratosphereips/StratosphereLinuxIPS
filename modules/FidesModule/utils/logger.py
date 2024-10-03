import json
import threading
from dataclasses import is_dataclass, asdict
from typing import Optional, List, Callable

LoggerPrintCallbacks: List[Callable[[str, str], None]] = [lambda level, msg: print(f'{level}: {msg}')]
"""Set this to custom callback that should be executed when there's new log message.

First parameter is level ('DEBUG', 'INFO', 'WARN', 'ERROR'), second is message to be logged.
"""


class Logger:
    """Logger class used for logging.

    When the application runs as a Slips module, it uses native Slips logging,
    otherwise it uses basic println.
    """

    def __init__(self, name: Optional[str] = None):
        # try to guess the name if it is not set explicitly
        if name is None:
            name = self.__try_to_guess_name()
        self.__name = name

    # this whole method is a hack
    # noinspection PyBroadException
    @staticmethod
    def __try_to_guess_name() -> str:
        # noinspection PyPep8
        try:
            import sys
            # noinspection PyUnresolvedReferences,PyProtectedMember
            name = sys._getframe().f_back.f_code.co_name
            if name is None:
                import inspect
                inspect.currentframe()
                frame = inspect.currentframe()
                frame = inspect.getouterframes(frame, 2)
                name = frame[1][3]
        except:
            name = "logger"
        return name

    def debug(self, message: str, params=None):
        return self.__print('DEBUG', message, params)

    def info(self, message: str, params=None):
        return self.__print('INFO', message, params)

    def warn(self, message: str, params=None):
        return self.__print('WARN', message, params)

    def error(self, message: str, params=None):
        return self.__print('ERROR', message, params)

    def __format(self, message: str, params=None):
        thread = threading.get_ident()
        formatted_message = f"T{thread}: {self.__name} -  {message}"
        if params:
            params = asdict(params) if is_dataclass(params) else params
            formatted_message = f"{formatted_message} {json.dumps(params)}"
        return formatted_message

    def __print(self, level: str, message: str, params=None):
        formatted_message = self.__format(message, params)
        for print_callback in LoggerPrintCallbacks:
            print_callback(level, formatted_message)
