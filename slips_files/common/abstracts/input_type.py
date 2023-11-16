from abc import ABC, abstractmethod


class IInputType(ABC):
    """
    Interface for all input types supported by slips placed in slips_files/core/profiler.py
    """
    @abstractmethod
    def process_line(self, line: str):
        """
        Process all fields of a given line
        """
