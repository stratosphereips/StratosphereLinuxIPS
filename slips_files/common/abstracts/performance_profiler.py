from abc import ABC, abstractmethod


class IPerformanceProfiler(ABC):
    @abstractmethod
    def _create_profiler(self):
        pass

    @abstractmethod
    def start(self):
        pass

    @abstractmethod
    def stop(self):
        pass

    @abstractmethod
    def print(self):
        pass
