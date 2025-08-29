# SPDX-FileCopyrightText: 2021 Sebastian Garcia <sebastian.garcia@agents.fel.cvut.cz>
# SPDX-License-Identifier: GPL-2.0-only
from abc import ABC, abstractmethod


class IObserver(ABC):
    """
    gets notified whenever an observable has a new msg for it
    """

    @abstractmethod
    def update(self, msg):
        """is called whenever there's a new msg"""
        pass


class IObservable(ABC):
    def __init__(self):
        self.observers = []

    def add_observer(self, observer):
        self.observers.append(observer)

    def remove_observer(self, observer):
        self.observers.remove(observer)

    def notify_observers(self, msg):
        for observer in self.observers:
            observer.update(msg)
