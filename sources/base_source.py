from abc import ABC, abstractmethod


class BaseSource(ABC):

    @abstractmethod
    def read(self):
        pass

    @abstractmethod
    def close(self):
        pass