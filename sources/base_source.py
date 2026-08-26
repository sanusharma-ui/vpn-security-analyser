from abc import ABC, abstractmethod


class BaseSource(ABC):

    @abstractmethod
    def read(self):
        """
        Returns an iterable packet stream.
        """
        pass

    @abstractmethod
    def close(self):
        pass

    def get_source_type(self):
        return self.__class__.__name__