from abc import ABC, abstractmethod


class BaseAIAnalyzer(ABC):

    @abstractmethod
    def analyze(
        self,
        report
    ):
        pass