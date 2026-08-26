from sources.base_source import BaseSource


class LiveSource(BaseSource):

    def __init__(self, interface):
        self.interface = interface

    def read(self):
        raise NotImplementedError(
            "Live packet source will be implemented later."
        )

    def close(self):
        pass