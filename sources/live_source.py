from sources.base_source import BaseSource


class LiveSource(BaseSource):

    def __init__(
        self,
        interface,
        capture_filter=None,
        display_filter=None
    ):
        self.interface = interface
        self.capture_filter = capture_filter
        self.display_filter = display_filter
        self.capture = None

    def read(self):

        raise NotImplementedError(
            "Live capture adapter is not enabled yet."
        )

    def close(self):

        if self.capture:
            try:
                self.capture.close()
            except Exception:
                pass