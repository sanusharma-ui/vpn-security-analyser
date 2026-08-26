import os
import pyshark

from sources.base_source import BaseSource


class PCAPSource(BaseSource):

    def __init__(self, file_path):
        self.file_path = file_path
        self.capture = None

    def read(self):

        if not os.path.exists(self.file_path):
            raise FileNotFoundError(
                f"PCAP file not found: {self.file_path}"
            )

        self.capture = pyshark.FileCapture(
            self.file_path,
            keep_packets=False
        )

        return self.capture

    def close(self):

        if self.capture:
            self.capture.close()