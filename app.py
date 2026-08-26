import sys
import json

from sources.pcap_source import PCAPSource
from core.engine import SecurityEngine


def main():

    if len(sys.argv) < 2:
        print("Usage:")
        print("python app.py <pcap_file>")
        return

    file_path = sys.argv[1]

    source = PCAPSource(file_path)

    engine = SecurityEngine()

    try:

        packets = source.read()

        result = engine.analyze(
            packets
        )

        print("\n=== VPN SECURITY ANALYZER ===\n")

        print(
            json.dumps(
                result,
                indent=4
            )
        )

    finally:
        source.close()


if __name__ == "__main__":
    main()