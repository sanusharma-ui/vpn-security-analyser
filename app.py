import argparse
import json
import sys

from sources.pcap_source import PCAPSource
from core.engine import SecurityEngine


def parse_args():

    parser = argparse.ArgumentParser(
        description=(
            "IPsec VPN Security Analyzer"
        )
    )

    parser.add_argument(
        "pcap",
        help="Path to PCAP/PCAPNG file"
    )

    parser.add_argument(
        "--output",
        help="Optional JSON report output path"
    )

    return parser.parse_args()


def main():

    args = parse_args()

    source = PCAPSource(
        args.pcap
    )

    engine = SecurityEngine()

    try:

        packets = source.read()

        report = engine.analyze(
            packets,
            source_type="pcap"
        )

        rendered = json.dumps(
            report,
            indent=4,
            ensure_ascii=False
        )

        print(
            "\n=== VPN SECURITY ANALYZER ===\n"
        )

        print(rendered)

        if args.output:

            with open(
                args.output,
                "w",
                encoding="utf-8"
            ) as file:

                file.write(
                    rendered
                )

            print(
                f"\nReport saved to: "
                f"{args.output}"
            )

    except Exception as error:

        print(
            f"\nAnalyzer failed: {error}",
            file=sys.stderr
        )

        sys.exit(1)

    finally:

        source.close()


if __name__ == "__main__":
    main()