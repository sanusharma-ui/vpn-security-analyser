import argparse
import json
import sys

from sources.pcap_source import PCAPSource
from sources.live_source import LiveSource
from core.engine import SecurityEngine


def parse_args():

    parser = argparse.ArgumentParser(
        description="AI-Powered IPsec VPN Protocol Analyzer & Security Assessment Framework"
    )

    parser.add_argument(
        "pcap",
        nargs="?",
        default=None,
        help="Path to PCAP/PCAPNG capture file to analyze"
    )

    parser.add_argument(
        "--live",
        metavar="INTERFACE",
        help="Capture live packets from specified network interface (or 'default')"
    )

    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List all network interfaces available for live capture"
    )

    parser.add_argument(
        "--count",
        type=int,
        default=None,
        help="Number of packets to capture in live mode"
    )

    parser.add_argument(
        "--output",
        help="Optional file path to export full JSON security report"
    )

    return parser.parse_args()


def print_executive_summary(report):
    summary = report.get("summary", {})
    compliance = report.get("compliance", {})
    vulns = report.get("vulnerability_counts", {})
    traffic = report.get("traffic", {})
    crypto = report.get("crypto", {})

    print("\n" + "=" * 70)
    print("      AI-POWERED IPSEC VPN PROTOCOL SECURITY ASSESSMENT")
    print("=" * 70)
    print(f" Protocol Detected     : {summary.get('protocol') or 'None'}")
    print(f" Security Score        : {summary.get('security_score')}/100")
    print(f" Risk Score & Level    : {summary.get('risk_score')}/100 [{summary.get('risk_level')}]")
    print(f" Analysis Confidence   : {summary.get('analysis_confidence')}%")
    print("-" * 70)
    print(f" Packets Analyzed      : {traffic.get('packets_processed', 0)} (VPN Security Packets: {traffic.get('security_packets', 0)})")
    print(f" IKE Version / Cipher  : {crypto.get('ike_version')} | {crypto.get('encryption')} ({crypto.get('key_length')} bits)")
    print(f" PRF / Key-Exchange    : {crypto.get('prf')} | {crypto.get('dh_group_name')}")
    print("-" * 70)
    print(" COMPLIANCE AUDIT:")
    print(f"  • NIST SP 800-77 Rev 1: [{compliance.get('nist_sp_800_77_rev1', 'UNKNOWN')}]")
    print(f"  • CNSA Suite 2.0      : [{compliance.get('cnsa_2_0', 'UNKNOWN')}]")
    print("-" * 70)
    print(" VULNERABILITY FINDINGS:")
    print(f"  • CRITICAL: {vulns.get('critical', 0)}  |  HIGH: {vulns.get('high', 0)}  |  MEDIUM: {vulns.get('medium', 0)}  |  LOW: {vulns.get('low', 0)}")
    print("=" * 70 + "\n")


def main():

    args = parse_args()

    if args.list_interfaces:
        interfaces = LiveSource.list_interfaces()
        print("\n=== AVAILABLE NETWORK INTERFACES FOR LIVE CAPTURE ===\n")
        if not interfaces:
            print("No interfaces found. Ensure Wireshark/Npcap is installed.")
        else:
            for iface in interfaces:
                print(f" [{iface['index']}] {iface['name']}")
        print()
        sys.exit(0)

    if not args.pcap and not args.live:
        print("Error: Specify either a PCAP file or use --live <INTERFACE>.", file=sys.stderr)
        print("Run with --help or --list-interfaces for assistance.", file=sys.stderr)
        sys.exit(1)

    source = None
    source_type = "pcap"

    if args.live:
        source_type = "live"
        iface = None if args.live.lower() == "default" else args.live
        print(f"\n[*] Starting live capture on interface '{args.live}'...")
        print("[*] BPF Filter: udp port 500 or udp port 4500 or esp or ah")
        if args.count:
            print(f"[*] Capturing up to {args.count} packets...")
        source = LiveSource(interface=iface, packet_count=args.count)
    else:
        source = PCAPSource(args.pcap)

    engine = SecurityEngine()

    try:
        packets = source.read()
        report = engine.analyze(packets, source_type=source_type)

        print_executive_summary(report)

        rendered = json.dumps(report, indent=4, ensure_ascii=False)
        print(rendered)

        if args.output:
            with open(args.output, "w", encoding="utf-8") as file:
                file.write(rendered)
            print(f"\n[+] Full security report successfully saved to: {args.output}")

    except Exception as error:
        print(f"\n[!] Analyzer failed: {error}", file=sys.stderr)
        sys.exit(1)

    finally:
        if source:
            source.close()


if __name__ == "__main__":
    main()