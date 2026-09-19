import argparse
import json
import sys
from pathlib import Path
from sources.pcap_source import PCAPSource
from sources.live_source import LiveSource
from core.engine import SecurityEngine
from ai.ai_explainer import GeminiExplainer


def positive_int(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def positive_float(value):
    import math
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be finite and positive")
    return number


def parse_args():
    parser = argparse.ArgumentParser(description="IPsec VPN security assessment; engine-controlled findings and scores")
    parser.add_argument("pcap", nargs="?", help="PCAP/PCAPNG input")
    parser.add_argument("--live", metavar="INTERFACE", help="Capture interface, or 'default'")
    parser.add_argument("--list-interfaces", action="store_true")
    parser.add_argument("--count", type=positive_int, help="Live packet limit")
    parser.add_argument("--timeout", type=positive_float, help="Live capture duration in seconds, including idle periods")
    parser.add_argument("--update-interval", type=positive_float, default=2, help="Live report interval in seconds")
    parser.add_argument("--updates-jsonl", help="Write live snapshots as JSON lines")
    parser.add_argument("--output", help="Save final JSON report")
    parser.add_argument("--explain", action="store_true", help="Send sanitized engine findings to Gemini for optional explanations")
    args = parser.parse_args()
    if not args.list_interfaces:
        if bool(args.pcap) == bool(args.live):
            parser.error("Specify exactly one PCAP input or --live interface")
        if not args.live and (args.count or args.timeout or args.updates_jsonl):
            parser.error("--count, --timeout and --updates-jsonl require --live")
        paths = [Path(p).resolve() for p in (args.pcap, args.output, args.updates_jsonl) if p]
        if len(paths) != len(set(paths)):
            parser.error("Input, final report and live update paths must differ")
    return args


def print_executive_summary(report, stream=sys.stdout):
    summary = report["summary"]
    score = summary["security_score"]
    print(f"Security: {score if score is not None else 'UNKNOWN'} | Risk: {summary['risk_level']} | "
          f"Coverage: {summary.get('assessment_coverage', 0)}% | {summary.get('assessment_status', 'UNKNOWN')}", file=stream)
    print(f"Packets: {report['traffic']['packets_processed']} | Retained SAs: {len(report['sessions'])} | "
          f"Findings: {len(report['findings'])}", file=stream)


def write_report(path, report):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")


def main():
    args = parse_args()
    if args.list_interfaces:
        try:
            for interface in LiveSource.list_interfaces():
                print(f"{interface['index']}: {interface['name']}")
            return 0
        except RuntimeError as err:
            print(str(err), file=sys.stderr)
            return 1
    source_type = "live" if args.live else "pcap"
    source = LiveSource(interface=None if args.live == "default" else args.live,
                        packet_count=args.count, timeout=args.timeout) if args.live else PCAPSource(args.pcap)
    engine = SecurityEngine()
    updates = None
    exit_code = 0
    try:
        if args.updates_jsonl:
            target = Path(args.updates_jsonl)
            target.parent.mkdir(parents=True, exist_ok=True)
            updates = target.open("w", encoding="utf-8")
        def publish(report):
            report["traffic"].update(queue_drops=source.queue_drops, capture_status=source.status)
            print_executive_summary(report, stream=sys.stderr)
            if updates:
                updates.write(json.dumps(report) + "\n")
                updates.flush()
        try:
            report = engine.analyze(source.read(), source_type=source_type,
                on_update=publish if args.live else None, update_interval=args.update_interval)
        except Exception as err:
            report = engine.snapshot(source_type)
            report["metadata"].update(incomplete=True, error=str(err))
            exit_code = 1
        finally:
            source.close()
        if args.live:
            publish(report)
        # At most one provider call, after capture has stopped. Never blocks packet ingestion.
        if args.explain:
            report["ai_explanation"] = GeminiExplainer().analyze(report)
        print_executive_summary(report, stream=sys.stderr)
        print(json.dumps(report, indent=2, ensure_ascii=False))
        if args.output:
            write_report(args.output, report)
    except Exception as err:
        print(f"Analyzer failed: {err}", file=sys.stderr)
        exit_code = 1
    finally:
        if updates:
            updates.close()
        source.close()
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
