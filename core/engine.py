from parsers.packet_parser import PacketParser

from core.normalizer import SignalNormalizer
from core.session_manager import SessionManager

from analysis.rule_engine import RuleEngine
from analysis.risk_engine import RiskEngine
from analysis.confidence_engine import ConfidenceEngine

from reports.report_builder import ReportBuilder


class SecurityEngine:

    def __init__(self):

        self.packet_parser = PacketParser()

        self.normalizer = SignalNormalizer()

        self.rule_engine = RuleEngine()

        self.risk_engine = RiskEngine()

        self.confidence_engine = (
            ConfidenceEngine()
        )

        self.report_builder = (
            ReportBuilder()
        )

    def analyze(
        self,
        packets,
        source_type="unknown"
    ):

        all_signals = []

        packet_count = 0
        security_packets = 0

        session_manager = (
            SessionManager()
        )

        for packet in packets:

            packet_count += 1

            packet_signals = (
                self.packet_parser.parse(
                    packet,
                    packet_number=packet_count
                )
            )

            if not packet_signals:
                continue

            security_packets += 1

            all_signals.extend(
                packet_signals
            )

            session_manager.ingest(
                packet_signals
            )

        normalized = (
            self.normalizer.normalize(
                all_signals
            )
        )

        findings = (
            self.rule_engine.evaluate(
                normalized
            )
        )

        risk = (
            self.risk_engine.calculate(
                findings
            )
        )

        confidence = (
            self.confidence_engine.calculate(
                normalized
            )
        )

        sessions = (
            session_manager.get_sessions()
        )

        return (
            self.report_builder.build(

                packets_processed=
                    packet_count,

                security_packets=
                    security_packets,

                signals=
                    normalized,

                findings=
                    findings,

                risk=
                    risk,

                confidence=
                    confidence,

                sessions=
                    sessions,

                source_type=
                    source_type
            )
        )