from parsers.packet_parser import PacketParser
from core.normalizer import SignalNormalizer
from analysis.rule_engine import RuleEngine
from analysis.risk_engine import RiskEngine


class SecurityEngine:

    def __init__(self):

        self.packet_parser = PacketParser()
        self.normalizer = SignalNormalizer()

        self.rule_engine = RuleEngine()
        self.risk_engine = RiskEngine()

    def analyze(self, packets):

        signals = []

        packet_count = 0
        relevant_packets = 0

        for packet in packets:

            packet_count += 1

            packet_signals = self.packet_parser.parse(
                packet
            )

            if packet_signals:

                relevant_packets += 1

                signals.extend(
                    packet_signals
                )

        normalized = self.normalizer.normalize(
            signals
        )

        findings = self.rule_engine.evaluate(
            normalized
        )

        risk = self.risk_engine.calculate(
            findings
        )

        return {
            "packets_processed": packet_count,
            "security_packets": relevant_packets,

            "signals": normalized,

            "risk": risk,

            "findings": findings
        }