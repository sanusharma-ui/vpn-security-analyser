from parsers.packet_parser import PacketParser
from core.normalizer import SignalNormalizer


class SecurityEngine:

    def __init__(self):
        self.packet_parser = PacketParser()
        self.normalizer = SignalNormalizer()

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
                signals.extend(packet_signals)

        normalized = self.normalizer.normalize(
            signals
        )

        return {
            "packets_processed": packet_count,
            "security_packets": relevant_packets,
            "signals": normalized
        }