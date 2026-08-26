from core.signal import SecuritySignal


class IPsecParser:

    def parse(self, packet, packet_number=None):

        signals = []

        if hasattr(packet, "esp"):

            layer = packet.esp

            signals.append(
                SecuritySignal(
                    name="ipsec_protocol",
                    value="ESP",
                    source="packet",
                    packet_number=packet_number,
                    category="protocol"
                )
            )

            spi = self._get_field(
                layer,
                "spi"
            )

            if spi:

                signals.append(
                    SecuritySignal(
                        name="esp_spi",
                        value=str(spi),
                        source="packet",
                        packet_number=packet_number,
                        session_id=f"esp-{spi}",
                        category="session"
                    )
                )

            sequence = self._get_field(
                layer,
                "sequence"
            )

            if sequence is not None:

                signals.append(
                    SecuritySignal(
                        name="esp_sequence",
                        value=str(sequence),
                        source="packet",
                        packet_number=packet_number,
                        session_id=f"esp-{spi}" if spi else None,
                        category="session"
                    )
                )

        if hasattr(packet, "ah"):

            signals.append(
                SecuritySignal(
                    name="ipsec_protocol",
                    value="AH",
                    source="packet",
                    packet_number=packet_number,
                    category="protocol"
                )
            )

        return signals

    def _get_field(self, layer, name):

        try:
            return layer.get_field_value(name)
        except Exception:
            return None