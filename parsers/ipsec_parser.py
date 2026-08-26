from core.signal import SecuritySignal


class IPsecParser:

    def parse(self, packet):

        signals = []

        if hasattr(packet, "esp"):

            signals.append(
                SecuritySignal(
                    name="ipsec_protocol",
                    value="ESP",
                    source="pcap"
                )
            )

            try:
                spi = packet.esp.get_field_value("spi")

                if spi:
                    signals.append(
                        SecuritySignal(
                            name="esp_spi",
                            value=str(spi),
                            source="pcap"
                        )
                    )

            except Exception:
                pass

        if hasattr(packet, "ah"):

            signals.append(
                SecuritySignal(
                    name="ipsec_protocol",
                    value="AH",
                    source="pcap"
                )
            )

        return signals