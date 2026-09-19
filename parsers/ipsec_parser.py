from core.signal import SecuritySignal
from parsers.context import endpoints


class IPsecParser:

    def parse(self, packet, packet_number=None):

        signals = []
        src, dst = endpoints(packet)
        has_esp = hasattr(packet, "esp")
        has_ah = hasattr(packet, "ah")

        # Check for NAT-Traversal UDP encapsulation (UDP port 4500)
        if hasattr(packet, "udp"):
            try:
                srcport = str(packet.udp.get_field_value("srcport"))
                dstport = str(packet.udp.get_field_value("dstport"))
                if srcport == "4500" or dstport == "4500":
                    signals.append(
                        SecuritySignal(
                            name="natt_detected",
                            value=True,
                            source="packet",
                            packet_number=packet_number,
                            category="protocol"
                        )
                    )
            except Exception:
                pass

        if has_esp:
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

            spi = self._get_field(layer, "spi")
            spi_str = str(spi) if spi else None

            if spi_str:
                signals.append(
                    SecuritySignal(
                        name="esp_spi",
                        value=spi_str,
                        source="packet",
                        packet_number=packet_number,
                        session_id=f"esp:{src}>{dst}:{spi_str}",
                        category="session"
                    )
                )

            seq_raw = self._get_field(layer, "sequence")
            if seq_raw is not None:
                signals.append(
                    SecuritySignal(
                        name="esp_sequence",
                        value=str(seq_raw),
                        source="packet",
                        packet_number=packet_number,
                        session_id=f"esp:{src}>{dst}:{spi_str}" if spi_str else None,
                        category="session"
                    )
                )

                try:
                    seq_int = int(str(seq_raw), 0)
                    signals.append(
                        SecuritySignal(
                            name="esp_sequence_int",
                            value=seq_int,
                            source="packet",
                            packet_number=packet_number,
                            session_id=f"esp:{src}>{dst}:{spi_str}" if spi_str else None,
                            category="session"
                        )
                    )
                    # Detect potential sequence number rollover risk (> 4 billion without ESN)
                    if seq_int > 4_000_000_000:
                        signals.append(
                            SecuritySignal(
                                name="sequence_rollover_risk",
                                value=True,
                                source="packet",
                                packet_number=packet_number,
                                session_id=f"esp:{src}>{dst}:{spi_str}" if spi_str else None,
                                category="vulnerability"
                            )
                        )
                except Exception:
                    pass

        if has_ah:
            layer = packet.ah
            signals.append(
                SecuritySignal(
                    name="ipsec_protocol",
                    value="AH",
                    source="packet",
                    packet_number=packet_number,
                    category="protocol"
                )
            )

            spi = self._get_field(layer, "spi")
            if spi:
                signals.append(
                    SecuritySignal(
                        name="ah_spi",
                        value=str(spi),
                        source="packet",
                        packet_number=packet_number,
                        session_id=f"ah:{src}>{dst}:{spi}",
                        category="session"
                    )
                )

            # Security Check: AH provides integrity and authentication but NO confidentiality
            if not has_esp:
                signals.append(
                    SecuritySignal(
                        name="ah_without_esp",
                        value=True,
                        source="packet",
                        packet_number=packet_number,
                        session_id=f"ah:{src}>{dst}:{spi}" if spi else None,
                        category="vulnerability"
                    )
                )

        for signal in signals:
            if signal.session_id is None:
                if has_esp and spi_str:
                    signal.session_id = f"esp:{src}>{dst}:{spi_str}"
                elif has_ah and spi:
                    signal.session_id = f"ah:{src}>{dst}:{spi}"
        return signals

    def _get_field(self, layer, name):
        try:
            return layer.get_field_value(name)
        except Exception:
            return None