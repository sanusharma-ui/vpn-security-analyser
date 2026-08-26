from core.signal import SecuritySignal


class IKEParser:

    def parse(self, packet):

        signals = []

        if not hasattr(packet, "isakmp"):
            return signals

        layer = packet.isakmp

        signals.append(
            SecuritySignal(
                name="ike_detected",
                value=True,
                source="pcap"
            )
        )

        version = self._get_field(
            layer,
            [
                "version",
                "majorversion",
                "major_version"
            ]
        )

        if version is not None:

            normalized_version = self._normalize_version(version)

            signals.append(
                SecuritySignal(
                    name="ike_version",
                    value=normalized_version,
                    source="pcap"
                )
            )

        return signals

    def _get_field(self, layer, names):

        for name in names:

            try:
                value = layer.get_field_value(name)

                if value is not None:
                    return value

            except Exception:
                continue

        return None

    def _normalize_version(self, value):

        value = str(value).lower()

        if "2" in value:
            return "IKEv2"

        if "1" in value:
            return "IKEv1"

        return value