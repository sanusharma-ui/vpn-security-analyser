from datetime import datetime, timezone


class ReportBuilder:

    def build(
        self,
        packets_processed,
        security_packets,
        signals,
        findings,
        risk,
        confidence,
        sessions,
        source_type
    ):

        vpn_detected = bool(
            signals.get(
                "ike_detected"
            )
            or signals.get(
                "ipsec_protocol"
            )
        )

        summary = {

            "vpn_detected": vpn_detected,

            "protocol": (
                "IPsec"
                if vpn_detected
                else None
            ),

            "risk_score":
                risk["score"],

            "security_score":
                risk[
                    "security_score"
                ],

            "risk_level":
                risk["level"],

            "analysis_confidence":
                confidence["score"]
        }

        crypto = {

            "ike_version":
                signals.get(
                    "ike_version"
                ),

            "encryption":
                signals.get(
                    "encryption"
                ),

            "key_length":
                signals.get(
                    "key_length"
                ),

            "prf":
                signals.get(
                    "prf"
                ),

            "integrity":
                signals.get(
                    "integrity"
                ),

            "dh_group":
                signals.get(
                    "dh_group"
                ),

            "dh_group_name":
                signals.get(
                    "dh_group_name"
                )
        }

        protocol_details = {

            "ipsec_protocol":
                signals.get(
                    "ipsec_protocol"
                ),

            "ike_exchanges":
                signals.get(
                    "ike_exchange"
                ),

            "esp_spi":
                signals.get(
                    "esp_spi"
                )
        }

        return {

            "metadata": {

                "engine":
                    "VPN Security Analyzer",

                "engine_version":
                    "0.2.0",

                "generated_at":
                    datetime.now(
                        timezone.utc
                    ).isoformat(),

                "source_type":
                    source_type
            },

            "summary":
                summary,

            "traffic": {

                "packets_processed":
                    packets_processed,

                "security_packets":
                    security_packets
            },

            "crypto":
                crypto,

            "protocol":
                protocol_details,

            "confidence":
                confidence,

            "findings":
                findings,

            "sessions":
                sessions
        }