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
                ),

            "natt_detected":
                bool(signals.get("natt_detected"))
        }

        compliance = {"nist_sp_800_77_rev1": "UNKNOWN", "cnsa_2_0": "UNKNOWN"}

        # Vulnerability Severity Counts
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            if finding.get("status") != "FAIL":
                continue
            sev = finding.get("severity", "info")
            if sev in severity_counts:
                severity_counts[sev] += 1

        return {

            "metadata": {

                "engine":
                    "AI-Powered IPsec VPN Protocol Analyzer",

                "engine_version":
                    "0.6.0",

                "generated_at":
                    datetime.now(
                        timezone.utc
                    ).isoformat(),

                "source_type":
                    source_type
            },

            "summary":
                summary,

            "compliance":
                compliance,

            "vulnerability_counts":
                severity_counts,

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

            "findings": findings,
            "finding_status_counts": {
                status: sum(f.get("status") == status for f in findings)
                for status in ("PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE", "SUSPECTED")
            },

            "sessions":
                sessions
        }