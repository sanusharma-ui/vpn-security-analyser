from config.security_baseline import SECURITY_BASELINE


class RuleEngine:

    def __init__(
        self,
        baseline=None
    ):

        self.baseline = (
            baseline
            or SECURITY_BASELINE
        )

    def evaluate(
        self,
        signals
    ):

        findings = []

        self._check_ike(
            signals,
            findings
        )

        self._check_ike_exchange_and_mode(
            signals,
            findings
        )

        self._check_encryption(
            signals,
            findings
        )

        self._check_key_length(
            signals,
            findings
        )

        self._check_nonce_entropy(
            signals,
            findings
        )

        self._check_prf(
            signals,
            findings
        )

        self._check_integrity(
            signals,
            findings
        )

        self._check_dh(
            signals,
            findings
        )

        self._check_ipsec_protocol(
            signals,
            findings
        )

        self._check_replay_and_rollover(
            signals,
            findings
        )

        self._check_compliance(
            signals,
            findings
        )

        return findings

    def _add(
        self,
        findings,
        rule_id,
        parameter,
        value,
        severity,
        message,
        recommendation=None
    ):

        findings.append({

            "rule_id": rule_id,

            "parameter": parameter,

            "value": value,

            "severity": severity,

            "message": message,

            "recommendation":
                recommendation
        })

    def _single(self, value):

        if isinstance(value, list):

            if not value:
                return None

            return value[0]

        return value

    def _check_ike(
        self,
        signals,
        findings
    ):

        value = self._single(
            signals.get(
                "ike_version"
            )
        )

        if value is None:

            self._add(
                findings,
                "IKE-001",
                "ike_version",
                None,
                "medium",
                "IKE version could not be determined."
            )

            return

        if value in self.baseline[
            "ike_versions"
        ]["preferred"]:

            self._add(
                findings,
                "IKE-002",
                "ike_version",
                value,
                "info",
                "Preferred IKE version detected."
            )

            return

        if value in self.baseline[
            "ike_versions"
        ]["legacy"]:

            self._add(
                findings,
                "IKE-003",
                "ike_version",
                value,
                "high",
                "Legacy IKE version detected.",
                "Migrate to IKEv2."
            )

            return

        self._add(
            findings,
            "IKE-004",
            "ike_version",
            value,
            "medium",
            "Unknown IKE version."
        )

    def _check_encryption(
        self,
        signals,
        findings
    ):

        value = self._single(
            signals.get(
                "encryption"
            )
        )

        if value is None:

            self._add(
                findings,
                "ENC-001",
                "encryption",
                None,
                "medium",
                "Encryption algorithm could not be determined."
            )

            return

        policy = self.baseline[
            "encryption"
        ]

        if value in policy[
            "preferred"
        ]:

            self._add(
                findings,
                "ENC-002",
                "encryption",
                value,
                "info",
                "Preferred encryption algorithm detected."
            )

        elif value in policy[
            "acceptable"
        ]:

            self._add(
                findings,
                "ENC-003",
                "encryption",
                value,
                "low",
                "Encryption is acceptable but not preferred."
            )

        elif value in policy[
            "weak"
        ]:

            self._add(
                findings,
                "ENC-004",
                "encryption",
                value,
                "critical",
                "Weak encryption algorithm detected.",
                "Replace with an approved modern cipher."
            )

        else:

            self._add(
                findings,
                "ENC-005",
                "encryption",
                value,
                "medium",
                "Encryption algorithm is not recognized by the baseline."
            )

    def _check_key_length(
        self,
        signals,
        findings
    ):

        value = self._single(
            signals.get(
                "key_length"
            )
        )

        if value is None:

            self._add(
                findings,
                "KEY-001",
                "key_length",
                None,
                "low",
                "Encryption key length could not be determined."
            )

            return

        minimum = self.baseline[
            "minimum_key_length"
        ]

        preferred = self.baseline[
            "preferred_key_length"
        ]

        if value >= preferred:

            severity = "info"

            message = (
                "Preferred encryption "
                "key length detected."
            )

        elif value >= minimum:

            severity = "low"

            message = (
                "Encryption key length "
                "meets minimum baseline."
            )

        else:

            severity = "high"

            message = (
                "Encryption key length "
                "is below baseline."
            )

        self._add(
            findings,
            "KEY-002",
            "key_length",
            value,
            severity,
            message
        )

    def _check_prf(
        self,
        signals,
        findings
    ):

        value = self._single(
            signals.get("prf")
        )

        if value is None:

            self._add(
                findings,
                "PRF-001",
                "prf",
                None,
                "medium",
                "PRF could not be determined."
            )

            return

        policy = self.baseline[
            "prf"
        ]

        if value in policy[
            "preferred"
        ]:

            severity = "info"
            message = "Preferred PRF detected."

        elif value in policy[
            "legacy"
        ]:

            severity = "high"
            message = "Legacy PRF detected."

        else:

            severity = "medium"
            message = "Unknown PRF."

        self._add(
            findings,
            "PRF-002",
            "prf",
            value,
            severity,
            message
        )

    def _check_integrity(
        self,
        signals,
        findings
    ):

        encryption = self._single(
            signals.get(
                "encryption"
            )
        )

        integrity = self._single(
            signals.get(
                "integrity"
            )
        )

        if (
            encryption
            and "GCM" in encryption
        ):

            self._add(
                findings,
                "INT-001",
                "integrity",
                "AEAD",
                "info",
                "Integrity protection is provided by the AEAD encryption mode."
            )

            return

        if integrity is None:

            self._add(
                findings,
                "INT-002",
                "integrity",
                None,
                "medium",
                "Integrity algorithm could not be determined."
            )

            return

        policy = self.baseline[
            "integrity"
        ]

        if integrity in policy[
            "preferred"
        ]:

            severity = "info"

            message = (
                "Preferred integrity "
                "algorithm detected."
            )

        elif integrity in policy[
            "legacy"
        ]:

            severity = "high"

            message = (
                "Legacy integrity "
                "algorithm detected."
            )

        else:

            severity = "medium"

            message = (
                "Integrity algorithm "
                "is not recognized."
            )

        self._add(
            findings,
            "INT-003",
            "integrity",
            integrity,
            severity,
            message
        )

    def _check_dh(
        self,
        signals,
        findings
    ):

        value = self._single(
            signals.get(
                "dh_group"
            )
        )

        if value is None:

            self._add(
                findings,
                "DH-001",
                "dh_group",
                None,
                "medium",
                "Key-exchange group could not be determined."
            )

            return

        policy = self.baseline[
            "dh_groups"
        ]

        if value in policy[
            "preferred"
        ]:

            severity = "info"

            message = (
                "Preferred key-exchange "
                "group detected."
            )

        elif value in policy[
            "acceptable"
        ]:

            severity = "low"

            message = (
                "Key-exchange group "
                "is acceptable."
            )

        elif value in policy[
            "weak"
        ]:

            severity = "high"

            message = (
                "Weak key-exchange "
                "group detected."
            )

        else:

            severity = "medium"

            message = (
                "Unknown key-exchange "
                "group."
            )

        self._add(
            findings,
            "DH-002",
            "dh_group",
            value,
            severity,
            message
        )

        # Logjam / Weak DH attack vulnerability (RFC 7296 / NIST)
        if value in policy["weak"]:
            logjam_sev = "critical" if value in (1, 2) else "high"
            self._add(
                findings,
                "DH-003",
                "dh_group",
                value,
                logjam_sev,
                f"Diffie-Hellman Group {value} (< 2048 bits) is vulnerable to discrete logarithm precomputation (Logjam attack).",
                "Upgrade to DH Group 14 (2048-bit MODP), Group 19 (NIST P-256), or Group 31 (Curve25519)."
            )

    def _check_ike_exchange_and_mode(
        self,
        signals,
        findings
    ):

        # IKEv1 Aggressive Mode Check
        is_aggressive = signals.get("is_aggressive_mode")
        exchange = self._single(signals.get("ike_exchange"))

        if is_aggressive or exchange == "Aggressive Mode":
            self._add(
                findings,
                "IKE-005",
                "ike_exchange",
                "Aggressive Mode",
                "critical",
                "IKEv1 Aggressive Mode detected. Authentication hash is transmitted in cleartext, exposing the Pre-Shared Key (PSK) to offline dictionary attacks.",
                "Immediately migrate to IKEv2 or restrict to IKEv1 Main Mode using digital certificates."
            )

        # Handshake negotiation failure
        if signals.get("no_proposal_chosen"):
            self._add(
                findings,
                "IKE-006",
                "ike_notify",
                "NO_PROPOSAL_CHOSEN",
                "medium",
                "NO_PROPOSAL_CHOSEN notification received. Cryptographic suite mismatch or policy rejection between VPN peers.",
                "Align cryptographic proposals between initiator and responder."
            )

    def _check_nonce_entropy(
        self,
        signals,
        findings
    ):

        nonce_len = self._single(signals.get("nonce_length"))
        short_nonce = signals.get("short_nonce")
        min_nonce = self.baseline.get("minimum_nonce_length", 16)

        if short_nonce or (nonce_len is not None and nonce_len < min_nonce):
            self._add(
                findings,
                "IKE-007",
                "nonce_length",
                nonce_len,
                "high",
                f"Weak nonce entropy detected ({nonce_len} bytes). RFC 7296 and NIST SP 800-77 require at least 16 bytes (128 bits) of randomness.",
                "Configure VPN peers to generate cryptographically secure pseudorandom nonces of at least 128 bits."
            )

    def _check_ipsec_protocol(
        self,
        signals,
        findings
    ):

        protocol = signals.get(
            "ipsec_protocol"
        )

        if protocol is None:
            return

        values = (
            protocol
            if isinstance(protocol, list)
            else [protocol]
        )

        if "ESP" in values:
            self._add(
                findings,
                "IPSEC-001",
                "ipsec_protocol",
                "ESP",
                "info",
                "ESP traffic detected."
            )

        if "AH" in values:
            self._add(
                findings,
                "IPSEC-002",
                "ipsec_protocol",
                "AH",
                "low",
                "AH traffic detected."
            )

        # Flag AH without ESP (No Confidentiality)
        if signals.get("ah_without_esp"):
            self._add(
                findings,
                "IPSEC-003",
                "ipsec_protocol",
                "AH-only",
                "high",
                "Authentication Header (AH) used without ESP encryption. Traffic payload travels in cleartext with ZERO confidentiality.",
                "Enable Encapsulating Security Payload (ESP) encryption to ensure traffic privacy."
            )

    def _check_replay_and_rollover(
        self,
        signals,
        findings
    ):

        if signals.get("replay_detected"):
            self._add(
                findings,
                "IPSEC-004",
                "esp_sequence",
                "duplicate",
                "critical",
                "ESP duplicate packet sequence number detected. Potential Replay Attack or anti-replay window failure.",
                "Verify anti-replay window configuration and inspect network segment for packet injection."
            )

        if signals.get("sequence_rollover_risk"):
            self._add(
                findings,
                "IPSEC-005",
                "esp_sequence",
                "rollover_risk",
                "medium",
                "ESP 32-bit sequence number approaching rollover ceiling. May cause rekey disruption in high-throughput links.",
                "Enable 64-bit Extended Sequence Numbers (ESN, RFC 4304)."
            )

    def _check_compliance(
        self,
        signals,
        findings
    ):

        ike_ver = self._single(signals.get("ike_version"))
        enc = self._single(signals.get("encryption"))
        key_len = self._single(signals.get("key_length"))
        dh = self._single(signals.get("dh_group"))
        prf = self._single(signals.get("prf"))
        is_aggressive = signals.get("is_aggressive_mode")

        # NIST SP 800-77 Rev 1 Assessment
        nist_passed = True
        nist_reasons = []

        if is_aggressive:
            nist_passed = False
            nist_reasons.append("IKEv1 Aggressive Mode is disallowed")

        weak_encs = self.baseline.get("encryption", {}).get("weak", [])
        if enc in weak_encs:
            nist_passed = False
            nist_reasons.append(f"Insecure cipher '{enc}'")

        weak_dh = self.baseline.get("dh_groups", {}).get("weak", [])
        if dh in weak_dh:
            nist_passed = False
            nist_reasons.append(f"Insecure DH Group '{dh}' (< 2048-bit)")

        if key_len is not None and key_len < 128:
            nist_passed = False
            nist_reasons.append(f"Key length '{key_len}' < 128 bits")

        if nist_passed:
            self._add(
                findings,
                "COMP-001",
                "compliance",
                "NIST SP 800-77 Rev 1",
                "info",
                "Configuration complies with NIST SP 800-77 Rev 1 recommendations."
            )
        else:
            self._add(
                findings,
                "COMP-001",
                "compliance",
                "NIST SP 800-77 Rev 1",
                "high",
                f"Configuration fails NIST SP 800-77 Rev 1: {', '.join(nist_reasons)}.",
                "Upgrade to modern AES-GCM encryption, DH Group 14+, and disable legacy suites."
            )

        # CNSA Suite 2.0 Assessment (Quantum-Readiness)
        cnsa_passed = (
            enc == "AES-GCM-16"
            and key_len == 256
            and dh in (20, 21, 31)
            and prf in ("HMAC-SHA2-384", "HMAC-SHA2-512")
        )

        if cnsa_passed:
            self._add(
                findings,
                "COMP-002",
                "compliance",
                "CNSA Suite 2.0",
                "info",
                "Configuration meets CNSA Suite 2.0 quantum-resistant cryptographic requirements."
            )
        else:
            self._add(
                findings,
                "COMP-002",
                "compliance",
                "CNSA Suite 2.0",
                "low",
                "Configuration does not meet CNSA Suite 2.0 quantum-resistant baseline (Requires AES-256-GCM, DH Group 20/21/31, SHA-384/512).",
                "For post-quantum / high-security deployments, transition to AES-256-GCM and ECDH Group 20/21."
            )