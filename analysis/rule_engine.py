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

        self._check_encryption(
            signals,
            findings
        )

        self._check_key_length(
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