from config.security_baseline import SECURITY_BASELINE


class RuleEngine:

    def __init__(self, baseline=None):
        self.baseline = baseline or SECURITY_BASELINE

    def evaluate(self, signals):

        findings = []

        self._check_ike_version(signals, findings)
        self._check_encryption(signals, findings)
        self._check_key_length(signals, findings)
        self._check_prf(signals, findings)
        self._check_dh_group(signals, findings)

        return findings

    def _add_finding(
        self,
        findings,
        rule_id,
        parameter,
        value,
        severity,
        message
    ):

        findings.append({
            "rule_id": rule_id,
            "parameter": parameter,
            "value": value,
            "severity": severity,
            "message": message
        })

    def _check_ike_version(self, signals, findings):

        value = signals.get("ike_version")

        if value is None:
            self._add_finding(
                findings,
                "IKE-001",
                "ike_version",
                None,
                "medium",
                "IKE version could not be determined."
            )
            return

        if value in self.baseline["ike_versions"]["preferred"]:
            self._add_finding(
                findings,
                "IKE-002",
                "ike_version",
                value,
                "info",
                "Preferred IKE version detected."
            )

        elif value in self.baseline["ike_versions"]["legacy"]:
            self._add_finding(
                findings,
                "IKE-003",
                "ike_version",
                value,
                "high",
                "Legacy IKE version detected."
            )

        else:
            self._add_finding(
                findings,
                "IKE-004",
                "ike_version",
                value,
                "medium",
                "Unknown or unsupported IKE version."
            )

    def _check_encryption(self, signals, findings):

        value = signals.get("encryption")

        if value is None:
            self._add_finding(
                findings,
                "ENC-001",
                "encryption",
                None,
                "medium",
                "Encryption algorithm could not be determined."
            )
            return

        if value in self.baseline["encryption"]["strong"]:
            self._add_finding(
                findings,
                "ENC-002",
                "encryption",
                value,
                "info",
                "Strong encryption algorithm detected."
            )

        elif value in self.baseline["encryption"]["acceptable"]:
            self._add_finding(
                findings,
                "ENC-003",
                "encryption",
                value,
                "low",
                "Encryption algorithm is acceptable but not preferred."
            )

        else:
            self._add_finding(
                findings,
                "ENC-004",
                "encryption",
                value,
                "high",
                "Encryption algorithm is not approved by the current baseline."
            )

    def _check_key_length(self, signals, findings):

        value = signals.get("key_length")

        if value is None:
            self._add_finding(
                findings,
                "KEY-001",
                "key_length",
                None,
                "low",
                "Encryption key length could not be determined."
            )
            return

        minimum = self.baseline["minimum_key_length"]

        if value >= 256:
            severity = "info"
            message = "Strong encryption key length detected."

        elif value >= minimum:
            severity = "low"
            message = "Encryption key length meets the minimum baseline."

        else:
            severity = "high"
            message = "Encryption key length is below the required baseline."

        self._add_finding(
            findings,
            "KEY-002",
            "key_length",
            value,
            severity,
            message
        )

    def _check_prf(self, signals, findings):

        value = signals.get("prf")

        if value is None:
            self._add_finding(
                findings,
                "PRF-001",
                "prf",
                None,
                "medium",
                "PRF algorithm could not be determined."
            )
            return

        if value in self.baseline["prf"]["strong"]:
            self._add_finding(
                findings,
                "PRF-002",
                "prf",
                value,
                "info",
                "Strong PRF detected."
            )

        elif value in self.baseline["prf"]["legacy"]:
            self._add_finding(
                findings,
                "PRF-003",
                "prf",
                value,
                "high",
                "Legacy PRF detected."
            )

        else:
            self._add_finding(
                findings,
                "PRF-004",
                "prf",
                value,
                "medium",
                "PRF is not recognized by the current baseline."
            )

    def _check_dh_group(self, signals, findings):

        value = signals.get("dh_group")

        if value is None:
            self._add_finding(
                findings,
                "DH-001",
                "dh_group",
                None,
                "medium",
                "Diffie-Hellman group could not be determined."
            )
            return

        if value in self.baseline["dh_groups"]["strong"]:
            self._add_finding(
                findings,
                "DH-002",
                "dh_group",
                value,
                "info",
                "Strong key-exchange group detected."
            )

        elif value in self.baseline["dh_groups"]["acceptable"]:
            self._add_finding(
                findings,
                "DH-003",
                "dh_group",
                value,
                "low",
                "Key-exchange group is acceptable but not preferred."
            )

        else:
            self._add_finding(
                findings,
                "DH-004",
                "dh_group",
                value,
                "high",
                "Key-exchange group is not approved by the current baseline."
            )