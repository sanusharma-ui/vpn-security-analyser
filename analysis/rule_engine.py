from config.security_baseline import SECURITY_BASELINE


class RuleEngine:
    """Deterministic checks on one SA and one observation scope at a time."""

    def __init__(self, baseline=None):
        self.baseline = baseline if baseline is not None else SECURITY_BASELINE

    @staticmethod
    def values(signals, name):
        value = signals.get(name)
        return value if isinstance(value, list) else ([] if value is None else [value])

    def evaluate(self, signals, scope="observed"):
        findings = []
        def add(rule, parameter, value, severity, message, recommendation=None,
                status=None):
            findings.append(dict(rule_id=rule, parameter=parameter, value=value,
                severity=severity, message=message, recommendation=recommendation,
                status=status or ("PASS" if severity == "info" else "FAIL"),
                scope=scope))

        checks = (
            ("ike_version", "ike_versions", "IKE", "Migrate to IKEv2."),
            ("encryption", "encryption", "ENC", "Remove weak proposals; use an approved modern cipher."),
            ("prf", "prf", "PRF", "Use a PRF approved by the selected policy."),
            ("dh_group", "dh_groups", "DH", "Use an approved modern key-exchange group."),
        )
        aliases = {"DES-CBC": "DES", "3DES-CBC": "3DES", "IDEA-CBC": "IDEA",
                   "Blowfish-CBC": "Blowfish", "CAST-128-CBC": "CAST", "RC5-R16-B64-CBC": "RC5"}
        for field, policy_key, prefix, fix in checks:
            values = self.values(signals, field)
            if not values:
                add(f"{prefix}-001", field, None, "info", f"{field} was not observable.", status="UNKNOWN")
            for value in values:
                canonical = aliases.get(value, value) if field == "encryption" else value
                policy = self.baseline[policy_key]
                severity, status = "info", "PASS"
                rule = f"{prefix}-002"
                if canonical in policy.get("weak", []):
                    severity = "critical" if field == "encryption" else "high"
                    rule = "ENC-004" if field == "encryption" else rule
                elif canonical in policy.get("legacy", []):
                    severity = "high"
                    rule = "IKE-003" if field == "ike_version" else rule
                elif canonical in policy.get("acceptable", []):
                    severity = "low"
                elif canonical not in policy.get("preferred", []):
                    status = "UNKNOWN"
                if severity != "info":
                    status = "FAIL"
                add(rule, field, value, severity,
                    f"{scope.capitalize()} {field}: {value}; policy result {status}.",
                    fix if status == "FAIL" else None, status)

        lengths = self.values(signals, "key_length")
        if not lengths:
            add("KEY-001", "key_length", None, "info", "Key length was not observable.", status="UNKNOWN")
        for value in lengths:
            valid = isinstance(value, int) and not isinstance(value, bool) and value > 0
            severity = "high" if valid and value < self.baseline["minimum_key_length"] else "info"
            add("KEY-002", "key_length", value, severity,
                f"{scope.capitalize()} key length: {value} bits.",
                "Meet the configured minimum key length." if severity == "high" else None,
                None if valid else "UNKNOWN")

        ciphers = self.values(signals, "encryption")
        aead = bool(ciphers) and all(c in ("AES-GCM-8", "AES-GCM-12", "AES-GCM-16", "ChaCha20-Poly1305") for c in ciphers)
        integrity = self.values(signals, "integrity")
        if aead:
            add("INT-001", "integrity", "AEAD", "info", "Observed cipher alternatives provide integrated integrity.", status="NOT_APPLICABLE")
        elif not integrity:
            add("INT-002", "integrity", None, "info", "Integrity or its association with proposals was not observable.", status="UNKNOWN")
        else:
            for value in integrity:
                policy = self.baseline["integrity"]
                severity = "high" if value in policy["legacy"] else "info"
                status = "FAIL" if severity == "high" else ("PASS" if value in policy["preferred"] else "UNKNOWN")
                add("INT-003", "integrity", value, severity,
                    f"{scope.capitalize()} integrity transform: {value}.", status=status)

        if True in self.values(signals, "is_aggressive_mode"):
            add("IKE-005", "is_aggressive_mode", True, "high",
                "IKEv1 Aggressive Mode observed. If PSK authentication is used, offline password guessing may be possible.",
                "Migrate to IKEv2 and verify authentication policy.")
        if True in self.values(signals, "no_proposal_chosen"):
            add("IKE-006", "no_proposal_chosen", True, "info",
                "Peer rejected the proposals; this alone does not establish an attack.", status="SUSPECTED")
        for length in self.values(signals, "nonce_length"):
            if isinstance(length, int) and length < self.baseline.get("minimum_nonce_length", 16):
                add("IKE-007", "nonce_length", length, "high",
                    "Observed nonce is shorter than policy minimum; length alone does not measure entropy.",
                    "Verify nonce generation and protocol-specific minimum requirements.")
        for protocol in self.values(signals, "ipsec_protocol"):
            add("IPSEC-001" if protocol == "ESP" else "IPSEC-002", "ipsec_protocol", protocol,
                "info", f"{protocol} observed; encryption strength is not inferred from this header.")
        if True in self.values(signals, "ah_without_esp"):
            add("IPSEC-003", "ah_without_esp", True, "info",
                "AH observed without ESP in this packet. AH itself provides no confidentiality; other protection is unknown.",
                "Check the confidentiality policy and any other encryption layer.", "SUSPECTED")
        if True in self.values(signals, "suspected_replay") or True in self.values(signals, "replay_detected"):
            add("IPSEC-004", "suspected_replay", True, "medium",
                "Duplicate ESP sequence observed. Capture/network duplication or suspected replay; receiver acceptance is unknown.",
                "Correlate capture points and gateway replay-drop counters.", "SUSPECTED")
        if True in self.values(signals, "sequence_rollover_risk"):
            add("IPSEC-005", "sequence_rollover_risk", True, "info",
                "High ESP sequence observed; ESN negotiation and rekey state are unknown.", status="UNKNOWN")
        # Passive observations do not establish full organizational compliance.
        for rule, name in (("COMP-001", "NIST SP 800-77 Rev 1"), ("COMP-002", "CNSA 2.0")):
            add(rule, "compliance", name, "info",
                f"{name}: full assessment requires configuration, authentication and gateway evidence; no certification claimed.",
                status="UNKNOWN")
        return findings
