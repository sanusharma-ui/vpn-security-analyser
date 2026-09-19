class ConfidenceEngine:
    IMPORTANT_FIELDS = ["ike_version", "encryption", "key_length", "prf", "dh_group", "integrity"]

    def calculate(self, signals, findings=None):
        findings = findings or []
        assessed = {f["parameter"] for f in findings
                    if f.get("status") in ("PASS", "FAIL", "NOT_APPLICABLE") and f.get("scope") != "offered"}
        missing = [name for name in self.IMPORTANT_FIELDS if name not in assessed]
        score = round(100 * (len(self.IMPORTANT_FIELDS)-len(missing))/len(self.IMPORTANT_FIELDS))
        return {"score": score, "coverage": score, "detected_fields": len(self.IMPORTANT_FIELDS)-len(missing),
                "expected_fields": len(self.IMPORTANT_FIELDS), "missing_fields": missing,
                "meaning": "Coverage of supported passive crypto checks, not probability of security.",
                "evidence_confidence": "LIMITED" if missing else "OBSERVED",
                "unassessed_controls": ["authentication validation", "CHILD_SA policy", "receiver anti-replay enforcement"]}
