class RiskEngine:
    WEIGHTS = {"info": 0, "low": 10, "medium": 30, "high": 60, "critical": 100}

    def calculate(self, findings):
        # Worst confirmed selected/observed control. Added weaknesses cannot reduce risk.
        assessed = [f for f in findings if f.get("status", "FAIL") in ("PASS", "FAIL")
                    and f.get("scope") != "offered" and f.get("parameter") not in ("ipsec_protocol", "compliance")]
        if not assessed:
            return {"score": None, "security_score": None, "level": "UNKNOWN"}
        score = max(self.WEIGHTS.get(f.get("severity"), 0) for f in assessed)
        has_cipher = any(f.get("parameter") == "encryption" for f in assessed)
        return {"score": score, "security_score": 100-score if has_cipher else None,
                "level": self._level(score)}

    def _level(self, score):
        return "LOW" if score < 25 else "MEDIUM" if score < 50 else "HIGH" if score < 75 else "CRITICAL"
