class RiskEngine:

    WEIGHTS = {
        "info": 0,
        "low": 5,
        "medium": 15,
        "high": 30,
        "critical": 50
    }

    def calculate(self, findings):

        score = 0

        for finding in findings:

            severity = finding.get(
                "severity",
                "info"
            )

            score += self.WEIGHTS.get(
                severity,
                0
            )

        score = min(score, 100)

        return {
            "score": score,
            "level": self._get_level(score)
        }

    def _get_level(self, score):

        if score <= 20:
            return "LOW"

        if score <= 50:
            return "MEDIUM"

        if score <= 75:
            return "HIGH"

        return "CRITICAL"