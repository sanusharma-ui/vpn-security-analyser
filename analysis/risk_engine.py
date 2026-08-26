class RiskEngine:

    WEIGHTS = {
        "info": 0,
        "low": 10,
        "medium": 30,
        "high": 60,
        "critical": 100
    }

    def calculate(
        self,
        findings
    ):

        risk_findings = [
            finding
            for finding in findings
            if finding.get(
                "severity"
            ) != "info"
        ]

        if not risk_findings:

            return {
                "score": 0,
                "security_score": 100,
                "level": "LOW"
            }

        scores = []

        for finding in risk_findings:

            severity = finding.get(
                "severity",
                "medium"
            )

            scores.append(
                self.WEIGHTS.get(
                    severity,
                    30
                )
            )

        highest = max(scores)

        average = (
            sum(scores)
            / len(scores)
        )

        score = int(
            round(
                highest * 0.7
                + average * 0.3
            )
        )

        score = max(
            0,
            min(score, 100)
        )

        return {
            "score": score,
            "security_score": 100 - score,
            "level": self._level(score)
        }

    def _level(self, score):

        if score < 25:
            return "LOW"

        if score < 50:
            return "MEDIUM"

        if score < 75:
            return "HIGH"

        return "CRITICAL"