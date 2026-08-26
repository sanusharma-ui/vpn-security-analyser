class ConfidenceEngine:

    IMPORTANT_FIELDS = [
        "ike_version",
        "encryption",
        "key_length",
        "prf",
        "dh_group"
    ]

    def calculate(
        self,
        signals
    ):

        detected = 0

        missing = []

        for field in self.IMPORTANT_FIELDS:

            if (
                field in signals
                and signals[field]
                is not None
            ):

                detected += 1

            else:

                missing.append(field)

        total = len(
            self.IMPORTANT_FIELDS
        )

        score = int(
            round(
                (
                    detected
                    / total
                )
                * 100
            )
        )

        return {
            "score": score,
            "detected_fields": detected,
            "expected_fields": total,
            "missing_fields": missing
        }