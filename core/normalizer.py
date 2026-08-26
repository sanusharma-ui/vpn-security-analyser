class SignalNormalizer:

    def normalize(self, signals):

        result = {}

        for signal in signals:

            name = signal.name
            value = signal.value

            if value is None:
                continue

            if name not in result:

                result[name] = value
                continue

            existing = result[name]

            if existing == value:
                continue

            if not isinstance(
                existing,
                list
            ):
                existing = [existing]

            if value not in existing:
                existing.append(value)

            result[name] = existing

        return result