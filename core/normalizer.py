class SignalNormalizer:

    def normalize(self, signals):

        result = {}

        for signal in signals:

            name = signal.name
            value = signal.value

            if name not in result:
                result[name] = value

            elif result[name] != value:

                existing = result[name]

                if not isinstance(existing, list):
                    existing = [existing]

                if value not in existing:
                    existing.append(value)

                result[name] = existing

        return result