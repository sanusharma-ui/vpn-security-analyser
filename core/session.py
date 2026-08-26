from dataclasses import dataclass, field
from typing import Dict, Any, List


@dataclass
class VPNSession:

    session_id: str

    packet_count: int = 0

    signals: Dict[str, Any] = field(
        default_factory=dict
    )

    exchanges: List[str] = field(
        default_factory=list
    )

    def add_signal(
        self,
        name,
        value
    ):

        self.packet_count += 1

        if name == "ike_exchange":

            if value not in self.exchanges:
                self.exchanges.append(value)

        if name not in self.signals:

            self.signals[name] = value

        elif self.signals[name] != value:

            existing = self.signals[name]

            if not isinstance(
                existing,
                list
            ):
                existing = [existing]

            if value not in existing:
                existing.append(value)

            self.signals[name] = existing

    def to_dict(self):

        return {
            "session_id": self.session_id,
            "packet_count": self.packet_count,
            "exchanges": self.exchanges,
            "signals": self.signals
        }