from dataclasses import dataclass, field
from typing import Dict, Any, List, Set, Tuple


@dataclass
class VPNSession:

    session_id: str
    packet_count: int = 0
    signals: Dict[str, Any] = field(default_factory=dict)
    exchanges: List[str] = field(default_factory=list)
    observed_sequences: Set[int] = field(default_factory=set)
    duplicate_sequences: List[int] = field(default_factory=list)
    roles: List[str] = field(default_factory=list)

    def add_signal(self, name, value) -> List[Tuple[str, Any]]:
        self.packet_count += 1
        new_events = []

        if name == "ike_exchange":
            if value not in self.exchanges:
                self.exchanges.append(value)

        if name == "ike_role":
            if value not in self.roles:
                self.roles.append(value)

        # Anti-replay sequence tracking per session/SPI
        if name == "esp_sequence_int":
            if value in self.observed_sequences:
                self.duplicate_sequences.append(value)
                new_events.append(("replay_detected", True))
                self.signals["replay_detected"] = True
                self.signals["duplicate_sequences"] = list(set(self.duplicate_sequences))
            else:
                self.observed_sequences.add(value)

        if name not in self.signals:
            self.signals[name] = value
        elif self.signals[name] != value:
            existing = self.signals[name]
            if not isinstance(existing, list):
                existing = [existing]
            if value not in existing:
                existing.append(value)
            self.signals[name] = existing

        return new_events

    def to_dict(self):
        return {
            "session_id": self.session_id,
            "packet_count": self.packet_count,
            "exchanges": self.exchanges,
            "roles": self.roles,
            "replay_detected": bool(self.duplicate_sequences),
            "duplicate_sequences": list(set(self.duplicate_sequences)),
            "signals": self.signals
        }