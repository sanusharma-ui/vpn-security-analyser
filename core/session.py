from collections import OrderedDict
from dataclasses import dataclass, field
from core.signal import SecuritySignal


@dataclass
class VPNSession:
    session_id: str
    packet_count: int = 0
    last_seen: float = 0
    last_packet: int = None
    observations: dict = field(default_factory=dict)
    sequences: OrderedDict = field(default_factory=OrderedDict)
    duplicates: list = field(default_factory=list)
    truncated: bool = False
    max_observations: int = 256
    sequence_window: int = 4096

    def ingest(self, signal):
        if signal.packet_number is None or signal.packet_number != self.last_packet:
            self.packet_count += 1
            self.last_packet = signal.packet_number
        if signal.name == "esp_sequence_int":
            value = signal.value
            if value in self.sequences:
                if value not in self.duplicates:
                    self.duplicates = (self.duplicates + [value])[-16:]
                self.retain(SecuritySignal("suspected_replay", True, "session",
                    packet_number=signal.packet_number, session_id=self.session_id,
                    timestamp=signal.timestamp, category="vulnerability"))
            self.sequences[value] = None
            self.sequences.move_to_end(value)
            if len(self.sequences) > self.sequence_window:
                self.sequences.popitem(last=False)
            return
        if signal.name not in ("esp_sequence",):
            self.retain(signal)

    def retain(self, signal):
        key = (signal.scope, signal.name, str(signal.value))
        if key not in self.observations:
            if len(self.observations) >= self.max_observations:
                self.truncated = True
                return
            self.observations[key] = []
        samples = self.observations[key]
        if len(samples) < 3 and not any(s.packet_number == signal.packet_number for s in samples):
            samples.append(signal)

    def evidence(self):
        return [s for samples in self.observations.values() for s in samples]

    def to_dict(self):
        return {"session_id": self.session_id, "packet_count": self.packet_count,
                "suspected_replay": bool(self.duplicates), "replay_detected": False,
                "duplicate_sequences": list(self.duplicates), "evidence_truncated": self.truncated,
                "sequence_window": self.sequence_window}
