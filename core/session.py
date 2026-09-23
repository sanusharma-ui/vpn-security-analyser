import json
from collections import OrderedDict
from dataclasses import dataclass, field
from core.signal import SecuritySignal
from copy import deepcopy
from core.timeline import SessionTimeline


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
    timeline: SessionTimeline = field(default_factory=SessionTimeline)
    proposal_samples: list = field(default_factory=list)
    proposal_samples_omitted: int = 0
    proposal_history_bytes: int = 0
    proposal_history_limit_bytes: int = 65536
    selected_proposal_issue: bool = False

    def ingest(self, signal):
        if signal.packet_number is None or signal.packet_number != self.last_packet:
            self.packet_count += 1
            self.last_packet = signal.packet_number
        if signal.name == "ike_message":
            self.timeline.observe_ike(signal)
            return
        if signal.name == "ike_proposals":
            details = signal.value
            if signal.scope == "selected" and details["status"] != "UNAVAILABLE":
                proposals = details["proposals"]
                types = [t["type"] for p in proposals for t in p["transforms"]]
                self.selected_proposal_issue |= (
                    details["status"] != "COMPLETE" or len(proposals) != 1
                    or proposals[0]["protocol_id"] != 1 or len(types) != len(set(types))
                    or not {1, 2, 4}.issubset(types))
            sample = {"packet_number": signal.packet_number,
                      "timestamp": signal.timestamp, "scope": signal.scope, **details}
            sample_bytes = len(json.dumps(sample, ensure_ascii=True).encode("utf-8"))
            if (len(self.proposal_samples) < 16
                    and self.proposal_history_bytes + sample_bytes <= self.proposal_history_limit_bytes):
                self.proposal_samples.append(deepcopy(sample))
                self.proposal_history_bytes += sample_bytes
            else:
                self.proposal_samples_omitted += 1
            return
        if signal.name == "ipsec_protocol" and not self.timeline.total:
            self.timeline.add(signal, "IPSEC_OBSERVED", {"protocol": signal.value})
        if signal.name == "esp_sequence_int":
            value = signal.value
            if value in self.sequences:
                self.timeline.add(signal, "ESP_DUPLICATE_SEQUENCE", {
                    "sequence": value, "status": "SUSPECTED",
                    "meaning": "Duplicate sequence observed; replay or receiver acceptance is not established."})
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
                "sequence_window": self.sequence_window, "timeline": self.timeline.to_dict(),
                "ike_proposals": deepcopy(self.proposal_samples),
                "proposal_samples_omitted": self.proposal_samples_omitted,
                "proposal_history_limit_bytes": self.proposal_history_limit_bytes,
                "selected_proposal_issue": self.selected_proposal_issue}
