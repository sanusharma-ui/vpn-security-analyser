"""Bounded passive event history; repeated headers are not proof of retransmission."""
from collections import OrderedDict, deque
from copy import deepcopy


class SessionTimeline:
    def __init__(self, limit=128):
        self.events = deque(maxlen=limit)
        self.seen_headers = OrderedDict()
        self.limit = limit
        self.total = 0

    def add(self, signal, kind, details):
        self.total += 1
        self.events.append({"kind": kind, "packet_number": signal.packet_number,
                            "timestamp": signal.timestamp, "details": deepcopy(details)})

    def observe_ike(self, signal):
        value = signal.value
        key = (value["src"], value["dst"], value["exchange"], value["message_id"],
               value["response"], value["initiator"])
        repeated = False
        if (value["version"] == 2 and value["message_id"] is not None
                and value["response"] is not None and value["initiator"] is not None
                and "unknown" not in (value["src"], value["dst"])):
            repeated = key in self.seen_headers
            self.seen_headers[key] = None
            self.seen_headers.move_to_end(key)
            if len(self.seen_headers) > self.limit:
                self.seen_headers.popitem(last=False)
        self.add(signal, "IKE_REPEATED_HEADER" if repeated else "IKE_MESSAGE", value)

    def to_dict(self):
        return {"events": deepcopy(list(self.events)), "total_events": self.total,
                "omitted_events": self.total - len(self.events), "limit": self.limit,
                "order": "capture_ingestion", "repeat_window": self.limit,
                "meaning": "Observed headers only. Repetition may be retransmission or duplicate capture; "
                           "encrypted exchanges do not prove authentication, rekey or deletion success."}
