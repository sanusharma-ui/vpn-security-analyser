from dataclasses import dataclass, asdict
from typing import Any, Optional


@dataclass
class SecuritySignal:
    name: str
    value: Any
    source: str

    confidence: float = 1.0

    packet_number: Optional[int] = None
    session_id: Optional[str] = None

    category: Optional[str] = None

    def to_dict(self):
        return asdict(self)