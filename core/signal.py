from dataclasses import dataclass
from typing import Any


@dataclass
class SecuritySignal:
    name: str
    value: Any
    source: str
    confidence: float = 1.0