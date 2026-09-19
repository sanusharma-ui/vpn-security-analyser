"""Explicit deployment settings; no credentials are stored in source."""
import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class APISettings:
    api_key: str
    data_dir: Path = Path("data/backend")
    allowed_origins: tuple = field(default_factory=tuple)
    max_jobs: int = 100
    max_active_jobs: int = 2
    max_upload_bytes: int = 50 * 1024 * 1024

    @classmethod
    def from_env(cls):
        key = os.environ.get("VPN_ANALYZER_API_KEY", "")
        if len(key) < 32:
            raise RuntimeError("Set VPN_ANALYZER_API_KEY to a random secret of at least 32 characters.")
        origins = tuple(x.strip() for x in os.environ.get("VPN_ANALYZER_CORS_ORIGINS", "").split(",") if x.strip())
        if "*" in origins:
            raise RuntimeError("Configure explicit browser origins; wildcard CORS is not supported.")
        return cls(api_key=key, data_dir=Path(os.environ.get("VPN_ANALYZER_DATA_DIR", "data/backend")),
                   allowed_origins=origins)
