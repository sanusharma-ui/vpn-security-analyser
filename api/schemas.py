"""Public request and response contracts used by OpenAPI."""
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field


class CaptureRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)
    interface: str = Field(min_length=1, max_length=512, description="Exact name returned by /interfaces.")
    duration_seconds: float = Field(default=60, gt=0, le=3600)
    packet_limit: int | None = Field(default=None, gt=0, le=1_000_000)
    update_interval_seconds: float = Field(default=2, ge=0.5, le=30)


class JobStatus(BaseModel):
    id: str
    source_type: Literal["live", "pcap"]
    state: Literal["queued", "running", "stopping", "completed", "stopped", "failed", "interrupted"]
    revision: int
    created_at: str
    updated_at: str
    finished_at: str | None = None
    parameters: dict[str, Any]
    error: str | None = None
    summary: dict[str, Any] | None = None
    links: dict[str, str]


class JobList(BaseModel):
    items: list[JobStatus]
    total: int
    limit: int
    offset: int


class ReportResponse(BaseModel):
    model_config = ConfigDict(extra="allow")
    metadata: dict[str, Any]
    summary: dict[str, Any]
    traffic: dict[str, Any]
    findings: list[dict[str, Any]]
    sessions: list[dict[str, Any]]
    quality: dict[str, Any]


class AIInputResponse(BaseModel):
    schema_version: str
    authoritative_source: str
    instructions: str
    assessment: dict[str, Any]
    limitations: list[str]
    sessions: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    omitted_findings: int
    omitted_sessions: int


class ComparisonResponse(BaseModel):
    schema_version: str
    mode: Literal["passive_observation_comparison"]
    baseline: dict[str, Any]
    current: dict[str, Any]
    newly_observed: list[dict[str, Any]]
    no_longer_observed: list[dict[str, Any]]
    persistent: list[dict[str, Any]]
    sessions: dict[str, list[str]]
    scores: dict[str, dict[str, float | None]]
    score_comparison_reasons: list[str]
    limitations: list[str]
