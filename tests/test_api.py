import json
import threading
import time
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.routes import create_app
from api.service import JobService, TERMINAL
from api.storage import JobStore
from config.settings import APISettings
from core.engine import SecurityEngine
from test_regressions import ike

KEY = "unit-test-token-with-at-least-32-characters"
HEADERS = {"X-API-Key": KEY}


class FakeLive:
    queue_drops = 0

    def __init__(self, interface=None, timeout=None, packet_count=None):
        self.timeout = timeout
        self.packet_count = packet_count
        self.stop_event = threading.Event()
        self.status = "ready"

    def read(self):
        self.status = "capturing"
        if not self.stop_event.is_set():
            yield ike()
        if self.packet_count == 1:
            self.status = "complete"
            return
        deadline = time.monotonic()+self.timeout
        while not self.stop_event.wait(0.01) and time.monotonic() < deadline:
            yield None
        self.status = "stopped" if self.stop_event.is_set() else "timeout"

    def request_stop(self):
        self.stop_event.set()

    def close(self):
        self.request_stop()


@pytest.fixture
def settings(tmp_path):
    return APISettings(api_key=KEY, data_dir=tmp_path / "backend")


def make_app(settings, live=FakeLive, pcap=None):
    def factory(config):
        options = {"live_factory": live}
        if pcap:
            options["pcap_factory"] = pcap
        return JobService(config, **options)
    return create_app(settings, service_factory=factory,
                      interface_provider=lambda: [{"index": 1, "name": "test-interface"}])


@pytest.fixture
def client(settings):
    with TestClient(make_app(settings)) as client:
        yield client


def start(client, **values):
    response = client.post("/api/v1/captures", headers=HEADERS,
        json={"interface": "test-interface", "duration_seconds": 0.05, **values})
    assert response.status_code == 202, response.text
    return response.json()["id"]


def finished(client, identifier):
    deadline = time.monotonic()+10
    while time.monotonic() < deadline:
        row = client.get(f"/api/v1/jobs/{identifier}", headers=HEADERS).json()
        if row["state"] in TERMINAL:
            return row
        time.sleep(0.01)
    pytest.fail("Job did not finish")


def test_authentication_and_openapi(client):
    assert client.get("/health").status_code == 200
    assert client.get("/api/v1/interfaces").status_code == 401
    assert client.get("/api/v1/interfaces", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/api/v1/interfaces", headers=HEADERS).status_code == 200
    schema = client.get("/openapi.json").json()
    assert schema["components"]["securitySchemes"]["APIKeyHeader"]["name"] == "X-API-Key"
    assert "application/octet-stream" in schema["paths"]["/api/v1/analyses/pcap"]["post"]["requestBody"]["content"]


@pytest.mark.parametrize("body", [
    {"interface": "unknown"}, {"interface": "test-interface", "duration_seconds": 0},
    {"interface": "test-interface", "duration_seconds": 3601},
    {"interface": "test-interface", "packet_limit": -1},
    {"interface": "test-interface", "update_interval_seconds": 0},
    {"interface": "test-interface", "capture_filter": "arbitrary"},
])
def test_capture_input_validation(client, body):
    assert client.post("/api/v1/captures", json=body, headers=HEADERS).status_code == 422


def test_live_lifecycle_report_ai_and_terminal_sse(client):
    identifier = start(client)
    row = finished(client, identifier)
    assert row["state"] == "completed"
    report = client.get(row["links"]["report"], headers=HEADERS).json()
    assert report["traffic"]["packets_processed"] == 1
    assert report["traffic"]["capture_status"] == "timeout"
    assert report["summary"]["security_score"] == 100
    assert report["metadata"]["job_id"] == identifier
    ai = client.get(row["links"]["ai_input"], headers=HEADERS).json()
    assert ai["assessment"]["security_score"] == 100
    assert "10.0.0.1" not in json.dumps(ai)
    stream = client.get(row["links"]["events"], headers=HEADERS)
    assert "event: complete" in stream.text
    download = client.get(row["links"]["report"]+"?download=true", headers=HEADERS)
    assert ".json" in download.headers["content-disposition"]
    assert client.get("/api/v1/jobs?limit=1", headers=HEADERS).json()["total"] == 1


def test_stop_is_idempotent_and_live_concurrency_is_bounded(client):
    identifier = start(client, duration_seconds=60)
    assert client.post("/api/v1/captures", headers=HEADERS,
        json={"interface": "test-interface"}).status_code == 409
    assert client.delete(f"/api/v1/jobs/{identifier}", headers=HEADERS).status_code == 409
    assert client.post(f"/api/v1/jobs/{identifier}/explain", headers=HEADERS).status_code == 409
    assert client.post(f"/api/v1/jobs/{identifier}/stop", headers=HEADERS).status_code == 200
    assert finished(client, identifier)["state"] == "stopped"
    assert client.post(f"/api/v1/jobs/{identifier}/stop", headers=HEADERS).json()["state"] == "stopped"


def test_capture_failure_returns_incomplete_report(settings):
    class Broken(FakeLive):
        def read(self):
            yield ike()
            raise RuntimeError("secret/internal/path")
    with TestClient(make_app(settings, live=Broken)) as client:
        identifier = start(client)
        row = finished(client, identifier)
        assert row["state"] == "failed" and "secret" not in row["error"]
        report = client.get(row["links"]["report"], headers=HEADERS).json()
        assert report["metadata"]["incomplete"]
        assert report["summary"]["security_score"] is None


def test_queue_loss_is_visible_and_suppresses_score(settings):
    class Dropping(FakeLive):
        queue_drops = 5
    with TestClient(make_app(settings, live=Dropping)) as client:
        identifier = start(client)
        row = finished(client, identifier)
        report = client.get(row["links"]["report"], headers=HEADERS).json()
        assert report["traffic"]["queue_drops"] == 5
        assert report["summary"]["security_score"] is None


def test_explainer_fallback_preserves_report(client, monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_MODEL", raising=False)
    identifier = start(client)
    row = finished(client, identifier)
    before = client.get(row["links"]["report"], headers=HEADERS).json()
    result = client.post(row["links"]["explain"], headers=HEADERS).json()
    assert result["status"] == "unavailable"
    after = client.get(row["links"]["report"], headers=HEADERS).json()
    assert after["summary"] == before["summary"]
    assert after["findings"] == before["findings"]


def test_pcap_upload_runs_real_tshark_and_cleans_input(client, settings):
    response = client.post("/api/v1/analyses/pcap",
        headers={**HEADERS, "Content-Type": "application/octet-stream"},
        content=Path("data/pcaps/test_vpn.pcap").read_bytes())
    assert response.status_code == 202, response.text
    row = finished(client, response.json()["id"])
    assert row["state"] == "completed", row
    report = client.get(row["links"]["report"], headers=HEADERS).json()
    assert report["traffic"]["packets_processed"] == 6
    deadline = time.monotonic()+2
    while list((settings.data_dir / "uploads").glob("*.pcap")) and time.monotonic() < deadline:
        time.sleep(0.01)
    assert not list((settings.data_dir / "uploads").glob("*.pcap"))


def test_bad_uploads_are_rejected_and_cleaned(client, settings):
    assert client.post("/api/v1/analyses/pcap", headers=HEADERS, content=b"bad").status_code == 415
    assert client.post("/api/v1/analyses/pcap",
        headers={**HEADERS, "Content-Type": "application/octet-stream"}, content=b"bad").status_code == 422
    assert client.post("/api/v1/analyses/pcap",
        headers={**HEADERS, "Content-Type": "application/octet-stream", "Content-Length": str(51*1024*1024)},
        content=b"x").status_code == 413
    assert not list((settings.data_dir / "uploads").glob("*.pcap"))


def test_persistence_and_restart_interruption(settings):
    first = JobService(settings, live_factory=FakeLive)
    identifier = str(uuid.uuid4())
    first.store.insert({"id": identifier, "state": "running", "source_type": "live",
        "created_at": "2026-09-19T00:00:00Z", "updated_at": "2026-09-19T00:00:00Z", "parameters": {}})
    first.store.update(identifier, report=SecurityEngine().analyze([ike()]))
    first.shutdown()
    second = JobService(settings, live_factory=FakeLive)
    try:
        assert second.status(identifier)["state"] == "interrupted"
        assert second.report(identifier)["summary"]["security_score"] is None
        assert second.report(identifier)["metadata"]["incomplete"]
    finally:
        second.shutdown()


def test_data_directory_rejects_second_backend(settings):
    first = JobStore(settings.data_dir)
    try:
        with pytest.raises(RuntimeError, match="one backend worker"):
            JobStore(settings.data_dir)
    finally:
        first.close()


def test_unknown_and_malformed_ids(client):
    assert client.get(f"/api/v1/jobs/{uuid.uuid4()}", headers=HEADERS).status_code == 404
    assert client.get("/api/v1/jobs/not-a-uuid", headers=HEADERS).status_code == 422


def test_saved_job_limit_and_delete(settings):
    from dataclasses import replace
    settings = replace(settings, max_jobs=1)
    with TestClient(make_app(settings)) as client:
        identifier = start(client)
        finished(client, identifier)
        assert client.post("/api/v1/captures", headers=HEADERS,
            json={"interface": "test-interface"}).status_code == 429
        deadline = time.monotonic()+2
        while time.monotonic() < deadline:
            response = client.delete(f"/api/v1/jobs/{identifier}", headers=HEADERS)
            if response.status_code == 204:
                break
            time.sleep(0.01)
        assert response.status_code == 204
        assert client.get(f"/api/v1/jobs/{identifier}", headers=HEADERS).status_code == 404


def test_shutdown_stops_active_job_and_persists(settings):
    with TestClient(make_app(settings)) as client:
        identifier = start(client, duration_seconds=60)
    with TestClient(make_app(settings)) as client:
        assert client.get(f"/api/v1/jobs/{identifier}", headers=HEADERS).json()["state"] == "stopped"
