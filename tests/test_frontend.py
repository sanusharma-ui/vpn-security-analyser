from pathlib import Path
from fastapi.testclient import TestClient

from api.routes import create_app
from api.service import JobService
from config.settings import APISettings

KEY = "test-token-at-least-32-characters-long!!"


def test_frontend_dashboard_serving(tmp_path):
    settings = APISettings(api_key=KEY, data_dir=tmp_path / "backend")
    app = create_app(settings, service_factory=lambda c: JobService(c))

    with TestClient(app) as client:
        # 1. Health check is still public and working
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["status"] == "ok"

        # 2. Root GET / serves index.html
        resp = client.get("/")
        assert resp.status_code == 200
        assert "text/html" in resp.headers.get("content-type", "")
        assert "IPsec Shield" in resp.text
        assert "Cyber SOC Dashboard" in resp.text
        assert "js/app.js" in resp.text

        # 3. Static CSS is served
        css = client.get("/css/main.css")
        assert css.status_code == 200
        assert "text/css" in css.headers.get("content-type", "")
        assert "--bg-base" in css.text

        # 4. Static JS is served
        js = client.get("/js/app.js")
        assert js.status_code == 200
        assert "javascript" in js.headers.get("content-type", "")
        assert "Application" in js.text

        # 5. Static sample PCAP is served
        pcap = client.get("/samples/test_vpn.pcap")
        assert pcap.status_code == 200
        assert len(pcap.content) == 1448

        # 6. API routes still strictly protected
        assert client.get("/api/v1/interfaces").status_code == 401
        assert client.get("/api/v1/interfaces", headers={"X-API-Key": KEY}).status_code == 200
