import uuid

from test_api import client, settings, HEADERS, start, finished


def test_comparison_auth_validation_and_saved_reports(client):
    baseline = start(client, packet_limit=1)
    finished(client, baseline)
    current = start(client, packet_limit=1)
    finished(client, current)
    url = f"/api/v1/jobs/{current}/comparison?baseline_id={baseline}"
    assert client.get(url).status_code == 401
    response = client.get(url, headers=HEADERS)
    assert response.status_code == 200
    result = response.json()
    assert result["baseline"]["job_id"] == baseline and result["current"]["job_id"] == current
    assert result["mode"] == "passive_observation_comparison"
    assert client.get(f"/api/v1/jobs/{current}/comparison?baseline_id={current}", headers=HEADERS).status_code == 409
    assert client.get(f"/api/v1/jobs/{current}/comparison?baseline_id=bad", headers=HEADERS).status_code == 422
    assert client.get(f"/api/v1/jobs/{current}/comparison?baseline_id={uuid.uuid4()}", headers=HEADERS).status_code == 404


def test_active_job_comparison_is_rejected(client):
    baseline = start(client, packet_limit=1)
    finished(client, baseline)
    current = start(client, duration_seconds=10)
    response = client.get(f"/api/v1/jobs/{current}/comparison?baseline_id={baseline}", headers=HEADERS)
    assert response.status_code == 409
    client.post(f"/api/v1/jobs/{current}/stop", headers=HEADERS)
    finished(client, current)


def test_uploaded_pcap_details_persist_and_compare_through_api(client):
    from pathlib import Path
    identifiers = []
    for _ in range(2):
        response = client.post("/api/v1/analyses/pcap",
            headers={**HEADERS, "Content-Type": "application/octet-stream"},
            content=Path("data/pcaps/test_vpn.pcap").read_bytes())
        assert response.status_code == 202
        identifier = response.json()["id"]
        assert finished(client, identifier)["state"] == "completed"
        identifiers.append(identifier)
    reports = [client.get(f"/api/v1/jobs/{identifier}/report", headers=HEADERS).json()
               for identifier in identifiers]
    for report in reports:
        assert report["metadata"]["engine_version"] == "0.6.0"
        assert any(s["timeline"]["events"] for s in report["sessions"])
        assert any(p["status"] == "COMPLETE" for s in report["sessions"] for p in s["ike_proposals"])
    comparison = client.get(f"/api/v1/jobs/{identifiers[1]}/comparison?baseline_id={identifiers[0]}", headers=HEADERS)
    assert comparison.status_code == 200
    assert comparison.json()["newly_observed"] == []
    assert comparison.json()["no_longer_observed"] == []
    assert comparison.json()["sessions"]["shared"]
