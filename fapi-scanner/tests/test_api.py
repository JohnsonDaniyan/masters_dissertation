from scanner.discovery.metadata_fetch import MetadataFetch
from fastapi.testclient import TestClient

from scanner.api import app
from tests.par_fakes import FakeParAS


client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["service"] == "fapi-scanner"


def test_lists_checks():
    response = client.get("/api/v1/checks")
    assert response.status_code == 200
    ids = {item["check_id"] for item in response.json()["checks"]}
    assert ids == {"DISC-001", "DISC-002", "DISC-003", "PAR-001", "PAR-002", "PAR-003"}


def test_scan_uses_mock_metadata(monkeypatch):
    fetched = MetadataFetch(
        url="http://as.example/.well-known/oauth-authorization-server",
        status_code=200,
        document={
            "issuer": "https://as.example",
            "authorization_endpoint": "https://as.example/authorize",
            "pushed_authorization_request_endpoint": "https://as.example/par",
            "require_pushed_authorization_requests": True,
        },
    )
    fake = FakeParAS()
    monkeypatch.setattr("scanner.engine.fetch_metadata", lambda target: fetched)
    monkeypatch.setattr("scanner.discovery.par_enforcement.post_form", fake.post_form)
    monkeypatch.setattr("scanner.discovery.par_enforcement.get_request", fake.get_request)

    response = client.post("/api/v1/scan", json={"target": "http://as.example"})
    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["pass"] == 6
    assert body["summary"]["fail"] == 0
    assert {item["check_id"] for item in body["results"]} == {
        "DISC-001",
        "DISC-002",
        "DISC-003",
        "PAR-001",
        "PAR-002",
        "PAR-003",
    }
