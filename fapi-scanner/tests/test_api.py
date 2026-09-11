from scanner.discovery.metadata_fetch import MetadataFetch
from fastapi.testclient import TestClient

from scanner.api import app
from tests.fake_lab import FakeLab
from tests.test_bh_checks import FETCHED


client = TestClient(app)

EXPECTED_IDS = {
    "DISC-001",
    "DISC-002",
    "DISC-003",
    "PAR-001",
    "PAR-002",
    "PKCE-001",
    "PKCE-002",
    "AUTH-001",
    "AUTH-002",
    "AUTH-003",
    "DPOP-001",
    "DPOP-002",
    "MTLS-002",
    "TOK-001",
    "TOK-002",
    "RESP-001",
    "RESP-002",
    "RESP-003",
    "DCR-001",
    "DCM-001",
}


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["service"] == "fapi-scanner"


def test_lists_checks():
    response = client.get("/api/v1/checks")
    assert response.status_code == 200
    ids = {item["check_id"] for item in response.json()["checks"]}
    assert ids == EXPECTED_IDS


def test_scan_uses_fake_lab(monkeypatch):
    FakeLab().install(monkeypatch)
    monkeypatch.setattr("scanner.engine.fetch_metadata", lambda target: FETCHED)

    response = client.post("/api/v1/scan", json={"target": "http://as.example"})
    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["pass"] == 20
    assert body["summary"]["fail"] == 0
    assert {item["check_id"] for item in body["results"]} == EXPECTED_IDS
