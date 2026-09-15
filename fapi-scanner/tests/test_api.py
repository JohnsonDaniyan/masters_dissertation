from scanner.discovery.metadata_fetch import MetadataFetch
from fastapi.testclient import TestClient

from scanner.api import app, normalise_target
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


def test_rewrites_localhost_lab_when_configured(monkeypatch):
    monkeypatch.setenv("SCAN_LOCALHOST_REWRITE", "http://mock-lab:8000")

    assert normalise_target("http://127.0.0.1:8000") == "http://mock-lab:8000"
    assert normalise_target("http://localhost:8000/") == "http://mock-lab:8000"
    assert normalise_target("http://127.0.0.1:9000") == "http://127.0.0.1:9000"


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


def test_report_pdf_from_scan_payload(monkeypatch):
    FakeLab().install(monkeypatch)
    monkeypatch.setattr("scanner.engine.fetch_metadata", lambda target: FETCHED)

    scan = client.post("/api/v1/scan", json={"target": "http://as.example"})
    response = client.post("/api/v1/report/pdf", json=scan.json())
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/pdf")
    assert "fapi-scan-as.example.pdf" in response.headers["content-disposition"]
    assert response.content.startswith(b"%PDF-")
    assert b"FAPI" in response.content or len(response.content) > 500


def test_scan_pdf_runs_checks(monkeypatch):
    FakeLab().install(monkeypatch)
    monkeypatch.setattr("scanner.engine.fetch_metadata", lambda target: FETCHED)

    response = client.post("/api/v1/scan/pdf", json={"target": "https://as.example"})
    assert response.status_code == 200
    assert response.content.startswith(b"%PDF-")
    assert "attachment" in response.headers["content-disposition"]
