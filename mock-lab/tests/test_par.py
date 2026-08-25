import time

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.store import par_store

client = TestClient(app)

VALID_PAR = {
    "client_id": "test-client",
    "redirect_uri": "https://client.example/callback",
    "scope": "openid accounts",
    "code_challenge": "E9Melhoa2OcwObgj_zthkQS-BglfS65ibk4BfLF0hVA",
    "code_challenge_method": "S256",
}


@pytest.fixture(autouse=True)
def reset_par_store_and_toggles():
    par_store.clear()
    settings.PAR_ENFORCED = True
    settings.REQUEST_URI_REUSABLE = False
    settings.REQUEST_URI_LONG_LIVED = False
    settings.ALLOW_PLAIN_PKCE = False
    yield
    par_store.clear()
    settings.PAR_ENFORCED = True
    settings.REQUEST_URI_REUSABLE = False
    settings.REQUEST_URI_LONG_LIVED = False
    settings.ALLOW_PLAIN_PKCE = False


def test_par_rejects_missing_parameters():
    resp = client.post("/par", data={"client_id": "test-client"})
    assert resp.status_code in (400, 422)


def test_par_rejects_invalid_pkce_method():
    body = {**VALID_PAR, "code_challenge_method": "plain"}
    resp = client.post("/par", data=body)
    assert resp.status_code == 400


def test_par_issues_request_uri():
    resp = client.post("/par", data=VALID_PAR)
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["request_uri"].startswith("urn:ietf:params:oauth:request_uri:")
    assert payload["expires_in"] == 60


def test_authorize_rejects_missing_request_uri_when_par_enforced():
    resp = client.get("/authorize", params={"client_id": "test-client"})
    assert resp.status_code == 400


def test_authorize_rejects_unknown_request_uri():
    resp = client.get(
        "/authorize",
        params={
            "client_id": "test-client",
            "request_uri": "urn:ietf:params:oauth:request_uri:unknown",
        },
    )
    assert resp.status_code == 400


def test_authorize_accepts_valid_request_uri_once():
    par = client.post("/par", data=VALID_PAR).json()
    first = client.get(
        "/authorize",
        params={"client_id": VALID_PAR["client_id"], "request_uri": par["request_uri"]},
    )
    assert first.status_code == 200
    assert first.json()["params"]["redirect_uri"] == VALID_PAR["redirect_uri"]

    replay = client.get(
        "/authorize",
        params={"client_id": VALID_PAR["client_id"], "request_uri": par["request_uri"]},
    )
    assert replay.status_code == 400


def test_par_enforced_false_allows_front_channel_bypass():
    settings.PAR_ENFORCED = False
    resp = client.get("/authorize", params=VALID_PAR)
    assert resp.status_code == 200
    assert resp.json()["params"]["client_id"] == VALID_PAR["client_id"]


def test_request_uri_reusable_allows_replay():
    settings.REQUEST_URI_REUSABLE = True
    par = client.post("/par", data=VALID_PAR).json()
    params = {"client_id": VALID_PAR["client_id"], "request_uri": par["request_uri"]}
    assert client.get("/authorize", params=params).status_code == 200
    assert client.get("/authorize", params=params).status_code == 200


def test_request_uri_expires_by_default(monkeypatch):
    par = client.post("/par", data=VALID_PAR).json()
    now = time.time()
    monkeypatch.setattr(par_store.time, "time", lambda: now + 61)
    resp = client.get(
        "/authorize",
        params={"client_id": VALID_PAR["client_id"], "request_uri": par["request_uri"]},
    )
    assert resp.status_code == 400


def test_request_uri_long_lived_does_not_expire(monkeypatch):
    settings.REQUEST_URI_LONG_LIVED = True
    par = client.post("/par", data=VALID_PAR).json()
    now = time.time()
    monkeypatch.setattr(par_store.time, "time", lambda: now + 61)
    resp = client.get(
        "/authorize",
        params={"client_id": VALID_PAR["client_id"], "request_uri": par["request_uri"]},
    )
    assert resp.status_code == 200


def test_metadata_advertises_par_endpoint():
    resp = client.get("/.well-known/oauth-authorization-server")
    assert resp.status_code == 200
    doc = resp.json()
    assert doc["pushed_authorization_request_endpoint"].endswith("/par")
    assert doc["require_pushed_authorization_requests"] is True
