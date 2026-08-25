import base64

from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.registry.clients import (
    MTLS_CLIENT_ID,
    TEST_CLIENT_ID,
    TEST_CLIENT_SECRET,
    UNREGISTERED_CERT_PEM,
    get_mtls_cert_pem,
)
from tests.auth_helpers import JWT_BEARER, make_client_assertion, with_jwt

client = TestClient(app)

VALID_PAR = {
    "client_id": TEST_CLIENT_ID,
    "redirect_uri": "https://client.example/callback",
    "scope": "openid accounts",
    "code_challenge": "E9Melhoa2OcwObgj_zthkQS-BglfS65ibk4BfLF0hVA",
    "code_challenge_method": "S256",
}


def test_private_key_jwt_succeeds_once():
    jti = "jti-once"
    first = client.post("/par", data=with_jwt(VALID_PAR, jti=jti))
    assert first.status_code == 200
    assert "request_uri" in first.json()

    replay = client.post("/par", data=with_jwt(VALID_PAR, jti=jti))
    assert replay.status_code == 401
    assert "replay" in replay.json()["detail"]


def test_jwt_replay_allowed_when_protection_disabled():
    settings.JWT_REPLAY_PROTECTION = False
    assertion = make_client_assertion(jti="jti-reuse")
    body = {
        **VALID_PAR,
        "client_assertion_type": JWT_BEARER,
        "client_assertion": assertion,
    }
    assert client.post("/par", data=body).status_code == 200
    assert client.post("/par", data=body).status_code == 200


def test_mtls_succeeds_with_registered_cert():
    resp = client.post(
        "/par",
        data={**VALID_PAR, "client_id": MTLS_CLIENT_ID},
        headers={"X-SSL-Client-Cert": get_mtls_cert_pem()},
    )
    assert resp.status_code == 200
    assert "request_uri" in resp.json()


def test_mtls_fails_without_cert_by_default():
    resp = client.post("/par", data=VALID_PAR)
    assert resp.status_code == 401
    assert "client authentication required" in resp.json()["detail"]


def test_mtls_fails_with_unregistered_cert():
    resp = client.post(
        "/par",
        data={**VALID_PAR, "client_id": MTLS_CLIENT_ID},
        headers={"X-SSL-Client-Cert": UNREGISTERED_CERT_PEM},
    )
    assert resp.status_code == 401


def test_mtls_enforced_false_allows_request_without_cert():
    settings.MTLS_CLIENT_AUTH_ENFORCED = False
    resp = client.post("/par", data=VALID_PAR)
    assert resp.status_code == 200


def test_weak_client_auth_rejected_by_default():
    resp = client.post(
        "/par",
        data={**VALID_PAR, "client_secret": TEST_CLIENT_SECRET},
    )
    assert resp.status_code == 401
    assert "secret" in resp.json()["detail"]


def test_allow_weak_client_auth_accepts_client_secret_post():
    settings.ALLOW_WEAK_CLIENT_AUTH = True
    resp = client.post(
        "/par",
        data={**VALID_PAR, "client_secret": TEST_CLIENT_SECRET},
    )
    assert resp.status_code == 200


def test_allow_weak_client_auth_accepts_client_secret_basic():
    settings.ALLOW_WEAK_CLIENT_AUTH = True
    token = base64.b64encode(f"{TEST_CLIENT_ID}:{TEST_CLIENT_SECRET}".encode()).decode()
    resp = client.post(
        "/par",
        data=VALID_PAR,
        headers={"Authorization": f"Basic {token}"},
    )
    assert resp.status_code == 200
