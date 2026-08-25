from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.registry.clients import (
    MTLS_CLIENT_ID,
    TEST_CLIENT_ID,
    UNREGISTERED_CERT_PEM,
    get_mtls_cert_pem,
)
from tests.auth_helpers import with_jwt
from tests.dpop_helpers import make_dpop_proof, new_dpop_key

client = TestClient(app)

CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CODE_CHALLENGE_S256 = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

VALID_PAR = {
    "client_id": TEST_CLIENT_ID,
    "redirect_uri": "https://client.example/callback",
    "scope": "openid accounts",
    "code_challenge": CODE_CHALLENGE_S256,
    "code_challenge_method": "S256",
}

TOKEN_HTU = "http://testserver/token"
RESOURCE_HTU = "http://testserver/resource"


def _issue_code(par_data: dict, headers: dict | None = None) -> str:
    par = client.post("/par", data=par_data, headers=headers or {}).json()
    auth = client.get(
        "/authorize",
        params={"client_id": par_data["client_id"], "request_uri": par["request_uri"]},
    )
    assert auth.status_code == 200
    return auth.json()["code"]


def _jwt_code() -> str:
    return _issue_code(with_jwt(VALID_PAR))


def _mtls_code() -> str:
    return _issue_code(
        {**VALID_PAR, "client_id": MTLS_CLIENT_ID},
        headers={"X-SSL-Client-Cert": get_mtls_cert_pem()},
    )


def test_valid_dpop_proof_accepted_malformed_rejected():
    code = _jwt_code()
    key = new_dpop_key()
    proof = make_dpop_proof(key, "POST", TOKEN_HTU)
    resp = client.post(
        "/token",
        data=with_jwt(
            {
                "grant_type": "authorization_code",
                "code": code,
                "client_id": TEST_CLIENT_ID,
                "code_verifier": CODE_VERIFIER,
            }
        ),
        headers={"DPoP": proof},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "DPoP"
    assert "jkt" in body["cnf"]
    assert resp.headers.get("dpop-nonce")

    code = _jwt_code()
    bad = client.post(
        "/token",
        data=with_jwt(
            {
                "grant_type": "authorization_code",
                "code": code,
                "client_id": TEST_CLIENT_ID,
                "code_verifier": CODE_VERIFIER,
            }
        ),
        headers={"DPoP": "not-a-jwt"},
    )
    assert bad.status_code == 400
    assert "dpop" in bad.json()["detail"].lower()


def test_malformed_dpop_accepted_when_validation_not_strict():
    settings.DPOP_VALIDATION_STRICT = False
    code = _jwt_code()
    resp = client.post(
        "/token",
        data=with_jwt(
            {
                "grant_type": "authorization_code",
                "code": code,
                "client_id": TEST_CLIENT_ID,
                "code_verifier": CODE_VERIFIER,
            }
        ),
        headers={"DPoP": "not-a-jwt"},
    )
    assert resp.status_code == 200
    assert resp.json()["token_type"] == "DPoP"


def test_dpop_replay_rejected_by_default_and_allowed_when_disabled():
    code = _jwt_code()
    key = new_dpop_key()
    token_proof = make_dpop_proof(key, "POST", TOKEN_HTU)
    issued = client.post(
        "/token",
        data=with_jwt(
            {
                "grant_type": "authorization_code",
                "code": code,
                "client_id": TEST_CLIENT_ID,
                "code_verifier": CODE_VERIFIER,
            }
        ),
        headers={"DPoP": token_proof},
    )
    assert issued.status_code == 200
    access_token = issued.json()["access_token"]

    resource_proof = make_dpop_proof(key, "GET", RESOURCE_HTU, jti="replay-me")
    first = client.get(
        "/resource",
        headers={"Authorization": f"DPoP {access_token}", "DPoP": resource_proof},
    )
    assert first.status_code == 200

    replay = client.get(
        "/resource",
        headers={"Authorization": f"DPoP {access_token}", "DPoP": resource_proof},
    )
    assert replay.status_code == 401
    assert "replay" in replay.json()["detail"].lower()

    settings.DPOP_REPLAY_PROTECTION = False
    allowed = client.get(
        "/resource",
        headers={"Authorization": f"DPoP {access_token}", "DPoP": resource_proof},
    )
    assert allowed.status_code == 200


def test_mtls_bound_token_requires_matching_cert():
    code = _mtls_code()
    issued = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": MTLS_CLIENT_ID,
            "code_verifier": CODE_VERIFIER,
        },
        headers={"X-SSL-Client-Cert": get_mtls_cert_pem()},
    )
    assert issued.status_code == 200
    assert "x5t#S256" in issued.json()["cnf"]
    access_token = issued.json()["access_token"]

    missing = client.get(
        "/resource",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert missing.status_code == 401

    wrong = client.get(
        "/resource",
        headers={
            "Authorization": f"Bearer {access_token}",
            "X-SSL-Client-Cert": UNREGISTERED_CERT_PEM,
        },
    )
    assert wrong.status_code == 401

    ok = client.get(
        "/resource",
        headers={
            "Authorization": f"Bearer {access_token}",
            "X-SSL-Client-Cert": get_mtls_cert_pem(),
        },
    )
    assert ok.status_code == 200


def test_mtls_binding_enforced_false_allows_cert_mismatch():
    settings.MTLS_BINDING_ENFORCED = False
    code = _mtls_code()
    issued = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": MTLS_CLIENT_ID,
            "code_verifier": CODE_VERIFIER,
        },
        headers={"X-SSL-Client-Cert": get_mtls_cert_pem()},
    )
    access_token = issued.json()["access_token"]

    resp = client.get(
        "/resource",
        headers={
            "Authorization": f"Bearer {access_token}",
            "X-SSL-Client-Cert": UNREGISTERED_CERT_PEM,
        },
    )
    assert resp.status_code == 200
