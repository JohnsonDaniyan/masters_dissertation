import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.crypto.pkce import verify_pkce
from app.main import app
from app.store import code_store, par_store
from tests.auth_helpers import with_jwt

client = TestClient(app)

# 43-char verifier; S256 challenge is BASE64URL(SHA256(verifier))
CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CODE_CHALLENGE_S256 = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

VALID_PAR = {
    "client_id": "test-client",
    "redirect_uri": "https://client.example/callback",
    "scope": "openid accounts",
    "code_challenge": CODE_CHALLENGE_S256,
    "code_challenge_method": "S256",
}


@pytest.fixture(autouse=True)
def reset_stores_and_toggles():
    par_store.clear()
    code_store.clear()
    settings.PAR_ENFORCED = True
    settings.ALLOW_PLAIN_PKCE = False
    settings.PKCE_ENFORCED = True
    yield
    par_store.clear()
    code_store.clear()
    settings.PAR_ENFORCED = True
    settings.ALLOW_PLAIN_PKCE = False
    settings.PKCE_ENFORCED = True


def _issue_code(par_body: dict | None = None) -> str:
    par = client.post("/par", data=with_jwt(par_body or VALID_PAR)).json()
    auth = client.get(
        "/authorize",
        params={
            "client_id": (par_body or VALID_PAR)["client_id"],
            "request_uri": par["request_uri"],
        },
    )
    assert auth.status_code == 200
    return auth.json()["code"]


def test_verify_pkce_s256_matches_challenge():
    assert verify_pkce(CODE_VERIFIER, CODE_CHALLENGE_S256, "S256")
    assert not verify_pkce("wrong-verifier", CODE_CHALLENGE_S256, "S256")


def test_verify_pkce_plain():
    assert verify_pkce("abc", "abc", "plain")
    assert not verify_pkce("abc", "xyz", "plain")


def test_authorize_stores_challenge_on_issued_code():
    code = _issue_code()
    entry = code_store._store[code]
    assert entry["code_challenge"] == CODE_CHALLENGE_S256
    assert entry["code_challenge_method"] == "S256"


def test_token_succeeds_with_correct_code_verifier():
    code = _issue_code()
    resp = client.post(
        "/token",
        data=with_jwt(
            {
                "grant_type": "authorization_code",
                "code": code,
                "client_id": VALID_PAR["client_id"],
                "code_verifier": CODE_VERIFIER,
            }
        ),
    )
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["token_type"] == "Bearer"
    assert "access_token" in payload


def test_token_rejects_incorrect_code_verifier():
    code = _issue_code()
    resp = client.post(
        "/token",
        data=with_jwt(
            {
                "grant_type": "authorization_code",
                "code": code,
                "client_id": VALID_PAR["client_id"],
                "code_verifier": "not-the-verifier",
            }
        ),
    )
    assert resp.status_code == 400
    assert "PKCE" in resp.json()["detail"]


def test_token_requires_code_verifier_when_enforced():
    code = _issue_code()
    resp = client.post(
        "/token",
        data=with_jwt(
            {
                "grant_type": "authorization_code",
                "code": code,
                "client_id": VALID_PAR["client_id"],
            }
        ),
    )
    assert resp.status_code == 400
    assert "code_verifier" in resp.json()["detail"]


def test_pkce_enforced_false_allows_token_without_verifier():
    settings.PKCE_ENFORCED = False
    code = _issue_code()
    resp = client.post(
        "/token",
        data=with_jwt(
            {
                "grant_type": "authorization_code",
                "code": code,
                "client_id": VALID_PAR["client_id"],
            }
        ),
    )
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_allow_plain_pkce_accepts_plain_method():
    settings.ALLOW_PLAIN_PKCE = True
    plain_par = {
        **VALID_PAR,
        "code_challenge": CODE_VERIFIER,
        "code_challenge_method": "plain",
    }
    code = _issue_code(plain_par)
    resp = client.post(
        "/token",
        data=with_jwt(
            {
                "grant_type": "authorization_code",
                "code": code,
                "client_id": VALID_PAR["client_id"],
                "code_verifier": CODE_VERIFIER,
            }
        ),
    )
    assert resp.status_code == 200


def test_plain_method_rejected_when_not_allowed():
    settings.PAR_ENFORCED = False
    auth = client.get(
        "/authorize",
        params={
            **VALID_PAR,
            "code_challenge": CODE_VERIFIER,
            "code_challenge_method": "plain",
        },
    )
    assert auth.status_code == 200
    resp = client.post(
        "/token",
        data=with_jwt(
            {
                "grant_type": "authorization_code",
                "code": auth.json()["code"],
                "client_id": VALID_PAR["client_id"],
                "code_verifier": CODE_VERIFIER,
            }
        ),
    )
    assert resp.status_code == 400
    assert "plain" in resp.json()["detail"]
