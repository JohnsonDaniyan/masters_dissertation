import jwt
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.registry.clients import RS_CLIENT_ID, TEST_CLIENT_ID
from app.tokens.issuer import PUBLIC_KEY, RESOURCE_AUDIENCE, TOKEN_ALG, is_jwt
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
ACCOUNTS_HTU = "http://testserver/accounts"


def _issue_dpop_token(key) -> str:
    par = client.post("/par", data=with_jwt(VALID_PAR)).json()
    auth = client.get(
        "/authorize",
        params={"client_id": TEST_CLIENT_ID, "request_uri": par["request_uri"]},
    )
    code = auth.json()["code"]
    proof = make_dpop_proof(key, "POST", TOKEN_HTU)
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
        headers={"DPoP": proof},
    )
    assert issued.status_code == 200
    return issued.json()["access_token"]


def test_structured_token_is_independently_verifiable_by_rs():
    key = new_dpop_key()
    access_token = _issue_dpop_token(key)
    assert is_jwt(access_token)

    claims = jwt.decode(
        access_token,
        PUBLIC_KEY,
        algorithms=[TOKEN_ALG],
        audience=RESOURCE_AUDIENCE,
        issuer=settings.ISSUER,
    )
    assert "jkt" in claims["cnf"]
    assert claims["client_id"] == TEST_CLIENT_ID

    jwks = client.get("/jwks").json()
    assert jwks["keys"][0]["kty"] == "EC"

    proof = make_dpop_proof(key, "GET", ACCOUNTS_HTU)
    resp = client.get(
        "/accounts",
        headers={"Authorization": f"DPoP {access_token}", "DPoP": proof},
    )
    assert resp.status_code == 200
    assert resp.json()["accounts"][0]["account_id"] == "acc-001"

    tx_proof = make_dpop_proof(key, "GET", "http://testserver/transactions")
    tx = client.get(
        "/transactions",
        headers={"Authorization": f"DPoP {access_token}", "DPoP": tx_proof},
    )
    assert tx.status_code == 200
    assert tx.json()["transactions"]


def test_unstructured_token_uses_introspection_path():
    settings.TOKEN_UNSTRUCTURED = True
    key = new_dpop_key()
    access_token = _issue_dpop_token(key)
    assert access_token.startswith("opaque-")

    unauth = client.post("/introspect", data={"token": access_token})
    assert unauth.status_code == 401

    introspected = client.post(
        "/introspect",
        data=with_jwt({"token": access_token, "client_id": RS_CLIENT_ID}),
    )
    assert introspected.status_code == 200
    body = introspected.json()
    assert body["active"] is True
    assert "jkt" in body["cnf"]

    proof = make_dpop_proof(key, "GET", ACCOUNTS_HTU)
    resp = client.get(
        "/accounts",
        headers={"Authorization": f"DPoP {access_token}", "DPoP": proof},
    )
    assert resp.status_code == 200
    assert resp.json()["accounts"]


def test_unauthenticated_introspection_allowed_when_not_required():
    settings.INTROSPECTION_AUTH_REQUIRED = False
    key = new_dpop_key()
    access_token = _issue_dpop_token(key)
    resp = client.post("/introspect", data={"token": access_token})
    assert resp.status_code == 200
    assert resp.json()["active"] is True


def test_rs_rejects_mismatched_binding_unless_it_trusts_the_as():
    key = new_dpop_key()
    access_token = _issue_dpop_token(key)
    other_key = new_dpop_key()
    bad_proof = make_dpop_proof(other_key, "GET", ACCOUNTS_HTU)

    rejected = client.get(
        "/accounts",
        headers={"Authorization": f"DPoP {access_token}", "DPoP": bad_proof},
    )
    assert rejected.status_code == 401

    settings.RS_TRUSTS_AS_BLINDLY = True
    allowed = client.get(
        "/accounts",
        headers={"Authorization": f"DPoP {access_token}", "DPoP": bad_proof},
    )
    assert allowed.status_code == 200
