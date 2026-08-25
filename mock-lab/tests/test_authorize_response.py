from urllib.parse import parse_qs, urlparse

import jwt
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.routes.metadata import build_issuer
from app.tokens.issuer import PUBLIC_KEY, TOKEN_ALG
from tests.auth_helpers import with_jwt

client = TestClient(app)

VALID_PAR = {
    "client_id": "test-client",
    "redirect_uri": "https://client.example/callback",
    "scope": "openid accounts",
    "code_challenge": "E9Melhoa2OcwObgj_zthkQS-BglfS65ibk4BfLF0hVA",
    "code_challenge_method": "S256",
}


def _authorize(**extra_params):
    par = client.post("/par", data=with_jwt(VALID_PAR)).json()
    params = {
        "client_id": VALID_PAR["client_id"],
        "request_uri": par["request_uri"],
        **extra_params,
    }
    return client.get("/authorize", params=params)


def _query(url: str) -> dict:
    return {key: values[0] for key, values in parse_qs(urlparse(url).query).items()}


def test_iss_present_and_matches_metadata_issuer():
    resp = _authorize()
    assert resp.status_code == 200
    body = resp.json()
    issuer = build_issuer()
    assert body["iss"] == issuer
    query = _query(body["redirect"])
    assert query["iss"] == issuer
    assert query["code"] == body["code"]

    metadata = client.get("/.well-known/oauth-authorization-server").json()
    assert metadata["issuer"] == body["iss"]


def test_iss_omitted_when_toggled():
    settings.ISS_PARAM_OMITTED = True
    resp = _authorize()
    assert resp.status_code == 200
    body = resp.json()
    assert "iss" not in body
    assert "iss" not in _query(body["redirect"])
    assert "code" in _query(body["redirect"])


def test_redirect_uri_exact_match_enforced():
    resp = _authorize(redirect_uri="https://client.example/callback/extra")
    assert resp.status_code == 400
    assert "redirect_uri" in resp.json()["detail"]


def test_redirect_uri_loose_match_allows_prefix():
    settings.REDIRECT_URI_LOOSE_MATCH = True
    resp = _authorize(redirect_uri="https://client.example/callback/extra")
    assert resp.status_code == 200
    assert resp.json()["redirect"].startswith("https://client.example/callback/extra?")


def test_jarm_is_signed_by_default():
    resp = _authorize()
    assert resp.status_code == 200
    jarm = resp.json()["jarm"]
    claims = jwt.decode(
        jarm,
        PUBLIC_KEY,
        algorithms=[TOKEN_ALG],
        audience="test-client",
        issuer=build_issuer(),
    )
    assert claims["code"] == resp.json()["code"]
    assert jwt.get_unverified_header(jarm)["alg"] == "ES256"


def test_jarm_unsigned_when_signature_check_disabled():
    settings.JARM_SIGNATURE_CHECK = False
    resp = _authorize()
    assert resp.status_code == 200
    jarm = resp.json()["jarm"]
    header = jwt.get_unverified_header(jarm)
    assert header["alg"] == "none"
    claims = jwt.decode(jarm, options={"verify_signature": False})
    assert claims["code"] == resp.json()["code"]
