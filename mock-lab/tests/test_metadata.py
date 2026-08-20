from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_metadata_returns_200_and_required_fields():
    resp = client.get("/.well-known/oauth-authorization-server")
    assert resp.status_code == 200
    doc = resp.json()
    for field in ["issuer", "authorization_endpoint", "pushed_authorization_request_endpoint",
                  "token_endpoint", "jwks_uri"]:
        assert field in doc

def test_issuer_is_https_no_query_or_fragment():
    resp = client.get("/.well-known/oauth-authorization-server")
    issuer = resp.json()["issuer"]
    assert issuer.startswith("https://")
    assert "?" not in issuer
    assert "#" not in issuer