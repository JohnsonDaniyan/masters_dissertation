from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient

from app.config import settings
from app.dpop.jwk import public_jwk_from_key
from app.main import app
from app.registry.clients import get_client

client = TestClient(app)

IAT = "lab-initial-access-token"


def _jwks():
    key = ec.generate_private_key(ec.SECP256R1())
    return {"keys": [public_jwk_from_key(key.public_key())]}


def _payload(**overrides):
    body = {
        "redirect_uris": ["https://dcr.example/callback"],
        "token_endpoint_auth_method": "private_key_jwt",
        "jwks": _jwks(),
    }
    body.update(overrides)
    return body


def test_registration_rejected_without_initial_access_token():
    resp = client.post("/register", json=_payload())
    assert resp.status_code == 401
    assert "initial access token" in resp.json()["detail"]


def test_registration_succeeds_with_initial_access_token():
    resp = client.post(
        "/register",
        json=_payload(),
        headers={"Authorization": f"Bearer {IAT}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["client_id"].startswith("dcr-")
    assert body["registration_access_token"]
    assert body["jwks"]["keys"]
    stored = get_client(body["client_id"])
    assert stored is not None
    assert stored["public_key"] is not None


def test_open_registration_allows_unauthenticated_post():
    settings.DCR_OPEN_REGISTRATION = True
    resp = client.post("/register", json=_payload())
    assert resp.status_code == 200
    assert resp.json()["client_id"]


def test_config_update_rejected_without_registration_access_token():
    created = client.post(
        "/register",
        json=_payload(),
        headers={"Authorization": f"Bearer {IAT}"},
    ).json()
    resp = client.put(
        f"/register/{created['client_id']}",
        json={"redirect_uris": ["https://dcr.example/new"]},
    )
    assert resp.status_code == 401
    assert "registration access token" in resp.json()["detail"]


def test_config_update_with_registration_access_token():
    created = client.post(
        "/register",
        json=_payload(),
        headers={"Authorization": f"Bearer {IAT}"},
    ).json()
    resp = client.put(
        f"/register/{created['client_id']}",
        json={"redirect_uris": ["https://dcr.example/new"]},
        headers={"Authorization": f"Bearer {created['registration_access_token']}"},
    )
    assert resp.status_code == 200
    assert resp.json()["redirect_uris"] == ["https://dcr.example/new"]


def test_dcm_auth_not_required_allows_unauthenticated_update():
    settings.DCM_AUTH_REQUIRED = False
    created = client.post(
        "/register",
        json=_payload(),
        headers={"Authorization": f"Bearer {IAT}"},
    ).json()
    resp = client.put(
        f"/register/{created['client_id']}",
        json={"redirect_uris": ["https://dcr.example/open"]},
    )
    assert resp.status_code == 200
    assert resp.json()["redirect_uris"] == ["https://dcr.example/open"]
