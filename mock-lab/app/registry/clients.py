from __future__ import annotations

import datetime
import hashlib
import hmac
import secrets

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.dpop.jwk import jwk_to_public_key

TEST_CLIENT_ID = "test-client"
MTLS_CLIENT_ID = "mtls-client"
RS_CLIENT_ID = "mock-rs"
TEST_CLIENT_SECRET = "test-secret"

_DYNAMIC_IDS: set[str] = set()


def _rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _self_signed_cert(key, common_name: str) -> x509.Certificate:
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )


def cert_sha256_thumbprint(cert: x509.Certificate) -> str:
    der = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()


def cert_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


_jwt_key = _rsa_key()
_mtls_key = _rsa_key()
_rs_key = _rsa_key()
_mtls_cert = _self_signed_cert(_mtls_key, MTLS_CLIENT_ID)
_unregistered_key = _rsa_key()
UNREGISTERED_CERT_PEM = cert_pem(_self_signed_cert(_unregistered_key, "unregistered"))

CLIENTS: dict[str, dict] = {
    TEST_CLIENT_ID: {
        "private_key": _jwt_key,
        "public_key": _jwt_key.public_key(),
        "client_secret": TEST_CLIENT_SECRET,
        "cert_thumbprint": None,
        "cert_pem": None,
        "redirect_uris": ["https://client.example/callback"],
        "registration_access_token": None,
        "jwks": None,
    },
    MTLS_CLIENT_ID: {
        "private_key": None,
        "public_key": None,
        "client_secret": None,
        "cert_thumbprint": cert_sha256_thumbprint(_mtls_cert),
        "cert_pem": cert_pem(_mtls_cert),
        "redirect_uris": ["https://client.example/callback"],
        "registration_access_token": None,
        "jwks": None,
    },
    RS_CLIENT_ID: {
        "private_key": _rs_key,
        "public_key": _rs_key.public_key(),
        "client_secret": None,
        "cert_thumbprint": None,
        "cert_pem": None,
        "redirect_uris": [],
        "registration_access_token": None,
        "jwks": None,
    },
}


def get_client(client_id: str | None) -> dict | None:
    if not client_id:
        return None
    return CLIENTS.get(client_id)


def get_client_public_key(client_id: str):
    client = get_client(client_id)
    if not client or client.get("public_key") is None:
        raise ValueError("unknown client or no registered public key")
    return client["public_key"]


def get_client_private_key(client_id: str):
    client = get_client(client_id)
    if not client or client.get("private_key") is None:
        raise ValueError("unknown client or no private key")
    return client["private_key"]


def get_mtls_cert_pem() -> str:
    return CLIENTS[MTLS_CLIENT_ID]["cert_pem"]


def get_redirect_uris(client_id: str) -> list[str]:
    client = get_client(client_id)
    if not client:
        return []
    return list(client.get("redirect_uris") or [])


def client_id_for_thumbprint(thumbprint: str) -> str | None:
    wanted = thumbprint.lower()
    for client_id, client in CLIENTS.items():
        registered = client.get("cert_thumbprint")
        if registered and registered.lower() == wanted:
            return client_id
    return None


def verify_client_secret(client_id: str | None, secret: str | None) -> bool:
    client = get_client(client_id)
    if not client or not secret:
        return False
    expected = client.get("client_secret")
    if not expected:
        return False
    return hmac.compare_digest(expected, secret)


def clear_dynamic_clients() -> None:
    for client_id in list(_DYNAMIC_IDS):
        CLIENTS.pop(client_id, None)
    _DYNAMIC_IDS.clear()


def _apply_crypto(entry: dict, payload: dict) -> None:
    jwks = payload.get("jwks")
    if jwks and isinstance(jwks, dict) and jwks.get("keys"):
        entry["jwks"] = jwks
        try:
            entry["public_key"] = jwk_to_public_key(jwks["keys"][0])
        except Exception:
            entry["public_key"] = None
    if payload.get("tls_client_certificate"):
        pem = payload["tls_client_certificate"]
        cert = x509.load_pem_x509_certificate(pem.encode())
        entry["cert_pem"] = cert_pem(cert)
        entry["cert_thumbprint"] = cert_sha256_thumbprint(cert)
    if payload.get("cert_thumbprint"):
        entry["cert_thumbprint"] = payload["cert_thumbprint"]


def _public_view(client_id: str, client: dict) -> dict:
    return {
        "client_id": client_id,
        "redirect_uris": list(client.get("redirect_uris") or []),
        "jwks": client.get("jwks"),
        "cert_thumbprint": client.get("cert_thumbprint"),
        "token_endpoint_auth_method": client.get("token_endpoint_auth_method"),
        "registration_access_token": client.get("registration_access_token"),
        "registration_client_uri": f"/register/{client_id}",
    }


def register_client(payload: dict) -> dict:
    client_id = f"dcr-{secrets.token_urlsafe(12)}"
    entry = {
        "private_key": None,
        "public_key": None,
        "client_secret": None,
        "cert_thumbprint": None,
        "cert_pem": None,
        "redirect_uris": list(payload.get("redirect_uris") or []),
        "jwks": None,
        "token_endpoint_auth_method": payload.get(
            "token_endpoint_auth_method", "private_key_jwt"
        ),
        "registration_access_token": secrets.token_urlsafe(32),
    }
    _apply_crypto(entry, payload)
    CLIENTS[client_id] = entry
    _DYNAMIC_IDS.add(client_id)
    return _public_view(client_id, entry)


def update_client(client_id: str, payload: dict) -> dict:
    client = get_client(client_id)
    if client is None:
        raise KeyError(client_id)
    if "redirect_uris" in payload:
        client["redirect_uris"] = list(payload.get("redirect_uris") or [])
    if "token_endpoint_auth_method" in payload:
        client["token_endpoint_auth_method"] = payload["token_endpoint_auth_method"]
    _apply_crypto(client, payload)
    return _public_view(client_id, client)


def registration_access_token_matches(client_id: str, token: str | None) -> bool:
    client = get_client(client_id)
    expected = client.get("registration_access_token") if client else None
    if not expected or not token:
        return False
    return hmac.compare_digest(expected, token)
