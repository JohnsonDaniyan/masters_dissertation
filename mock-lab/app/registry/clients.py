from __future__ import annotations

import datetime
import hashlib
import hmac

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

TEST_CLIENT_ID = "test-client"
MTLS_CLIENT_ID = "mtls-client"
RS_CLIENT_ID = "mock-rs"
TEST_CLIENT_SECRET = "test-secret"


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
    },
    MTLS_CLIENT_ID: {
        "private_key": None,
        "public_key": None,
        "client_secret": None,
        "cert_thumbprint": cert_sha256_thumbprint(_mtls_cert),
        "cert_pem": cert_pem(_mtls_cert),
        "redirect_uris": ["https://client.example/callback"],
    },
    RS_CLIENT_ID: {
        "private_key": _rs_key,
        "public_key": _rs_key.public_key(),
        "client_secret": None,
        "cert_thumbprint": None,
        "cert_pem": None,
        "redirect_uris": [],
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
