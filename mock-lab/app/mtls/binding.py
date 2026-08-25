import base64
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from app.auth.mtls import normalize_cert_header


def cert_x5t_s256(cert: x509.Certificate) -> str:
    der = cert.public_bytes(serialization.Encoding.DER)
    digest = hashlib.sha256(der).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def presented_x5t_s256(cert_header: str) -> str:
    pem = normalize_cert_header(cert_header)
    cert = x509.load_pem_x509_certificate(pem.encode())
    return cert_x5t_s256(cert)


def token_matches_cert(cnf: dict, cert_header: str | None, enforce: bool) -> bool:
    expected = cnf.get("x5t#S256")
    if not expected:
        return True
    if not enforce:
        return True
    if not cert_header:
        return False
    try:
        return presented_x5t_s256(cert_header) == expected
    except Exception:
        return False
