"""Keys and certificate the scanner uses as its own OAuth client."""

import datetime
import json
from urllib.parse import quote

from cryptography import x509

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
from jwt.algorithms import ECAlgorithm, RSAAlgorithm


class ClientIdentity:
    def __init__(self):
        self.rsa_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.dpop_private = ec.generate_private_key(ec.SECP256R1())
        self.mtls_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.cert = self._self_signed_cert(self.mtls_private)

    def _self_signed_cert(self, key) -> x509.Certificate:
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fapi-scanner")])
        now = datetime.datetime.now(datetime.timezone.utc)
        return (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256())
        )

    @property
    def rsa_public_jwk(self) -> dict:
        raw = RSAAlgorithm.to_jwk(self.rsa_private.public_key())
        return json.loads(raw) if isinstance(raw, str) else raw

    @property
    def dpop_public_jwk(self) -> dict:
        raw = ECAlgorithm.to_jwk(self.dpop_private.public_key())
        return json.loads(raw) if isinstance(raw, str) else raw

    @property
    def cert_pem(self) -> str:
        return self.cert.public_bytes(serialization.Encoding.PEM).decode()

    @property
    def cert_header(self) -> str:
        """PEM without raw newlines — httpx rejects control characters in headers."""
        return quote(self.cert_pem, safe="")
