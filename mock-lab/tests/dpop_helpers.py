import time
import uuid

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from app.dpop.jwk import public_jwk_from_key


def new_dpop_key():
    return ec.generate_private_key(ec.SECP256R1())


def make_dpop_proof(private_key, htm: str, htu: str, jti: str | None = None, nonce: str | None = None) -> str:
    jwk = public_jwk_from_key(private_key.public_key())
    now = int(time.time())
    claims = {
        "htm": htm,
        "htu": htu,
        "jti": jti or str(uuid.uuid4()),
        "iat": now,
    }
    if nonce:
        claims["nonce"] = nonce
    return jwt.encode(
        claims,
        private_key,
        algorithm="ES256",
        headers={"typ": "dpop+jwt", "jwk": jwk},
    )
