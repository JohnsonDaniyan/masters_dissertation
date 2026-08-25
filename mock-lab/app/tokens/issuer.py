import secrets
import time

import jwt
from cryptography.hazmat.primitives.asymmetric import ec

from app.config import settings
from app.dpop.jwk import public_jwk_from_key
from app.store import token_store

RESOURCE_AUDIENCE = "mock-rs"

PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1())
PUBLIC_KEY = PRIVATE_KEY.public_key()
TOKEN_ALG = "ES256"


def as_jwk() -> dict:
    jwk = public_jwk_from_key(PUBLIC_KEY)
    jwk["use"] = "sig"
    jwk["alg"] = TOKEN_ALG
    jwk["kid"] = "mock-as-token"
    return jwk


def is_jwt(token: str) -> bool:
    return token.count(".") == 2 and not token.startswith("opaque-")


def issue_access_token(
    *,
    client_id: str,
    scope: str,
    cnf: dict | None = None,
    token_type: str = "Bearer",
    subject: str | None = None,
) -> tuple[str, dict]:
    now = int(time.time())
    claims = {
        "iss": settings.ISSUER,
        "sub": subject or client_id,
        "aud": RESOURCE_AUDIENCE,
        "client_id": client_id,
        "scope": scope,
        "iat": now,
        "exp": now + 3600,
        "token_type": token_type,
    }
    if cnf:
        claims["cnf"] = cnf

    if settings.TOKEN_UNSTRUCTURED:
        token = f"opaque-{secrets.token_urlsafe(24)}"
    else:
        token = jwt.encode(
            claims,
            PRIVATE_KEY,
            algorithm=TOKEN_ALG,
            headers={"kid": "mock-as-token", "typ": "at+jwt"},
        )

    token_store.store(token, claims)
    return token, claims
