import jwt

from app.auth.jti_store import is_replay
from app.config import settings
from app.registry.clients import get_client_public_key

ALLOWED_ALGS = {"RS256", "ES256"}


def validate_client_assertion(assertion: str, expected_audience: str) -> str:
    header = jwt.get_unverified_header(assertion)
    alg = header.get("alg")
    if alg not in ALLOWED_ALGS:
        raise ValueError("unsupported client assertion algorithm")

    unverified = jwt.decode(assertion, options={"verify_signature": False, "verify_aud": False})
    client_id = unverified.get("sub")
    if not client_id:
        raise ValueError("client assertion missing sub")
    if unverified.get("iss") != client_id:
        raise ValueError("client assertion iss must equal sub")
    if not unverified.get("jti"):
        raise ValueError("client assertion missing jti")

    public_key = get_client_public_key(client_id)
    claims = jwt.decode(
        assertion,
        public_key,
        algorithms=["RS256", "ES256"],
        audience=expected_audience,
    )

    if is_replay(claims["jti"], allow_replay=not settings.JWT_REPLAY_PROTECTION):
        raise ValueError("client assertion replay detected")

    return client_id
