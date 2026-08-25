import time
import uuid

import jwt

from app.config import settings
from app.registry.clients import TEST_CLIENT_ID, get_client_private_key

JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


def make_client_assertion(
    client_id: str = TEST_CLIENT_ID,
    jti: str | None = None,
    **overrides,
) -> str:
    now = int(time.time())
    payload = {
        "iss": client_id,
        "sub": client_id,
        "aud": settings.ISSUER,
        "jti": jti or str(uuid.uuid4()),
        "iat": now,
        "exp": now + 60,
        "nbf": now,
    }
    payload.update(overrides)
    return jwt.encode(payload, get_client_private_key(client_id), algorithm="RS256")


def with_jwt(data: dict, jti: str | None = None, client_id: str | None = None) -> dict:
    cid = client_id or data.get("client_id") or TEST_CLIENT_ID
    return {
        **data,
        "client_assertion_type": JWT_BEARER,
        "client_assertion": make_client_assertion(cid, jti=jti),
    }
