import time

import jwt

from app.config import settings
from app.routes.metadata import build_issuer
from app.tokens.issuer import PRIVATE_KEY, TOKEN_ALG


def wrap_as_jarm(params: dict, audience: str) -> str:
    payload = {
        **params,
        "iss": build_issuer(),
        "aud": audience,
        "exp": int(time.time()) + 60,
    }
    if settings.JARM_SIGNATURE_CHECK:
        return jwt.encode(
            payload,
            PRIVATE_KEY,
            algorithm=TOKEN_ALG,
            headers={"typ": "JWT", "kid": "mock-as-token"},
        )
    return jwt.encode(payload, None, algorithm="none")
