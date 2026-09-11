import time
import uuid

import jwt


def build_client_assertion(client_id: str, audience: str, private_key, jti: str | None = None) -> str:
    now = int(time.time())
    payload = {
        "iss": client_id,
        "sub": client_id,
        "aud": audience,
        "jti": jti or str(uuid.uuid4()),
        "iat": now,
        "exp": now + 60,
    }
    return jwt.encode(payload, private_key, algorithm="RS256")
