import time
import uuid

import jwt


def build_dpop_proof(htm: str, htu: str, private_key, jwk: dict, malformed: bool = False) -> str:
    payload = {"jti": str(uuid.uuid4()), "iat": int(time.time())}
    if not malformed:
        payload["htm"] = htm
        payload["htu"] = htu
    headers = {"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk}
    return jwt.encode(payload, private_key, algorithm="ES256", headers=headers)
