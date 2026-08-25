import jwt

from app.config import settings
from app.dpop.jwk import jwk_thumbprint, jwk_to_public_key
from app.dpop.nonce_store import check_and_consume_jti, check_and_consume_nonce

ALLOWED_ALGS = {"ES256", "RS256"}


def validate_dpop_proof(proof: str, htm: str, htu: str, strict: bool) -> dict:
    try:
        header = jwt.get_unverified_header(proof)
        jwk = header.get("jwk")
        alg = header.get("alg")
        if not jwk or alg not in ALLOWED_ALGS:
            raise ValueError("DPoP header must include jwk and a supported alg")
        if header.get("typ") != "dpop+jwt" and strict:
            raise ValueError("DPoP typ must be dpop+jwt")

        public_key = jwk_to_public_key(jwk)
        claims = jwt.decode(proof, public_key, algorithms=[alg])
    except Exception:
        if not strict:
            return {"jkt": "unverified", "jti": "loose"}
        raise

    if strict:
        if claims.get("htm") != htm:
            raise ValueError("DPoP htm mismatch")
        if claims.get("htu") != htu:
            raise ValueError("DPoP htu mismatch")
        if not claims.get("jti"):
            raise ValueError("DPoP jti missing")
        if not claims.get("iat"):
            raise ValueError("DPoP iat missing")

    jkt = jwk_thumbprint(jwk)
    jti = claims.get("jti") or "loose"
    nonce = claims.get("nonce")
    if nonce and not check_and_consume_nonce(
        jkt, nonce, enforce=settings.DPOP_REPLAY_PROTECTION
    ):
        raise ValueError("DPoP nonce replay detected")

    return {"jkt": jkt, "jti": jti, "nonce": nonce}


def consume_proof_jti(jti: str, enforce: bool) -> None:
    if not check_and_consume_jti(jti, enforce=enforce):
        raise ValueError("DPoP proof replay detected")
