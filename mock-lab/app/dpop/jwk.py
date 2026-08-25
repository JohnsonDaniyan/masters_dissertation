import hashlib
import json
import base64

from jwt.algorithms import ECAlgorithm, RSAAlgorithm

from cryptography.hazmat.primitives.asymmetric import ec, rsa


def jwk_to_public_key(jwk: dict):
    kty = jwk.get("kty")
    if kty == "EC":
        return ECAlgorithm.from_jwk(jwk)
    if kty == "RSA":
        return RSAAlgorithm.from_jwk(jwk)
    raise ValueError("unsupported JWK kty")


def jwk_thumbprint(jwk: dict) -> str:
    kty = jwk.get("kty")
    if kty == "EC":
        members = {"crv": jwk["crv"], "kty": "EC", "x": jwk["x"], "y": jwk["y"]}
    elif kty == "RSA":
        members = {"e": jwk["e"], "kty": "RSA", "n": jwk["n"]}
    else:
        raise ValueError("unsupported JWK kty")
    canonical = json.dumps(members, separators=(",", ":"), sort_keys=True)
    digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def public_jwk_from_key(public_key) -> dict:
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return json.loads(ECAlgorithm.to_jwk(public_key))
    if isinstance(public_key, rsa.RSAPublicKey):
        return json.loads(RSAAlgorithm.to_jwk(public_key))
    raise ValueError("unsupported public key type")
