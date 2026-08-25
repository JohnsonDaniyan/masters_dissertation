import jwt
from fastapi import HTTPException, Request

from app.config import settings
from app.dpop.nonce_store import issue_nonce
from app.dpop.proof import consume_proof_jti, validate_dpop_proof
from app.mtls.binding import presented_x5t_s256
from app.store import token_store
from app.tokens.issuer import PUBLIC_KEY, RESOURCE_AUDIENCE, TOKEN_ALG, is_jwt


def request_htu(request: Request) -> str:
    return str(request.base_url).rstrip("/") + request.url.path


def verify_access_token(token: str) -> dict:
    return jwt.decode(
        token,
        PUBLIC_KEY,
        algorithms=[TOKEN_ALG],
        audience=RESOURCE_AUDIENCE,
        issuer=settings.ISSUER,
    )


def introspect_token(token: str) -> dict | None:
    record = token_store.lookup(token)
    if record is None and is_jwt(token):
        try:
            record = verify_access_token(token)
        except Exception:
            return None
    return record


def resolve_token_claims(token: str) -> tuple[dict, str]:
    """Return (claims, path) where path is 'jwt' or 'introspection'."""
    if is_jwt(token) and not settings.TOKEN_UNSTRUCTURED:
        try:
            return verify_access_token(token), "jwt"
        except Exception as exc:
            raise HTTPException(status_code=401, detail=f"invalid_token: {exc}") from exc

    record = introspect_token(token)
    if record is None:
        raise HTTPException(status_code=401, detail="invalid_token")
    return record, "introspection"


def verify_binding(token_claims: dict, presented_proof: dict) -> bool:
    if settings.RS_TRUSTS_AS_BLINDLY:
        return True
    cnf = token_claims.get("cnf") or {}
    if "jkt" in cnf:
        return cnf["jkt"] == presented_proof.get("jkt")
    if "x5t#S256" in cnf:
        if not settings.MTLS_BINDING_ENFORCED:
            return True
        return cnf["x5t#S256"] == presented_proof.get("cert_thumbprint")
    return False


def _presented_proof(request: Request, claims: dict) -> tuple[dict, dict]:
    presented: dict = {}
    headers: dict = {}
    cnf = claims.get("cnf") or {}

    if "jkt" in cnf and not settings.RS_TRUSTS_AS_BLINDLY:
        proof = request.headers.get("dpop")
        if not proof:
            raise HTTPException(status_code=401, detail="invalid_dpop_proof: DPoP proof required")
        try:
            result = validate_dpop_proof(
                proof, request.method, request_htu(request), settings.DPOP_VALIDATION_STRICT
            )
            if result.get("jti") and result["jti"] != "loose":
                consume_proof_jti(result["jti"], enforce=settings.DPOP_REPLAY_PROTECTION)
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=401, detail=f"invalid_dpop_proof: {exc}"
            ) from exc
        presented["jkt"] = result["jkt"]
        headers["DPoP-Nonce"] = issue_nonce(result["jkt"])

    cert_header = request.headers.get("x-ssl-client-cert")
    if cert_header:
        try:
            presented["cert_thumbprint"] = presented_x5t_s256(cert_header)
        except Exception:
            presented["cert_thumbprint"] = None

    return presented, headers


def extract_access_token(request: Request) -> str:
    header = request.headers.get("authorization")
    if not header:
        raise HTTPException(status_code=401, detail="invalid_request: access token required")
    scheme, _, value = header.partition(" ")
    if scheme.lower() not in ("bearer", "dpop") or not value:
        raise HTTPException(status_code=401, detail="invalid_request: access token required")
    return value.strip()


def authorize_resource(request: Request) -> tuple[dict, dict]:
    token = extract_access_token(request)
    claims, _path = resolve_token_claims(token)
    presented, headers = _presented_proof(request, claims)
    if not verify_binding(claims, presented):
        raise HTTPException(
            status_code=401,
            detail="invalid_token: sender-constrained binding check failed",
        )
    return claims, headers
