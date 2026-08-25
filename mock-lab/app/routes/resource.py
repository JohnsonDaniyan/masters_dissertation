from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from app.config import settings
from app.dpop.nonce_store import issue_nonce
from app.dpop.proof import consume_proof_jti, validate_dpop_proof
from app.mtls.binding import token_matches_cert
from app.routes.token import request_htu
from app.store.token_store import lookup

router = APIRouter()


def _bearer_token(request: Request) -> str | None:
    header = request.headers.get("authorization")
    if not header:
        return None
    scheme, _, value = header.partition(" ")
    if scheme.lower() not in ("bearer", "dpop") or not value:
        return None
    return value.strip()


@router.get("/resource")
def resource(request: Request):
    token = _bearer_token(request)
    if not token:
        raise HTTPException(status_code=401, detail="invalid_request: access token required")

    record = lookup(token)
    if record is None:
        raise HTTPException(status_code=401, detail="invalid_token")

    cnf = record.get("cnf") or {}
    headers = {}

    if "jkt" in cnf:
        proof = request.headers.get("dpop")
        if not proof:
            raise HTTPException(status_code=401, detail="invalid_dpop_proof: DPoP proof required")
        try:
            result = validate_dpop_proof(
                proof, "GET", request_htu(request), settings.DPOP_VALIDATION_STRICT
            )
            if result.get("jti") and result["jti"] != "loose":
                consume_proof_jti(result["jti"], enforce=settings.DPOP_REPLAY_PROTECTION)
        except Exception as exc:
            raise HTTPException(
                status_code=401, detail=f"invalid_dpop_proof: {exc}"
            ) from exc
        if settings.DPOP_VALIDATION_STRICT and result["jkt"] != cnf["jkt"]:
            raise HTTPException(status_code=401, detail="invalid_dpop_proof: jkt mismatch")
        headers["DPoP-Nonce"] = issue_nonce(result["jkt"])

    if "x5t#S256" in cnf:
        cert_header = request.headers.get("x-ssl-client-cert")
        if not token_matches_cert(cnf, cert_header, settings.MTLS_BINDING_ENFORCED):
            raise HTTPException(
                status_code=401,
                detail="invalid_token: mTLS certificate does not match token confirmation",
            )

    return JSONResponse(
        content={"status": "ok", "client_id": record["client_id"], "scope": record["scope"]},
        headers=headers,
    )
