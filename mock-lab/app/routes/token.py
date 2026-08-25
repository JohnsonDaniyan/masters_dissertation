from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import JSONResponse

from app.auth import require_client_auth
from app.config import settings
from app.crypto.pkce import verify_pkce
from app.dpop.nonce_store import issue_nonce
from app.dpop.proof import consume_proof_jti, validate_dpop_proof
from app.mtls.binding import presented_x5t_s256
from app.store.code_store import consume_code
from app.tokens.issuer import issue_access_token

router = APIRouter()


def request_htu(request: Request) -> str:
    return str(request.base_url).rstrip("/") + request.url.path


def handle_authorization_code_grant(code_entry: dict, code_verifier: str | None) -> None:
    if settings.PKCE_ENFORCED and not code_verifier:
        raise HTTPException(status_code=400, detail="invalid_grant: code_verifier required")

    if code_verifier:
        method = code_entry["code_challenge_method"]
        if method == "plain" and not settings.ALLOW_PLAIN_PKCE:
            raise HTTPException(status_code=400, detail="invalid_request: plain method not allowed")
        if not verify_pkce(code_verifier, code_entry["code_challenge"], method):
            raise HTTPException(status_code=400, detail="invalid_grant: PKCE verification failed")


def _dpop_from_request(request: Request) -> dict | None:
    proof = request.headers.get("dpop")
    if not proof:
        return None
    try:
        result = validate_dpop_proof(
            proof, "POST", request_htu(request), settings.DPOP_VALIDATION_STRICT
        )
        if result.get("jti") and result["jti"] != "loose":
            consume_proof_jti(result["jti"], enforce=settings.DPOP_REPLAY_PROTECTION)
        return result
    except Exception as exc:
        if settings.DPOP_VALIDATION_STRICT:
            raise HTTPException(
                status_code=400, detail=f"invalid_dpop_proof: {exc}"
            ) from exc
        return {"jkt": "unverified", "jti": "loose"}


@router.post("/token")
def token(
    request: Request,
    grant_type: str = Form(...),
    code: str = Form(...),
    redirect_uri: str | None = Form(default=None),
    client_id: str | None = Form(default=None),
    code_verifier: str | None = Form(default=None),
    client_assertion: str | None = Form(default=None),
    client_assertion_type: str | None = Form(default=None),
    client_secret: str | None = Form(default=None),
):
    if grant_type != "authorization_code":
        raise HTTPException(status_code=400, detail="unsupported_grant_type")

    authenticated_id = require_client_auth(
        request,
        client_id,
        client_assertion,
        client_assertion_type,
        client_secret,
    )

    dpop_result = _dpop_from_request(request)

    code_entry = consume_code(code)
    if code_entry is None:
        raise HTTPException(status_code=400, detail="invalid_grant: unknown or used code")

    if authenticated_id != code_entry["client_id"]:
        raise HTTPException(status_code=401, detail="invalid_client: client_id mismatch")
    if redirect_uri and redirect_uri != code_entry["redirect_uri"]:
        raise HTTPException(status_code=400, detail="invalid_grant: redirect_uri mismatch")
    if client_id and client_id != code_entry["client_id"]:
        raise HTTPException(status_code=400, detail="invalid_grant: client_id mismatch")

    handle_authorization_code_grant(code_entry, code_verifier)

    cnf: dict = {}
    token_type = "Bearer"
    headers = {}
    if dpop_result:
        cnf["jkt"] = dpop_result["jkt"]
        token_type = "DPoP"
        headers["DPoP-Nonce"] = issue_nonce(dpop_result["jkt"])
    else:
        cert_header = request.headers.get("x-ssl-client-cert")
        if cert_header:
            try:
                cnf["x5t#S256"] = presented_x5t_s256(cert_header)
            except Exception as exc:
                raise HTTPException(
                    status_code=400, detail=f"invalid_client: bad client certificate ({exc})"
                ) from exc

    access_token, _ = issue_access_token(
        client_id=authenticated_id,
        scope=code_entry["scope"],
        cnf=cnf,
        token_type=token_type,
    )
    body = {
        "access_token": access_token,
        "token_type": token_type,
        "expires_in": 3600,
        "scope": code_entry["scope"],
    }
    if cnf:
        body["cnf"] = cnf
    return JSONResponse(content=body, headers=headers)
