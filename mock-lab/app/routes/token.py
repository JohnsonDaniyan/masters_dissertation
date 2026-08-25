import secrets

from fastapi import APIRouter, Form, HTTPException, Request

from app.auth import require_client_auth
from app.config import settings
from app.crypto.pkce import verify_pkce
from app.store.code_store import consume_code

router = APIRouter()


def handle_authorization_code_grant(code_entry: dict, code_verifier: str | None) -> None:
    if settings.PKCE_ENFORCED and not code_verifier:
        raise HTTPException(status_code=400, detail="invalid_grant: code_verifier required")

    if code_verifier:
        method = code_entry["code_challenge_method"]
        if method == "plain" and not settings.ALLOW_PLAIN_PKCE:
            raise HTTPException(status_code=400, detail="invalid_request: plain method not allowed")
        if not verify_pkce(code_verifier, code_entry["code_challenge"], method):
            raise HTTPException(status_code=400, detail="invalid_grant: PKCE verification failed")


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

    return {
        "access_token": secrets.token_urlsafe(32),
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": code_entry["scope"],
    }
