from fastapi import APIRouter, Form, HTTPException, Request

from app.auth import require_client_auth
from app.config import settings
from app.store.par_store import (
    DEFAULT_TTL_SECONDS,
    LONG_LIVED_TTL_SECONDS,
    create_par_entry,
)

router = APIRouter()


@router.post("/par")
def pushed_authorization_request(
    request: Request,
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    scope: str = Form(...),
    code_challenge: str = Form(...),
    code_challenge_method: str = Form(...),
    client_assertion: str | None = Form(default=None),
    client_assertion_type: str | None = Form(default=None),
    client_secret: str | None = Form(default=None),
):
    if not client_id or not redirect_uri or not scope or not code_challenge:
        raise HTTPException(status_code=400, detail="invalid_request: missing parameter")

    if code_challenge_method != "S256" and not settings.ALLOW_PLAIN_PKCE:
        raise HTTPException(status_code=400, detail="invalid_request: only S256 supported")

    authenticated_id = require_client_auth(
        request,
        client_id,
        client_assertion,
        client_assertion_type,
        client_secret,
    )

    ttl = LONG_LIVED_TTL_SECONDS if settings.REQUEST_URI_LONG_LIVED else DEFAULT_TTL_SECONDS
    request_uri = create_par_entry(
        {
            "client_id": authenticated_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
        },
        ttl_seconds=ttl,
    )
    return {"request_uri": request_uri, "expires_in": ttl}
