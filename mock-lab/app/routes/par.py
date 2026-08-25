from fastapi import APIRouter, Form, HTTPException

from app.config import settings
from app.store.par_store import (
    DEFAULT_TTL_SECONDS,
    LONG_LIVED_TTL_SECONDS,
    create_par_entry,
)

router = APIRouter()


@router.post("/par")
def pushed_authorization_request(
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    scope: str = Form(...),
    code_challenge: str = Form(...),
    code_challenge_method: str = Form(...),
):
    if not client_id or not redirect_uri or not scope or not code_challenge:
        raise HTTPException(status_code=400, detail="invalid_request: missing parameter")

    if code_challenge_method != "S256" and not settings.ALLOW_PLAIN_PKCE:
        raise HTTPException(status_code=400, detail="invalid_request: only S256 supported")

    ttl = LONG_LIVED_TTL_SECONDS if settings.REQUEST_URI_LONG_LIVED else DEFAULT_TTL_SECONDS
    request_uri = create_par_entry(
        {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
        },
        ttl_seconds=ttl,
    )
    return {"request_uri": request_uri, "expires_in": ttl}
