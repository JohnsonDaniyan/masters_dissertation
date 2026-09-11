from fastapi import APIRouter, Body, Header, HTTPException

from app.config import settings
from app.registry.clients import (
    register_client,
    registration_access_token_matches,
    update_client,
)

router = APIRouter()


def _bearer(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


@router.post("/register")
def dynamic_client_registration(
    payload: dict = Body(default_factory=dict),
    authorization: str | None = Header(default=None),
):
    if not settings.DCR_OPEN_REGISTRATION:
        token = _bearer(authorization)
        if token != settings.INITIAL_ACCESS_TOKEN:
            raise HTTPException(status_code=401, detail="initial access token required")
    return register_client(payload)


@router.put("/register/{client_id}")
def dynamic_client_management(
    client_id: str,
    payload: dict = Body(default_factory=dict),
    authorization: str | None = Header(default=None),
):
    if settings.DCM_AUTH_REQUIRED:
        token = _bearer(authorization)
        if not registration_access_token_matches(client_id, token):
            raise HTTPException(
                status_code=401, detail="registration access token required"
            )
    try:
        return update_client(client_id, payload)
    except KeyError:
        raise HTTPException(status_code=404, detail="unknown client_id") from None
