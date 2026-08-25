from fastapi import APIRouter, Form, Request

from app.auth import require_client_auth
from app.config import settings
from app.tokens.verifier import introspect_token

router = APIRouter()


@router.post("/introspect")
def introspect(
    request: Request,
    token: str = Form(...),
    token_type_hint: str | None = Form(default=None),
    client_id: str | None = Form(default=None),
    client_assertion: str | None = Form(default=None),
    client_assertion_type: str | None = Form(default=None),
    client_secret: str | None = Form(default=None),
):
    if settings.INTROSPECTION_AUTH_REQUIRED:
        require_client_auth(
            request,
            client_id,
            client_assertion,
            client_assertion_type,
            client_secret,
        )

    record = introspect_token(token)
    if record is None:
        return {"active": False}

    return {
        "active": True,
        "iss": record.get("iss"),
        "sub": record.get("sub"),
        "aud": record.get("aud"),
        "client_id": record.get("client_id"),
        "scope": record.get("scope"),
        "exp": record.get("exp"),
        "iat": record.get("iat"),
        "token_type": record.get("token_type"),
        "cnf": record.get("cnf") or {},
        "token_type_hint": token_type_hint,
    }
