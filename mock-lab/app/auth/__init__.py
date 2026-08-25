import base64

from fastapi import HTTPException, Request

from app.auth.mtls import validate_mtls
from app.auth.private_key_jwt import validate_client_assertion
from app.config import settings
from app.registry.clients import verify_client_secret

JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


def _parse_basic(request: Request) -> tuple[str, str] | None:
    header = request.headers.get("authorization")
    if not header or not header.lower().startswith("basic "):
        return None
    try:
        decoded = base64.b64decode(header.split(" ", 1)[1]).decode()
        client_id, secret = decoded.split(":", 1)
    except (ValueError, UnicodeDecodeError):
        raise HTTPException(status_code=401, detail="invalid_client: malformed Authorization header")
    return client_id, secret


def require_client_auth(
    request: Request,
    client_id: str | None,
    client_assertion: str | None = None,
    client_assertion_type: str | None = None,
    client_secret: str | None = None,
) -> str:
    basic = _parse_basic(request)
    if basic or client_secret:
        if not settings.ALLOW_WEAK_CLIENT_AUTH:
            raise HTTPException(
                status_code=401,
                detail="invalid_client: client secret authentication is not allowed",
            )
        cid, secret = basic if basic else (client_id, client_secret)
        if not verify_client_secret(cid, secret):
            raise HTTPException(status_code=401, detail="invalid_client: invalid client secret")
        return cid

    if client_assertion:
        if client_assertion_type and client_assertion_type != JWT_BEARER:
            raise HTTPException(
                status_code=400,
                detail="invalid_request: unsupported client_assertion_type",
            )
        try:
            asserted_id = validate_client_assertion(client_assertion, settings.ISSUER)
        except Exception as exc:
            raise HTTPException(status_code=401, detail=f"invalid_client: {exc}") from exc
        if client_id and client_id != asserted_id:
            raise HTTPException(
                status_code=401,
                detail="invalid_client: client_id does not match assertion",
            )
        return asserted_id

    cert_header = request.headers.get("x-ssl-client-cert")
    if cert_header:
        try:
            return validate_mtls(cert_header, client_id)
        except Exception as exc:
            raise HTTPException(status_code=401, detail=f"invalid_client: {exc}") from exc

    if not settings.MTLS_CLIENT_AUTH_ENFORCED and client_id:
        return client_id

    raise HTTPException(status_code=401, detail="invalid_client: client authentication required")
