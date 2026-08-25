from fastapi import APIRouter, Response
from app.config import settings

router = APIRouter()

def build_issuer() -> str:
    if settings.ISSUER_MALFORMED:
        # deliberately break the format: add a query string, which
        # RFC 9207 / FAPI 2.0 explicitly forbids in an issuer identifier
        return settings.ISSUER + "?malformed=true"
    if settings.ISSUER_MISMATCH:
        # return a different issuer than what appears elsewhere (e.g. token claims)
        return settings.ISSUER.replace("mock-as", "mock-as-attacker")
    return settings.ISSUER

@router.get("/.well-known/oauth-authorization-server")
def metadata():
    if not settings.METADATA_ENABLED:
        return Response(status_code=404)

    doc = {
        "issuer": build_issuer(),
        "authorization_endpoint": f"{settings.BASE_URL}/authorize",
        "pushed_authorization_request_endpoint": f"{settings.BASE_URL}/par",
        "token_endpoint": f"{settings.BASE_URL}/token",
        "introspection_endpoint": f"{settings.BASE_URL}/introspect",
        "jwks_uri": f"{settings.BASE_URL}/jwks",
        "token_endpoint_auth_methods_supported": ["private_key_jwt", "tls_client_auth"],
        "dpop_signing_alg_values_supported": ["ES256"],
        "require_pushed_authorization_requests": settings.PAR_ENFORCED,
    }

    if settings.METADATA_INCOMPLETE:
        # deliberately drop a mandatory field for the "incomplete document" test
        doc.pop("pushed_authorization_request_endpoint", None)

    return doc