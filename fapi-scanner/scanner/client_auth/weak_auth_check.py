import base64

from scanner.crypto.pkce import generate_pkce
from scanner.flows.http import accepted
from scanner.flows import http
from scanner.reporting.helpers import outcome, transport_error

CHECK_ID = "AUTH-003"
DESCRIPTION = "Rejection of secret-based client authentication"
REFERENCE = "FAPI 2.0 — only private_key_jwt and tls_client_auth are permitted."


def check_weak_client_auth(ctx) -> object:
    endpoint = ctx.par_url
    try:
        _verifier, challenge = generate_pkce()
        basic = base64.b64encode(b"test-client:test-secret").decode()
        response = http.post_form(
            endpoint,
            {
                "client_id": "test-client",
                "redirect_uri": ctx.redirect_uri,
                "scope": ctx.scope,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
            headers={"Authorization": f"Basic {basic}"},
        )
    except Exception as exc:
        return transport_error(CHECK_ID, DESCRIPTION, endpoint, exc, REFERENCE)

    return outcome(
        check_id=CHECK_ID,
        description=DESCRIPTION,
        endpoint=endpoint,
        passed=not accepted(response.status_code),
        pass_detail="client_secret_basic was rejected.",
        fail_detail="client_secret_basic was accepted at the PAR endpoint.",
        remedy="Reject client_secret_basic and client_secret_post.",
        reference=REFERENCE,
    )
