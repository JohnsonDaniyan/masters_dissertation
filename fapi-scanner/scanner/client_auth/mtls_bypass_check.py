from scanner.crypto.pkce import generate_pkce
from scanner.flows.http import accepted
from scanner.flows import http
from scanner.reporting.helpers import outcome, transport_error

CHECK_ID = "AUTH-002"
DESCRIPTION = "mTLS client authentication enforcement"
REFERENCE = "RFC 8705; FAPI 2.0 tls_client_auth — client impersonation."


def check_mtls_bypass(ctx) -> object:
    """PAR with a full body but no client assertion and no client certificate."""
    endpoint = ctx.par_url
    try:
        _verifier, challenge = generate_pkce()
        response = http.post_form(
            endpoint,
            {
                "client_id": ctx.client_id or "scanner-test-client",
                "redirect_uri": ctx.redirect_uri,
                "scope": ctx.scope,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
    except Exception as exc:
        return transport_error(CHECK_ID, DESCRIPTION, endpoint, exc, REFERENCE)

    return outcome(
        check_id=CHECK_ID,
        description=DESCRIPTION,
        endpoint=endpoint,
        passed=not accepted(response.status_code),
        pass_detail="Request without a client certificate or assertion was rejected.",
        fail_detail="PAR succeeded with no client certificate and no private_key_jwt.",
        remedy="Require tls_client_auth or private_key_jwt at PAR and token endpoints.",
        reference=REFERENCE,
    )
