from scanner.flows.baseline import (
    BaselineBroken,
    FlowState,
    client_assertion,
    complete_authorization,
    ensure_registered,
    push_authorization_request,
)
from scanner.crypto.pkce import generate_pkce
from scanner.flows import http
from scanner.flows.http import accepted
from scanner.reporting.helpers import outcome, transport_error

CHECK_ID = "MTLS-002"
DESCRIPTION = "mTLS access-token binding at the resource server"
REFERENCE = "RFC 8705 cnf.x5t#S256; FAPI 2.0 token binding bypass."


def check_mtls_token_binding(ctx) -> object:
    endpoint = ctx.accounts_url
    try:
        ensure_registered(ctx)
        state = FlowState(metadata=ctx.metadata)
        push_authorization_request(ctx, state)
        complete_authorization(ctx, state)
        token = http.post_form(
            ctx.token_url,
            {
                "grant_type": "authorization_code",
                "code": state.auth_code,
                "client_id": ctx.client_id,
                "code_verifier": state.code_verifier,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": client_assertion(ctx),
            },
            headers={"X-SSL-Client-Cert": ctx.identity.cert_header},
        )
        if not accepted(token.status_code):
            raise BaselineBroken(f"mTLS token request failed (HTTP {token.status_code})")
        access_token = token.json()["access_token"]
        response = http.get(endpoint, headers={"Authorization": f"Bearer {access_token}"})
    except (BaselineBroken, Exception) as exc:
        return transport_error(CHECK_ID, DESCRIPTION, endpoint, exc, REFERENCE)

    return outcome(
        check_id=CHECK_ID,
        description=DESCRIPTION,
        endpoint=endpoint,
        passed=not accepted(response.status_code),
        pass_detail="Resource server rejected the token without a matching client certificate.",
        fail_detail="Resource server accepted an mTLS-bound token without the client certificate.",
        remedy="Re-check cnf.x5t#S256 against the presented certificate on every resource request.",
        reference=REFERENCE,
    )
