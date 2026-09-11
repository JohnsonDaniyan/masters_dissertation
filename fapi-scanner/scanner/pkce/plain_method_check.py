from scanner.flows.baseline import FlowState, ensure_registered, par_body
from scanner.crypto.pkce import generate_pkce
from scanner.flows.http import accepted
from scanner.flows import http
from scanner.reporting.helpers import outcome, transport_error

CHECK_ID = "PKCE-002"
DESCRIPTION = "Rejection of plain PKCE method"
REFERENCE = "RFC 7636 S256; FAPI 2.0 — weak PKCE method."


def check_plain_pkce_method(ctx) -> object:
    endpoint = ctx.par_url
    try:
        ensure_registered(ctx)
        verifier, _challenge = generate_pkce()
        state = FlowState(metadata=ctx.metadata, code_challenge=verifier, code_verifier=verifier)
        response = http.post_form(endpoint, par_body(ctx, verifier, method="plain"))
        _ = state
    except Exception as exc:
        return transport_error(CHECK_ID, DESCRIPTION, endpoint, exc, REFERENCE)

    return outcome(
        check_id=CHECK_ID,
        description=DESCRIPTION,
        endpoint=endpoint,
        passed=not accepted(response.status_code),
        pass_detail="PAR correctly rejected code_challenge_method=plain.",
        fail_detail="PAR accepted code_challenge_method=plain.",
        remedy="Require S256 PKCE unless a documented exception applies.",
        reference=REFERENCE,
    )
