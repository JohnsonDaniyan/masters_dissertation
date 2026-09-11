from scanner.flows.baseline import (
    BaselineBroken,
    FlowState,
    complete_authorization,
    exchange_token,
    push_authorization_request,
)
from scanner.flows.http import accepted
from scanner.reporting.helpers import outcome, transport_error

CHECK_ID = "PKCE-001"
DESCRIPTION = "PKCE enforcement at token endpoint"
REFERENCE = "RFC 7636; FAPI 2.0 — authorization code interception."


def check_missing_code_verifier(ctx) -> object:
    endpoint = ctx.token_url
    try:
        state = FlowState(metadata=ctx.metadata)
        push_authorization_request(ctx, state)
        complete_authorization(ctx, state)
        response = exchange_token(ctx, state, with_verifier=False)
    except (BaselineBroken, Exception) as exc:
        return transport_error(CHECK_ID, DESCRIPTION, endpoint, exc, REFERENCE)

    return outcome(
        check_id=CHECK_ID,
        description=DESCRIPTION,
        endpoint=endpoint,
        passed=not accepted(response.status_code),
        pass_detail="Token endpoint correctly required a code_verifier.",
        fail_detail="Token issued without a code_verifier.",
        remedy="Reject token requests missing a valid code_verifier.",
        reference=REFERENCE,
    )
