from scanner.flows.baseline import (
    BaselineBroken,
    FlowState,
    complete_authorization,
    exchange_token,
    push_authorization_request,
)
from scanner.flows.http import accepted
from scanner.reporting.helpers import outcome, transport_error

CHECK_ID = "DPOP-002"
DESCRIPTION = "Rejection of malformed DPoP proofs"
REFERENCE = "RFC 9449; FAPI 2.0 sender-constrained tokens."


def check_malformed_dpop(ctx) -> object:
    endpoint = ctx.token_url
    try:
        state = FlowState(metadata=ctx.metadata)
        push_authorization_request(ctx, state)
        complete_authorization(ctx, state)
        response = exchange_token(ctx, state, with_dpop=True, malformed_dpop=True)
    except (BaselineBroken, Exception) as exc:
        return transport_error(CHECK_ID, DESCRIPTION, endpoint, exc, REFERENCE)

    return outcome(
        check_id=CHECK_ID,
        description=DESCRIPTION,
        endpoint=endpoint,
        passed=not accepted(response.status_code),
        pass_detail="Malformed DPoP proof was rejected at the token endpoint.",
        fail_detail="Token issued despite a DPoP proof missing required claims.",
        remedy="Validate htm, htu, jti, iat and the embedded JWK on every DPoP proof.",
        reference=REFERENCE,
    )
