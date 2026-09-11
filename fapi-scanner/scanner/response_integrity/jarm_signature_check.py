import jwt

from scanner.flows.baseline import (
    BaselineBroken,
    FlowState,
    complete_authorization,
    push_authorization_request,
)
from scanner.reporting.helpers import outcome, transport_error

CHECK_ID = "RESP-003"
DESCRIPTION = "JARM response signature"
REFERENCE = "RFC 9101 JARM; unsigned/invalid authorization response."


def check_jarm_signature(ctx) -> object:
    endpoint = ctx.authorize_url
    try:
        state = FlowState(metadata=ctx.metadata)
        push_authorization_request(ctx, state)
        complete_authorization(ctx, state)
        jarm = state.authorize_body.get("jarm")
        if not jarm:
            raise BaselineBroken("Authorization response did not include a JARM JWT")
        alg = jwt.get_unverified_header(jarm).get("alg")
    except (BaselineBroken, Exception) as exc:
        return transport_error(CHECK_ID, DESCRIPTION, endpoint, exc, REFERENCE)

    signed = alg not in (None, "none")
    return outcome(
        check_id=CHECK_ID,
        description=DESCRIPTION,
        endpoint=endpoint,
        passed=signed,
        pass_detail=f"JARM is signed with alg={alg}.",
        fail_detail=f"JARM uses alg={alg}; an unsigned or invalid signature is accepted by this AS.",
        remedy="Sign JARM responses with a server asymmetric key (e.g. ES256).",
        reference=REFERENCE,
    )
