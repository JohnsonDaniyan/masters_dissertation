from urllib.parse import parse_qs, urlparse

from scanner.flows.baseline import (
    BaselineBroken,
    FlowState,
    complete_authorization,
    push_authorization_request,
)
from scanner.reporting.helpers import outcome, transport_error

CHECK_ID = "RESP-001"
DESCRIPTION = "Authorization response issuer verification"
REFERENCE = "RFC 9207; mix-up / issuer verification."


def check_issuer_parameter(ctx) -> object:
    endpoint = ctx.authorize_url
    try:
        state = FlowState(metadata=ctx.metadata)
        push_authorization_request(ctx, state)
        complete_authorization(ctx, state)
        body = state.authorize_body
        redirect = body.get("redirect") or ""
        query = parse_qs(urlparse(redirect).query)
        iss = body.get("iss") or (query.get("iss") or [None])[0]
    except (BaselineBroken, Exception) as exc:
        return transport_error(CHECK_ID, DESCRIPTION, endpoint, exc, REFERENCE)

    correct = iss == ctx.issuer
    return outcome(
        check_id=CHECK_ID,
        description=DESCRIPTION,
        endpoint=endpoint,
        passed=bool(iss) and correct,
        pass_detail="iss parameter present and matches the metadata issuer.",
        fail_detail="iss parameter missing or mismatched — exposes the client to mix-up attacks.",
        remedy="Include a correct iss parameter in every authorization response.",
        reference=REFERENCE,
    )
