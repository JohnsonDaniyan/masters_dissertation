from urllib.parse import parse_qs, urlparse

from scanner.flows.baseline import (
    BaselineBroken,
    FlowState,
    push_authorization_request,
)
from scanner.flows import http
from scanner.flows.http import accepted
from scanner.reporting.helpers import outcome, transport_error

CHECK_ID = "RESP-002"
DESCRIPTION = "Strict redirect_uri matching"
REFERENCE = "RFC 6749 / FAPI 2.0 — redirect URI manipulation."


def check_redirect_uri_matching(ctx) -> object:
    endpoint = ctx.authorize_url
    try:
        state = FlowState(metadata=ctx.metadata)
        push_authorization_request(ctx, state)
        response = http.get(
            endpoint,
            params={
                "client_id": ctx.client_id,
                "request_uri": state.request_uri,
                "redirect_uri": ctx.redirect_uri + "/extra",
            },
            follow_redirects=False,
        )
    except (BaselineBroken, Exception) as exc:
        return transport_error(CHECK_ID, DESCRIPTION, endpoint, exc, REFERENCE)

    loosened = accepted(response.status_code) or response.status_code in (302, 303)
    return outcome(
        check_id=CHECK_ID,
        description=DESCRIPTION,
        endpoint=endpoint,
        passed=not loosened,
        pass_detail="A prefix/partial redirect_uri was rejected.",
        fail_detail="A slightly different redirect_uri was accepted (loose matching).",
        remedy="Compare redirect_uri with exact string equality against the registered value.",
        reference=REFERENCE,
    )
