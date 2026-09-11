from scanner.flows.baseline import BaselineBroken, FlowState, push_authorization_request
from scanner.flows.http import accepted
from scanner.flows import http
from scanner.reporting.helpers import outcome, transport_error
from scanner.reporting.result import Severity

CHECK_ID = "PAR-002"
DESCRIPTION = "request_uri single-use enforcement"
REFERENCE = "RFC 9126 §2.2; Hosseyni et al. (2025) request_uri replay."


def check_request_uri_replay(ctx) -> object:
    endpoint = ctx.authorize_url
    try:
        state = FlowState(metadata=ctx.metadata)
        request_uri = push_authorization_request(ctx, state)
        params = {"client_id": ctx.client_id, "request_uri": request_uri}
        first = http.get(endpoint, params=params, follow_redirects=False)
        second = http.get(endpoint, params=params, follow_redirects=False)
    except (BaselineBroken, Exception) as exc:
        return transport_error(CHECK_ID, DESCRIPTION, endpoint, exc, REFERENCE)

    first_ok = accepted(first.status_code) or first.status_code in (302, 303)
    replayed = accepted(second.status_code) or second.status_code in (302, 303)
    if not first_ok:
        return transport_error(
            CHECK_ID,
            DESCRIPTION,
            endpoint,
            Exception(f"First use of request_uri failed (HTTP {first.status_code})"),
            REFERENCE,
        )
    return outcome(
        check_id=CHECK_ID,
        description=DESCRIPTION,
        endpoint=endpoint,
        passed=not replayed,
        pass_detail="request_uri was accepted once and rejected on reuse.",
        fail_detail="The same request_uri was accepted a second time.",
        remedy="Invalidate request_uri immediately after first use.",
        severity=Severity.MEDIUM,
        reference=REFERENCE,
    )
