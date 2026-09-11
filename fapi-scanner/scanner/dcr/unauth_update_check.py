from scanner.flows.baseline import BaselineBroken, ensure_registered
from scanner.flows import http
from scanner.flows.http import accepted
from scanner.reporting.helpers import outcome, transport_error
from scanner.reporting.result import Severity

CHECK_ID = "DCM-001"
DESCRIPTION = "Dynamic client management authorisation"
REFERENCE = "RFC 7592 — unauthenticated client configuration update."


def check_unauthenticated_update(ctx) -> object:
    try:
        ensure_registered(ctx)
        endpoint = f"{ctx.register_url}/{ctx.client_id}"
        response = http.put_json(endpoint, {"redirect_uris": [ctx.redirect_uri + "/mutated"]})
    except (BaselineBroken, Exception) as exc:
        endpoint = ctx.register_url
        return transport_error(CHECK_ID, DESCRIPTION, endpoint, exc, REFERENCE)

    return outcome(
        check_id=CHECK_ID,
        description=DESCRIPTION,
        endpoint=endpoint,
        passed=not accepted(response.status_code),
        pass_detail="Configuration update correctly required a registration access token.",
        fail_detail="Client configuration was changed without a registration access token.",
        remedy="Require the registration access token on PUT /register/{client_id}.",
        severity=Severity.MEDIUM,
        reference=REFERENCE,
    )
