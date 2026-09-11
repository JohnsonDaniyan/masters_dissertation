from scanner.flows.http import accepted
from scanner.flows import http
from scanner.reporting.helpers import outcome, transport_error
from scanner.reporting.result import Severity

CHECK_ID = "DCR-001"
DESCRIPTION = "Dynamic client registration authorisation"
REFERENCE = "RFC 7591 — unauthorised client registration."


def check_open_registration(ctx) -> object:
    endpoint = ctx.register_url
    try:
        response = http.post_json(endpoint, {"client_name": "scanner-probe", "redirect_uris": [ctx.redirect_uri]})
    except Exception as exc:
        return transport_error(CHECK_ID, DESCRIPTION, endpoint, exc, REFERENCE)

    return outcome(
        check_id=CHECK_ID,
        description=DESCRIPTION,
        endpoint=endpoint,
        passed=not accepted(response.status_code),
        pass_detail="Registration correctly required an initial access token.",
        fail_detail="Client registration succeeded without an initial access token.",
        remedy="Require a valid initial access token for POST /register.",
        severity=Severity.MEDIUM,
        reference=REFERENCE,
    )
