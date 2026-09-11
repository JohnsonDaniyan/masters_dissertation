from scanner.flows import http
from scanner.flows.http import accepted
from scanner.reporting.helpers import outcome, transport_error
from scanner.reporting.result import Severity

CHECK_ID = "TOK-001"
DESCRIPTION = "Introspection endpoint authentication"
REFERENCE = "RFC 7662; FAPI 2.0 — unauthenticated introspection."


def check_introspection_auth(ctx) -> object:
    endpoint = ctx.introspect_url
    try:
        response = http.post_form(endpoint, {"token": "scanner-probe-token"})
    except Exception as exc:
        return transport_error(CHECK_ID, DESCRIPTION, endpoint, exc, REFERENCE)

    return outcome(
        check_id=CHECK_ID,
        description=DESCRIPTION,
        endpoint=endpoint,
        passed=not accepted(response.status_code),
        pass_detail="Unauthenticated introspection was rejected.",
        fail_detail="Introspection succeeded without resource-server credentials.",
        remedy="Require RS authentication (private_key_jwt or mTLS) at /introspect.",
        severity=Severity.HIGH,
        reference=REFERENCE,
    )
