from scanner.flows.baseline import BaselineBroken, legitimate_access_token
from scanner.flows import http
from scanner.flows.http import accepted
from scanner.reporting.helpers import outcome, transport_error

CHECK_ID = "TOK-002"
DESCRIPTION = "Resource Server independent binding check"
REFERENCE = "Hosseyni et al. (2025) §3.5 Cuckoo's Token Attack."


def check_rs_binding_enforcement(ctx) -> object:
    endpoint = ctx.accounts_url
    try:
        state = legitimate_access_token(ctx, dpop=True)
        response = http.get(
            endpoint,
            headers={"Authorization": f"Bearer {state.access_token}"},
        )
    except (BaselineBroken, Exception) as exc:
        return transport_error(CHECK_ID, DESCRIPTION, endpoint, exc, REFERENCE)

    return outcome(
        check_id=CHECK_ID,
        description=DESCRIPTION,
        endpoint=endpoint,
        passed=not accepted(response.status_code),
        pass_detail="RS correctly rejected a sender-constrained token presented without proof.",
        fail_detail="RS accepted a sender-constrained token with no proof of possession.",
        remedy="RS must independently verify DPoP or mTLS binding on every resource request.",
        reference=REFERENCE,
    )
