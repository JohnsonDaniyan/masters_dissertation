from scanner.flows.http import accepted
from scanner.flows import http
from scanner.reporting.helpers import outcome, transport_error

CHECK_ID = "PAR-001"
DESCRIPTION = "PAR enforcement bypass"
REFERENCE = "RFC 9126; Hosseyni et al. (2025) §3.1–3.2 attacker token injection / client impersonation."


def check_par_bypass(ctx) -> object:
    endpoint = ctx.authorize_url
    try:
        response = http.get(
            endpoint,
            params={
                "client_id": "scanner-test-client",
                "redirect_uri": ctx.redirect_uri,
                "response_type": "code",
                "scope": ctx.scope,
                "code_challenge": "dummy",
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )
    except Exception as exc:
        return transport_error(CHECK_ID, DESCRIPTION, endpoint, exc, REFERENCE)

    bypassed = accepted(response.status_code) or response.status_code in (302, 303)
    return outcome(
        check_id=CHECK_ID,
        description=DESCRIPTION,
        endpoint=endpoint,
        passed=not bypassed,
        pass_detail="Authorization endpoint correctly rejected a request without request_uri.",
        fail_detail="Authorization endpoint accepted front-channel parameters without PAR.",
        remedy="Reject any /authorize request that lacks a valid request_uri.",
        reference=REFERENCE,
    )
