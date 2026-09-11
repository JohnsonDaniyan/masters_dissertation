from scanner.crypto.assertion_builder import build_client_assertion
from scanner.crypto.pkce import generate_pkce
from scanner.flows.baseline import ensure_registered
from scanner.flows.http import accepted
from scanner.flows import http
from scanner.reporting.helpers import outcome, transport_error

CHECK_ID = "AUTH-001"
DESCRIPTION = "Client assertion (JWT) replay protection"
REFERENCE = "RFC 7523; FAPI 2.0 private_key_jwt — assertion replay."


def check_client_assertion_replay(ctx) -> object:
    endpoint = ctx.par_url
    try:
        ensure_registered(ctx)
        _verifier, challenge = generate_pkce()
        assertion = build_client_assertion(ctx.client_id, ctx.assertion_audience, ctx.identity.rsa_private)
        data = {
            "client_id": ctx.client_id,
            "redirect_uri": ctx.redirect_uri,
            "scope": ctx.scope,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": assertion,
        }
        first = http.post_form(endpoint, data)
        second = http.post_form(endpoint, data)
    except Exception as exc:
        return transport_error(CHECK_ID, DESCRIPTION, endpoint, exc, REFERENCE)

    replayed = accepted(second.status_code)
    return outcome(
        check_id=CHECK_ID,
        description=DESCRIPTION,
        endpoint=endpoint,
        passed=not replayed,
        pass_detail="Reused client assertion correctly rejected.",
        fail_detail="The same client assertion JWT was accepted twice.",
        remedy="Track jti values and reject previously-seen assertions.",
        reference=REFERENCE,
    )
