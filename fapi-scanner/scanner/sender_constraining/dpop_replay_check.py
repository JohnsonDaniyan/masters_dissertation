from scanner.crypto.dpop_builder import build_dpop_proof
from scanner.flows.baseline import BaselineBroken, legitimate_access_token
from scanner.flows import http
from scanner.flows.http import accepted
from scanner.reporting.helpers import outcome, transport_error

CHECK_ID = "DPOP-001"
DESCRIPTION = "DPoP proof replay protection"
REFERENCE = "Hosseyni et al. (2025) §3.3 DPoP Proof Replay."


def check_dpop_replay(ctx) -> object:
    endpoint = ctx.accounts_url
    try:
        state = legitimate_access_token(ctx, dpop=True)
        proof = build_dpop_proof(
            "GET",
            endpoint,
            ctx.identity.dpop_private,
            ctx.identity.dpop_public_jwk,
        )
        headers = {"Authorization": f"DPoP {state.access_token}", "DPoP": proof}
        first = http.get(endpoint, headers=headers)
        second = http.get(endpoint, headers=headers)
    except (BaselineBroken, Exception) as exc:
        return transport_error(CHECK_ID, DESCRIPTION, endpoint, exc, REFERENCE)

    if not accepted(first.status_code):
        return transport_error(
            CHECK_ID,
            DESCRIPTION,
            endpoint,
            Exception(f"First DPoP resource request failed (HTTP {first.status_code})"),
            REFERENCE,
        )
    return outcome(
        check_id=CHECK_ID,
        description=DESCRIPTION,
        endpoint=endpoint,
        passed=not accepted(second.status_code),
        pass_detail="DPoP proof correctly rejected on reuse.",
        fail_detail="The same DPoP proof was accepted twice — replay not prevented.",
        remedy="Enforce single-use DPoP proofs via jti tracking or server nonces.",
        reference=REFERENCE,
    )
