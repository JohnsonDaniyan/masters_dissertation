from datetime import datetime, timezone

from scanner.catalog import CHECKS
from scanner.client_auth.jwt_replay_check import check_client_assertion_replay
from scanner.client_auth.mtls_bypass_check import check_mtls_bypass
from scanner.client_auth.weak_auth_check import check_weak_client_auth
from scanner.dcr.open_registration_check import check_open_registration
from scanner.dcr.unauth_update_check import check_unauthenticated_update
from scanner.discovery.issuer_check import evaluate_issuer_identifier
from scanner.discovery.metadata_check import evaluate_metadata_reachable
from scanner.discovery.metadata_fetch import fetch_metadata, normalise_base_url
from scanner.discovery.par_check import evaluate_par_advertised
from scanner.flows.baseline import ScanContext, ensure_registered
from scanner.flows.client_identity import ClientIdentity
from scanner.par.bypass_check import check_par_bypass
from scanner.par.replay_check import check_request_uri_replay
from scanner.pkce.missing_verifier_check import check_missing_code_verifier
from scanner.pkce.plain_method_check import check_plain_pkce_method
from scanner.response_integrity.issuer_param_check import check_issuer_parameter
from scanner.response_integrity.jarm_signature_check import check_jarm_signature
from scanner.response_integrity.redirect_uri_check import check_redirect_uri_matching
from scanner.sender_constraining.dpop_malformed_check import check_malformed_dpop
from scanner.sender_constraining.dpop_replay_check import check_dpop_replay
from scanner.sender_constraining.mtls_binding_check import check_mtls_token_binding
from scanner.token_resource.introspection_auth_check import check_introspection_auth
from scanner.token_resource.rs_binding_check import check_rs_binding_enforcement


def run_scan(target: str) -> dict:
    base_url = normalise_base_url(target)
    started = datetime.now(timezone.utc)
    fetched = fetch_metadata(base_url)
    ctx = ScanContext(
        base_url=base_url,
        metadata=fetched.document or {},
        identity=ClientIdentity(),
    )
    if fetched.document:
        try:
            ensure_registered(ctx)
        except Exception:
            pass

    results = [
        evaluate_metadata_reachable(fetched),
        evaluate_issuer_identifier(fetched),
        evaluate_par_advertised(fetched),
        check_par_bypass(ctx),
        check_request_uri_replay(ctx),
        check_missing_code_verifier(ctx),
        check_plain_pkce_method(ctx),
        check_client_assertion_replay(ctx),
        check_mtls_bypass(ctx),
        check_weak_client_auth(ctx),
        check_dpop_replay(ctx),
        check_malformed_dpop(ctx),
        check_mtls_token_binding(ctx),
        check_introspection_auth(ctx),
        check_rs_binding_enforcement(ctx),
        check_issuer_parameter(ctx),
        check_redirect_uri_matching(ctx),
        check_jarm_signature(ctx),
        check_open_registration(ctx),
        check_unauthenticated_update(ctx),
    ]

    counts = {"pass": 0, "fail": 0, "error": 0, "total": len(results)}
    for result in results:
        counts[result.status.value] += 1

    finished = datetime.now(timezone.utc)
    return {
        "target": base_url,
        "metadata_url": fetched.url,
        "started_at": started.isoformat(),
        "finished_at": finished.isoformat(),
        "duration_ms": int((finished - started).total_seconds() * 1000),
        "summary": counts,
        "checks": CHECKS,
        "results": [result.to_dict() for result in results],
    }
