from scanner.discovery.metadata_fetch import MetadataFetch
from scanner.engine import run_scan
from scanner.flows.baseline import ScanContext
from scanner.flows.client_identity import ClientIdentity
from scanner.par.bypass_check import check_par_bypass
from scanner.par.replay_check import check_request_uri_replay
from scanner.pkce.missing_verifier_check import check_missing_code_verifier
from scanner.pkce.plain_method_check import check_plain_pkce_method
from scanner.client_auth.jwt_replay_check import check_client_assertion_replay
from scanner.client_auth.mtls_bypass_check import check_mtls_bypass
from scanner.client_auth.weak_auth_check import check_weak_client_auth
from scanner.sender_constraining.dpop_replay_check import check_dpop_replay
from scanner.sender_constraining.dpop_malformed_check import check_malformed_dpop
from scanner.sender_constraining.mtls_binding_check import check_mtls_token_binding
from scanner.token_resource.introspection_auth_check import check_introspection_auth
from scanner.token_resource.rs_binding_check import check_rs_binding_enforcement
from scanner.response_integrity.issuer_param_check import check_issuer_parameter
from scanner.response_integrity.redirect_uri_check import check_redirect_uri_matching
from scanner.response_integrity.jarm_signature_check import check_jarm_signature
from scanner.dcr.open_registration_check import check_open_registration
from scanner.dcr.unauth_update_check import check_unauthenticated_update
from scanner.reporting.result import Status
from tests.fake_lab import FakeLab

METADATA = {
    "issuer": "https://as.example",
    "authorization_endpoint": "https://as.example/authorize",
    "pushed_authorization_request_endpoint": "https://as.example/par",
    "token_endpoint": "https://as.example/token",
    "introspection_endpoint": "https://as.example/introspect",
    "registration_endpoint": "https://as.example/register",
    "require_pushed_authorization_requests": True,
}

FETCHED = MetadataFetch(
    url="https://as.example/.well-known/oauth-authorization-server",
    status_code=200,
    document=METADATA,
)


def _ctx():
    return ScanContext(base_url="https://as.example", metadata=METADATA, identity=ClientIdentity())


def _lab(monkeypatch, **toggles) -> FakeLab:
    lab = FakeLab(**toggles)
    lab.install(monkeypatch)
    return lab


def test_endpoints_use_scan_target_not_metadata_host():
    from scanner.flows.baseline import rewrite_to_target

    assert (
        rewrite_to_target("https://mock-as.local/authorize", "http://127.0.0.1:8000", "/authorize")
        == "http://127.0.0.1:8000/authorize"
    )
    ctx = ScanContext(
        base_url="http://127.0.0.1:8000",
        metadata={**METADATA, "issuer": "https://mock-as.local?malformed=true"},
        identity=ClientIdentity(),
    )
    assert ctx.par_url == "http://127.0.0.1:8000/par"
    assert ctx.authorize_url == "http://127.0.0.1:8000/authorize"
    assert ctx.token_url == "http://127.0.0.1:8000/token"
    assert ctx.assertion_audience == "https://mock-as.local"


def test_conformant_lab_passes_bh_checks(monkeypatch):
    _lab(monkeypatch)
    ctx = _ctx()
    assert check_par_bypass(ctx).status is Status.PASS
    assert check_request_uri_replay(ctx).status is Status.PASS
    assert check_missing_code_verifier(ctx).status is Status.PASS
    assert check_plain_pkce_method(ctx).status is Status.PASS
    assert check_client_assertion_replay(ctx).status is Status.PASS
    assert check_mtls_bypass(ctx).status is Status.PASS
    assert check_weak_client_auth(ctx).status is Status.PASS
    assert check_dpop_replay(ctx).status is Status.PASS
    assert check_malformed_dpop(ctx).status is Status.PASS
    assert check_mtls_token_binding(ctx).status is Status.PASS
    assert check_introspection_auth(ctx).status is Status.PASS
    assert check_rs_binding_enforcement(ctx).status is Status.PASS
    assert check_issuer_parameter(ctx).status is Status.PASS
    assert check_redirect_uri_matching(ctx).status is Status.PASS
    assert check_jarm_signature(ctx).status is Status.PASS
    assert check_open_registration(ctx).status is Status.PASS
    assert check_unauthenticated_update(ctx).status is Status.PASS


def test_toggles_produce_expected_failures(monkeypatch):
    cases = [
        (check_par_bypass, {"par_enforced": False}),
        (check_request_uri_replay, {"request_uri_reusable": True}),
        (check_missing_code_verifier, {"pkce_enforced": False}),
        (check_plain_pkce_method, {"allow_plain_pkce": True}),
        (check_client_assertion_replay, {"jwt_replay_protection": False}),
        (check_mtls_bypass, {"mtls_client_auth_enforced": False}),
        (check_weak_client_auth, {"allow_weak_client_auth": True}),
        (check_dpop_replay, {"dpop_replay_protection": False}),
        (check_malformed_dpop, {"dpop_validation_strict": False}),
        (check_mtls_token_binding, {"mtls_binding_enforced": False}),
        (check_introspection_auth, {"introspection_auth_required": False}),
        (check_rs_binding_enforcement, {"rs_trusts_as_blindly": True}),
        (check_issuer_parameter, {"iss_param_omitted": True}),
        (check_redirect_uri_matching, {"redirect_uri_loose_match": True}),
        (check_jarm_signature, {"jarm_signature_check": False}),
        (check_open_registration, {"dcr_open_registration": True}),
        (check_unauthenticated_update, {"dcm_auth_required": False}),
    ]
    for check, toggles in cases:
        _lab(monkeypatch, **toggles)
        result = check(_ctx())
        assert result.status is Status.FAIL, f"{check.__name__} expected FAIL, got {result.status}: {result.detail}"


def test_engine_runs_full_catalogue(monkeypatch):
    _lab(monkeypatch)
    monkeypatch.setattr("scanner.engine.fetch_metadata", lambda target: FETCHED)
    report = run_scan("https://as.example")
    assert report["summary"]["fail"] == 0
    assert report["summary"]["error"] == 0
    assert report["summary"]["pass"] == 20
    ids = {item["check_id"] for item in report["results"]}
    assert "PAR-001" in ids
    assert "DCM-001" in ids
    assert "DISC-001" in ids
