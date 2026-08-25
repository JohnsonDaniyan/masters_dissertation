from scanner.discovery.metadata_fetch import MetadataFetch
from scanner.discovery.par_enforcement import (
    evaluate_authorize_requires_request_uri,
    evaluate_par_rejects_invalid,
    evaluate_request_uri_single_use,
)
from scanner.reporting.result import Status
from tests.par_fakes import FakeParAS, FakeResponse

FETCHED = MetadataFetch(
    url="https://as.example/.well-known/oauth-authorization-server",
    status_code=200,
    document={
        "issuer": "https://as.example",
        "authorization_endpoint": "https://as.example/authorize",
        "pushed_authorization_request_endpoint": "https://as.example/par",
        "require_pushed_authorization_requests": True,
    },
)


def _install(monkeypatch, fake: FakeParAS):
    monkeypatch.setattr("scanner.discovery.par_enforcement.post_form", fake.post_form)
    monkeypatch.setattr("scanner.discovery.par_enforcement.get_request", fake.get_request)


def test_par_001_pass_on_conformant_as(monkeypatch):
    _install(monkeypatch, FakeParAS())
    result = evaluate_par_rejects_invalid("https://as.example", FETCHED)
    assert result.status is Status.PASS


def test_par_001_fail_when_incomplete_accepted(monkeypatch):
    def post_form(url, data, timeout=5.0):
        return FakeResponse(200, {"request_uri": "urn:ietf:params:oauth:request_uri:x"})

    monkeypatch.setattr("scanner.discovery.par_enforcement.post_form", post_form)
    result = evaluate_par_rejects_invalid("https://as.example", FETCHED)
    assert result.status is Status.FAIL
    assert "incomplete" in result.detail.lower()


def test_par_002_fail_on_front_channel_bypass(monkeypatch):
    _install(monkeypatch, FakeParAS(allow_bypass=True))
    result = evaluate_authorize_requires_request_uri("https://as.example", FETCHED)
    assert result.status is Status.FAIL
    assert "bypass" in result.detail.lower()


def test_par_002_pass_when_request_uri_required(monkeypatch):
    _install(monkeypatch, FakeParAS())
    result = evaluate_authorize_requires_request_uri("https://as.example", FETCHED)
    assert result.status is Status.PASS


def test_par_003_fail_when_request_uri_reusable(monkeypatch):
    _install(monkeypatch, FakeParAS(reusable=True))
    result = evaluate_request_uri_single_use("https://as.example", FETCHED)
    assert result.status is Status.FAIL
    assert "replay" in result.detail.lower()


def test_par_003_pass_when_single_use(monkeypatch):
    _install(monkeypatch, FakeParAS())
    result = evaluate_request_uri_single_use("https://as.example", FETCHED)
    assert result.status is Status.PASS
