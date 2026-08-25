import httpx

from scanner.discovery.metadata_fetch import MetadataFetch, normalise_base_url
from scanner.reporting.result import Severity, Status, TestResult

REFERENCE = "RFC 9126 Pushed Authorization Requests; FAPI 2.0 Security Profile."

VALID_PAR = {
    "client_id": "fapi-scanner",
    "redirect_uri": "https://scanner.example/callback",
    "scope": "openid",
    "code_challenge": "E9Melhoa2OcwObgj_zthkQS-BglfS65ibk4BfLF0hVA",
    "code_challenge_method": "S256",
}


def post_form(url: str, data: dict, timeout: float = 5.0) -> httpx.Response:
    return httpx.post(url, data=data, timeout=timeout)


def get_request(url: str, params: dict | None = None, timeout: float = 5.0) -> httpx.Response:
    return httpx.get(url, params=params, timeout=timeout)


def par_endpoints(base_url: str, fetched: MetadataFetch) -> tuple[str, str]:
    base = normalise_base_url(base_url)
    document = fetched.document or {}
    par = document.get("pushed_authorization_request_endpoint") or f"{base}/par"
    authorize = document.get("authorization_endpoint") or f"{base}/authorize"
    return par, authorize


def _transport_error(check_id: str, description: str, endpoint: str, exc: Exception) -> TestResult:
    return TestResult(
        check_id=check_id,
        description=description,
        status=Status.ERROR,
        severity=Severity.INFO,
        endpoint=endpoint,
        detail=f"Request failed: {exc}",
        remedy="Confirm the PAR and authorization endpoints are reachable, then re-run this check.",
        reference=REFERENCE,
    )


def _rejecting(status_code: int | None) -> bool:
    return status_code is not None and status_code >= 400


def _accepted(status_code: int | None) -> bool:
    return status_code is not None and 200 <= status_code < 300


def push_authorization(par_url: str, data: dict | None = None) -> httpx.Response:
    return post_form(par_url, data or VALID_PAR)


def evaluate_par_rejects_invalid(base_url: str, fetched: MetadataFetch) -> TestResult:
    check_id = "PAR-001"
    description = "PAR rejects missing or invalid parameters"
    par_url, _ = par_endpoints(base_url, fetched)

    try:
        missing = post_form(par_url, {"client_id": VALID_PAR["client_id"]})
        invalid_pkce = post_form(par_url, {**VALID_PAR, "code_challenge_method": "plain"})
        valid = push_authorization(par_url)
    except httpx.RequestError as exc:
        return _transport_error(check_id, description, par_url, exc)

    if not _rejecting(missing.status_code):
        return TestResult(
            check_id=check_id,
            description=description,
            status=Status.FAIL,
            severity=Severity.HIGH,
            endpoint=par_url,
            detail=f"POST /par accepted an incomplete request (HTTP {missing.status_code}).",
            remedy="Reject PAR requests that omit required parameters with HTTP 400 invalid_request.",
            reference=REFERENCE,
        )

    if not _rejecting(invalid_pkce.status_code):
        return TestResult(
            check_id=check_id,
            description=description,
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            endpoint=par_url,
            detail=f"POST /par accepted code_challenge_method=plain (HTTP {invalid_pkce.status_code}).",
            remedy="Require S256 PKCE at the PAR endpoint unless a documented exception applies.",
            reference=REFERENCE,
        )

    body = {}
    try:
        body = valid.json()
    except ValueError:
        body = {}

    if not _accepted(valid.status_code) or not isinstance(body.get("request_uri"), str):
        return TestResult(
            check_id=check_id,
            description=description,
            status=Status.FAIL,
            severity=Severity.HIGH,
            endpoint=par_url,
            detail=f"A well-formed PAR request did not return a request_uri (HTTP {valid.status_code}).",
            remedy="Issue a single-use request_uri for valid PAR requests as specified in RFC 9126.",
            reference=REFERENCE,
        )

    return TestResult(
        check_id=check_id,
        description=description,
        status=Status.PASS,
        severity=Severity.INFO,
        endpoint=par_url,
        detail="Incomplete and plain-PKCE PAR requests are rejected; a valid request returns request_uri.",
        remedy="None required.",
        reference=REFERENCE,
    )


def evaluate_authorize_requires_request_uri(base_url: str, fetched: MetadataFetch) -> TestResult:
    check_id = "PAR-002"
    description = "Authorization requires a valid request_uri"
    par_url, authorize_url = par_endpoints(base_url, fetched)

    try:
        bypass = get_request(authorize_url, params=VALID_PAR)
        unknown = get_request(
            authorize_url,
            params={
                "client_id": VALID_PAR["client_id"],
                "request_uri": "urn:ietf:params:oauth:request_uri:unknown",
            },
        )
        issued = push_authorization(par_url).json()
        request_uri = issued.get("request_uri") if isinstance(issued, dict) else None
        valid = get_request(
            authorize_url,
            params={"client_id": VALID_PAR["client_id"], "request_uri": request_uri},
        ) if request_uri else None
    except httpx.RequestError as exc:
        return _transport_error(check_id, description, authorize_url, exc)
    except ValueError as exc:
        return _transport_error(check_id, description, par_url, exc)

    if _accepted(bypass.status_code):
        return TestResult(
            check_id=check_id,
            description=description,
            status=Status.FAIL,
            severity=Severity.HIGH,
            endpoint=authorize_url,
            detail=(
                "GET /authorize accepted front-channel parameters without a "
                f"request_uri (HTTP {bypass.status_code}). This is the PAR bypass."
            ),
            remedy="Require a previously issued request_uri at /authorize (PAR_ENFORCED=true).",
            reference=REFERENCE,
        )

    if not _rejecting(unknown.status_code):
        return TestResult(
            check_id=check_id,
            description=description,
            status=Status.FAIL,
            severity=Severity.HIGH,
            endpoint=authorize_url,
            detail=f"GET /authorize accepted an unknown request_uri (HTTP {unknown.status_code}).",
            remedy="Reject authorization requests whose request_uri is unknown, expired, or already used.",
            reference=REFERENCE,
        )

    if valid is None or not _accepted(valid.status_code):
        status = valid.status_code if valid is not None else "no request_uri"
        return TestResult(
            check_id=check_id,
            description=description,
            status=Status.FAIL,
            severity=Severity.HIGH,
            endpoint=authorize_url,
            detail=f"A freshly issued request_uri was not accepted at /authorize (HTTP {status}).",
            remedy="Honor unexpired, unused request_uri values issued by POST /par.",
            reference=REFERENCE,
        )

    return TestResult(
        check_id=check_id,
        description=description,
        status=Status.PASS,
        severity=Severity.INFO,
        endpoint=authorize_url,
        detail="Front-channel parameters and unknown request_uri values are rejected; a valid request_uri is accepted.",
        remedy="None required.",
        reference=REFERENCE,
    )


def evaluate_request_uri_single_use(base_url: str, fetched: MetadataFetch) -> TestResult:
    check_id = "PAR-003"
    description = "request_uri is single-use"
    par_url, authorize_url = par_endpoints(base_url, fetched)

    try:
        issued = push_authorization(par_url).json()
        request_uri = issued.get("request_uri") if isinstance(issued, dict) else None
        if not request_uri:
            return TestResult(
                check_id=check_id,
                description=description,
                status=Status.ERROR,
                severity=Severity.INFO,
                endpoint=par_url,
                detail="Could not obtain a request_uri with which to test replay.",
                remedy="Restore a working PAR endpoint, then re-run this check.",
                reference=REFERENCE,
            )
        params = {"client_id": VALID_PAR["client_id"], "request_uri": request_uri}
        first = get_request(authorize_url, params=params)
        replay = get_request(authorize_url, params=params)
    except httpx.RequestError as exc:
        return _transport_error(check_id, description, authorize_url, exc)
    except ValueError as exc:
        return _transport_error(check_id, description, par_url, exc)

    if not _accepted(first.status_code):
        return TestResult(
            check_id=check_id,
            description=description,
            status=Status.ERROR,
            severity=Severity.INFO,
            endpoint=authorize_url,
            detail=f"First use of request_uri failed (HTTP {first.status_code}); replay could not be evaluated.",
            remedy="Ensure a valid request_uri is accepted once before testing reuse.",
            reference=REFERENCE,
        )

    if _accepted(replay.status_code):
        return TestResult(
            check_id=check_id,
            description=description,
            status=Status.FAIL,
            severity=Severity.HIGH,
            endpoint=authorize_url,
            detail="The same request_uri was accepted a second time (replay).",
            remedy="Mark each request_uri as used after the first authorization request (REQUEST_URI_REUSABLE=false).",
            reference=REFERENCE,
        )

    return TestResult(
        check_id=check_id,
        description=description,
        status=Status.PASS,
        severity=Severity.INFO,
        endpoint=authorize_url,
        detail="request_uri was accepted once and rejected on replay.",
        remedy="None required.",
        reference=REFERENCE,
    )
