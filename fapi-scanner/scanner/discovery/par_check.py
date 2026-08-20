from scanner.discovery.metadata_fetch import MetadataFetch
from scanner.reporting.result import Severity, Status, TestResult

CHECK_ID = "DISC-003"
DESCRIPTION = "PAR advertisement"
REFERENCE = "RFC 9126 PAR; FAPI 2.0 require_pushed_authorization_requests."


def evaluate_par_advertised(fetched: MetadataFetch) -> TestResult:
    if fetched.error or fetched.status_code != 200 or not fetched.document:
        return TestResult(
            check_id=CHECK_ID,
            description=DESCRIPTION,
            status=Status.ERROR,
            severity=Severity.INFO,
            endpoint=fetched.url,
            detail="PAR advertisement was not evaluated because metadata could not be retrieved.",
            remedy="Restore a reachable RFC 8414 metadata document, then re-run this check.",
            reference=REFERENCE,
        )

    doc = fetched.document
    par_endpoint = doc.get("pushed_authorization_request_endpoint")
    requires_par = doc.get("require_pushed_authorization_requests")

    if not par_endpoint:
        return TestResult(
            check_id=CHECK_ID,
            description=DESCRIPTION,
            status=Status.FAIL,
            severity=Severity.HIGH,
            endpoint=fetched.url,
            detail="Metadata does not advertise pushed_authorization_request_endpoint.",
            remedy="Publish a PAR endpoint so clients are not forced onto a browser front channel.",
            reference=REFERENCE,
        )

    if requires_par is not True:
        return TestResult(
            check_id=CHECK_ID,
            description=DESCRIPTION,
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            endpoint=fetched.url,
            detail=(
                f"PAR endpoint is present ({par_endpoint}) but "
                "require_pushed_authorization_requests is not true."
            ),
            remedy="Set require_pushed_authorization_requests to true for FAPI 2.0 Security Profile.",
            reference=REFERENCE,
        )

    return TestResult(
        check_id=CHECK_ID,
        description=DESCRIPTION,
        status=Status.PASS,
        severity=Severity.INFO,
        endpoint=fetched.url,
        detail=f"PAR is required and advertised at {par_endpoint}.",
        remedy="None required.",
        reference=REFERENCE,
    )
