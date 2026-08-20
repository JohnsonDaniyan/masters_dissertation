from urllib.parse import urlsplit

from scanner.discovery.metadata_fetch import MetadataFetch
from scanner.reporting.result import Severity, Status, TestResult

CHECK_ID = "DISC-002"
DESCRIPTION = "Issuer identifier format"
REFERENCE = "RFC 9207 / FAPI 2.0 Security Profile — issuer identification."


def evaluate_issuer_identifier(fetched: MetadataFetch) -> TestResult:
    if fetched.error or fetched.status_code != 200 or not fetched.document:
        return TestResult(
            check_id=CHECK_ID,
            description=DESCRIPTION,
            status=Status.ERROR,
            severity=Severity.INFO,
            endpoint=fetched.url,
            detail="Issuer format was not evaluated because metadata could not be retrieved.",
            remedy="Restore a reachable RFC 8414 metadata document, then re-run this check.",
            reference=REFERENCE,
        )

    issuer = fetched.document.get("issuer")
    if not issuer or not isinstance(issuer, str):
        return TestResult(
            check_id=CHECK_ID,
            description=DESCRIPTION,
            status=Status.FAIL,
            severity=Severity.HIGH,
            endpoint=fetched.url,
            detail="Metadata is missing a string 'issuer' value.",
            remedy="Publish an HTTPS issuer identifier with no query or fragment.",
            reference=REFERENCE,
        )

    parts = urlsplit(issuer)
    problems = []
    if parts.scheme != "https":
        problems.append("scheme is not https")
    if parts.query:
        problems.append("contains a query string")
    if parts.fragment:
        problems.append("contains a fragment")
    if not parts.netloc:
        problems.append("is not an absolute URL")

    if problems:
        return TestResult(
            check_id=CHECK_ID,
            description=DESCRIPTION,
            status=Status.FAIL,
            severity=Severity.HIGH,
            endpoint=fetched.url,
            detail=f"Issuer '{issuer}' is malformed: {', '.join(problems)}.",
            remedy="Use an HTTPS issuer URL with no query string or fragment, matching the AS identity.",
            reference=REFERENCE,
        )

    return TestResult(
        check_id=CHECK_ID,
        description=DESCRIPTION,
        status=Status.PASS,
        severity=Severity.INFO,
        endpoint=fetched.url,
        detail=f"Issuer '{issuer}' is an HTTPS URL with no query or fragment.",
        remedy="None required.",
        reference=REFERENCE,
    )
