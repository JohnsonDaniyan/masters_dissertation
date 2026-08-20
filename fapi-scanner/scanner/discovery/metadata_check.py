from scanner.discovery.metadata_fetch import METADATA_PATH, MetadataFetch, fetch_metadata
from scanner.reporting.result import Severity, Status, TestResult

CHECK_ID = "DISC-001"
DESCRIPTION = "AS metadata endpoint reachability"
REFERENCE = (
    "Hosseyni et al. (2025) Attacker Token Injection / Client Impersonation "
    "precondition — clients without a verified metadata source are exposed to "
    "token-endpoint misconfiguration attacks."
)


def evaluate_metadata_reachable(fetched: MetadataFetch) -> TestResult:
    if fetched.error:
        return TestResult(
            check_id=CHECK_ID,
            description=DESCRIPTION,
            status=Status.ERROR,
            severity=Severity.INFO,
            endpoint=fetched.url,
            detail=f"Request failed: {fetched.error}",
            remedy="Confirm the target base URL is correct and reachable.",
            reference=REFERENCE,
        )

    if fetched.status_code == 200:
        if fetched.document is None:
            return TestResult(
                check_id=CHECK_ID,
                description=DESCRIPTION,
                status=Status.FAIL,
                severity=Severity.HIGH,
                endpoint=fetched.url,
                detail="Endpoint returned 200 but body is not valid JSON.",
                remedy="Publish a well-formed JSON metadata document per RFC 8414.",
                reference=REFERENCE,
            )
        if "issuer" not in fetched.document:
            return TestResult(
                check_id=CHECK_ID,
                description=DESCRIPTION,
                status=Status.FAIL,
                severity=Severity.HIGH,
                endpoint=fetched.url,
                detail="Metadata document present but missing 'issuer' field.",
                remedy="Include a valid 'issuer' field per RFC 8414 / FAPI 2.0.",
                reference=REFERENCE,
            )
        return TestResult(
            check_id=CHECK_ID,
            description=DESCRIPTION,
            status=Status.PASS,
            severity=Severity.INFO,
            endpoint=fetched.url,
            detail="Metadata document reachable and contains an issuer field.",
            remedy="None required.",
            reference=REFERENCE,
        )

    return TestResult(
        check_id=CHECK_ID,
        description=DESCRIPTION,
        status=Status.FAIL,
        severity=Severity.HIGH,
        endpoint=fetched.url,
        detail=(
            f"Expected 200, got {fetched.status_code}. Clients cannot "
            "discover AS endpoints, forcing reliance on hardcoded values "
            "— a precondition for token endpoint misconfiguration attacks."
        ),
        remedy="Publish AS metadata at the RFC 8414 well-known path.",
        reference=REFERENCE,
    )


def check_metadata_reachable(base_url: str) -> TestResult:
    """
    Case 1: Verifies the AS publishes a reachable metadata document.
    Maps to Hosseyni et al. (2025) Attacker Token Injection / Client
    Impersonation precondition — clients without a verified metadata
    source are exposed to token-endpoint misconfiguration attacks.
    """
    return evaluate_metadata_reachable(fetch_metadata(base_url))
