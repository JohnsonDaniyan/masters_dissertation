from scanner.reporting.result import Severity, Status, TestResult


def outcome(
    *,
    check_id: str,
    description: str,
    endpoint: str,
    passed: bool,
    pass_detail: str,
    fail_detail: str,
    remedy: str,
    severity: Severity = Severity.HIGH,
    reference: str = "",
) -> TestResult:
    return TestResult(
        check_id=check_id,
        description=description,
        status=Status.PASS if passed else Status.FAIL,
        severity=Severity.INFO if passed else severity,
        endpoint=endpoint,
        detail=pass_detail if passed else fail_detail,
        remedy="None required." if passed else remedy,
        reference=reference,
    )


def transport_error(check_id: str, description: str, endpoint: str, exc: Exception, reference: str = "") -> TestResult:
    return TestResult(
        check_id=check_id,
        description=description,
        status=Status.ERROR,
        severity=Severity.INFO,
        endpoint=endpoint,
        detail=str(exc),
        remedy="Confirm the target is reachable, then re-run this check.",
        reference=reference,
    )
