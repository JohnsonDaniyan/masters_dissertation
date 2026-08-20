from dataclasses import asdict, dataclass
from enum import Enum

class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class Status(str, Enum):
    PASS = "pass"       # conformant — no issue found
    FAIL = "fail"        # non-conformance detected
    ERROR = "error"       # test couldn't run (e.g. target unreachable)

@dataclass
class TestResult:
    check_id: str
    description: str
    status: Status
    severity: Severity
    endpoint: str
    detail: str
    remedy: str
    reference: str = ""

    def to_dict(self) -> dict:
        payload = asdict(self)
        payload["status"] = self.status.value
        payload["severity"] = self.severity.value
        return payload