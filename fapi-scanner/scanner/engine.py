from datetime import datetime, timezone

from scanner.catalog import CHECKS
from scanner.discovery.issuer_check import evaluate_issuer_identifier
from scanner.discovery.metadata_check import evaluate_metadata_reachable
from scanner.discovery.metadata_fetch import fetch_metadata, normalise_base_url
from scanner.discovery.par_check import evaluate_par_advertised
def run_scan(target: str) -> dict:
    base_url = normalise_base_url(target)
    started = datetime.now(timezone.utc)
    fetched = fetch_metadata(base_url)

    results = [
        evaluate_metadata_reachable(fetched),
        evaluate_issuer_identifier(fetched),
        evaluate_par_advertised(fetched),
    ]

    counts = {
        "pass": 0,
        "fail": 0,
        "error": 0,
        "total": len(results),
    }
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
