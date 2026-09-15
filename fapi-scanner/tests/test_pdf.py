from scanner.reporting.pdf import pdf_filename, render_scan_pdf


def test_pdf_filename_sanitises_host():
    assert pdf_filename("http://127.0.0.1:8000") == "fapi-scan-127.0.0.1-8000.pdf"
    assert pdf_filename("https://as.example/path") == "fapi-scan-as.example.pdf"


def test_render_scan_pdf_contains_findings():
    report = {
        "target": "http://127.0.0.1:8000",
        "metadata_url": "http://127.0.0.1:8000/.well-known/oauth-authorization-server",
        "started_at": "2026-09-14T00:00:00+00:00",
        "finished_at": "2026-09-14T00:00:01+00:00",
        "duration_ms": 1000,
        "summary": {"pass": 0, "fail": 1, "error": 0, "total": 1},
        "checks": [{"check_id": "PAR-001", "title": "PAR bypass"}],
        "results": [
            {
                "check_id": "PAR-001",
                "description": "Calls /authorize with front-channel parameters.",
                "status": "fail",
                "severity": "high",
                "endpoint": "http://127.0.0.1:8000/authorize",
                "detail": "Authorisation request without request_uri was accepted.",
                "remedy": "Reject front-channel authorisation parameters.",
                "reference": "RFC 9126",
            }
        ],
    }
    pdf = render_scan_pdf(report)
    assert pdf.startswith(b"%PDF-")
    assert b"%%EOF" in pdf[-1024:]
