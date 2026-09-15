from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, Field, field_validator

from scanner.catalog import CHECKS
from scanner.engine import run_scan
from scanner.reporting.pdf import pdf_filename, render_scan_pdf

app = FastAPI(
    title="FAPI Scanner API",
    description="HTTP interface for the FAPI 2.0 adversarial scanner used by FAPI Lens.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def normalise_target(value: str) -> str:
    target = value.strip()
    if not target:
        raise ValueError("target is required")
    if not target.startswith(("http://", "https://")):
        target = f"http://{target}"
    return target.rstrip("/")


class ScanRequest(BaseModel):
    target: str = Field(..., description="Base URL of the authorisation server under test")

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        return normalise_target(value)


class ScanReportPayload(BaseModel):
    target: str
    metadata_url: str = ""
    started_at: str = ""
    finished_at: str = ""
    duration_ms: int = 0
    summary: dict
    checks: list = Field(default_factory=list)
    results: list


def pdf_response(report: dict) -> Response:
    filename = pdf_filename(str(report.get("target") or "scan"))
    return Response(
        content=render_scan_pdf(report),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/health")
def health():
    return {"status": "ok", "service": "fapi-scanner"}


@app.get("/api/v1/checks")
def list_checks():
    return {"checks": CHECKS}


@app.post("/api/v1/scan")
def scan(request: ScanRequest):
    try:
        return run_scan(request.target)
    except Exception as exc:  # pragma: no cover - defensive API boundary
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/api/v1/scan")
def scan_get(target: str = Query(..., description="Base URL of the AS under test")):
    try:
        return run_scan(normalise_target(target))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:  # pragma: no cover - defensive API boundary
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/api/v1/scan/pdf")
def scan_pdf(request: ScanRequest):
    try:
        return pdf_response(run_scan(request.target))
    except Exception as exc:  # pragma: no cover - defensive API boundary
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/api/v1/report/pdf")
def report_pdf(report: ScanReportPayload):
    return pdf_response(report.model_dump())
