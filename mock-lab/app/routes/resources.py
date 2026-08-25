from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.seed.resources import ACCOUNTS, TRANSACTIONS
from app.tokens.verifier import authorize_resource

router = APIRouter()


def _protected(request: Request, body: dict):
    claims, headers = authorize_resource(request)
    payload = {**body, "client_id": claims["client_id"], "scope": claims.get("scope")}
    return JSONResponse(content=payload, headers=headers)


@router.get("/resource")
def resource(request: Request):
    return _protected(request, {"status": "ok"})


@router.get("/accounts")
def accounts(request: Request):
    return _protected(request, {"accounts": ACCOUNTS})


@router.get("/transactions")
def transactions(request: Request):
    return _protected(request, {"transactions": TRANSACTIONS})
