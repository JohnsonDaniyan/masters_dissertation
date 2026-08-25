from fastapi import APIRouter, HTTPException, Query

from app.config import settings
from app.store.code_store import issue_code
from app.store.par_store import consume_par_entry

router = APIRouter()


def _front_channel_params(
    client_id: str | None,
    redirect_uri: str | None,
    scope: str | None,
    code_challenge: str | None,
    code_challenge_method: str | None,
) -> dict:
    if not all([client_id, redirect_uri, scope, code_challenge, code_challenge_method]):
        raise HTTPException(
            status_code=400,
            detail="invalid_request: missing authorization parameter",
        )
    return {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
    }


@router.get("/authorize")
def authorize(
    request_uri: str | None = Query(default=None),
    client_id: str | None = Query(default=None),
    redirect_uri: str | None = Query(default=None),
    scope: str | None = Query(default=None),
    code_challenge: str | None = Query(default=None),
    code_challenge_method: str | None = Query(default=None),
):
    if request_uri:
        params = consume_par_entry(request_uri, reusable=settings.REQUEST_URI_REUSABLE)
        if params is None:
            raise HTTPException(
                status_code=400,
                detail="invalid_request: request_uri is invalid, expired, or already used",
            )
        if client_id and client_id != params["client_id"]:
            raise HTTPException(
                status_code=400,
                detail="invalid_request: client_id does not match request_uri",
            )
        code = issue_code(params)
        return {"status": "ok", "code": code, "params": params}

    if settings.PAR_ENFORCED:
        raise HTTPException(
            status_code=400,
            detail="invalid_request: request_uri is required",
        )

    params = _front_channel_params(
        client_id, redirect_uri, scope, code_challenge, code_challenge_method
    )
    code = issue_code(params)
    return {"status": "ok", "code": code, "params": params}
