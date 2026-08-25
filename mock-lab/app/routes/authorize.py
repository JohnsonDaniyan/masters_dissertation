from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Query

from app.config import settings
from app.jarm.response_jwt import wrap_as_jarm
from app.registry.clients import get_redirect_uris
from app.routes.metadata import build_issuer
from app.store.code_store import issue_code
from app.store.par_store import consume_par_entry

router = APIRouter()


def _uris_match(left: str, right: str) -> bool:
    if settings.REDIRECT_URI_LOOSE_MATCH:
        return left.startswith(right) or right.startswith(left)
    return left == right


def _matches_registered(redirect_uri: str, client_id: str) -> bool:
    registered = get_redirect_uris(client_id)
    if not registered:
        return False
    return any(_uris_match(redirect_uri, allowed) for allowed in registered)


def build_redirect(redirect_uri: str, code: str, registered_uri: str, audience: str) -> dict:
    if not _uris_match(redirect_uri, registered_uri):
        raise HTTPException(status_code=400, detail="invalid_request: redirect_uri mismatch")

    params: dict[str, str] = {"code": code}
    if not settings.ISS_PARAM_OMITTED:
        params["iss"] = build_issuer()

    query_redirect = f"{redirect_uri}?{urlencode(params)}"
    jarm = wrap_as_jarm(params, audience=audience)
    jarm_redirect = f"{redirect_uri}?{urlencode({'response': jarm})}"
    return {
        "redirect": query_redirect,
        "jarm_redirect": jarm_redirect,
        "jarm": jarm,
        "iss": params.get("iss"),
        "response_params": params,
    }


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


def _finalize(params: dict, response_redirect_uri: str | None) -> dict:
    registered_or_par = params["redirect_uri"]
    redirect_uri = response_redirect_uri or registered_or_par
    if not _matches_registered(redirect_uri, params["client_id"]):
        raise HTTPException(
            status_code=400,
            detail="invalid_request: redirect_uri is not registered",
        )
    code = issue_code(params)
    built = build_redirect(
        redirect_uri, code, registered_or_par, audience=params["client_id"]
    )
    body = {"status": "ok", "code": code, "params": params, **built}
    if body["iss"] is None:
        body.pop("iss")
    return body


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
        return _finalize(params, redirect_uri)

    if settings.PAR_ENFORCED:
        raise HTTPException(
            status_code=400,
            detail="invalid_request: request_uri is required",
        )

    params = _front_channel_params(
        client_id, redirect_uri, scope, code_challenge, code_challenge_method
    )
    return _finalize(params, redirect_uri)
