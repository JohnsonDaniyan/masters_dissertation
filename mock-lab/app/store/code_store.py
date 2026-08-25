import secrets

_store: dict[str, dict] = {}


def clear() -> None:
    _store.clear()


def issue_code(params: dict) -> str:
    code = secrets.token_urlsafe(24)
    _store[code] = {
        "client_id": params["client_id"],
        "redirect_uri": params["redirect_uri"],
        "scope": params["scope"],
        "code_challenge": params["code_challenge"],
        "code_challenge_method": params["code_challenge_method"],
        "used": False,
    }
    return code


def consume_code(code: str) -> dict | None:
    entry = _store.get(code)
    if not entry or entry["used"]:
        return None
    entry["used"] = True
    return entry
