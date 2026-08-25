import secrets

_store: dict[str, dict] = {}


def clear() -> None:
    _store.clear()


def issue_access_token(
    *,
    client_id: str,
    scope: str,
    cnf: dict | None = None,
    token_type: str = "Bearer",
) -> tuple[str, dict]:
    token = secrets.token_urlsafe(32)
    record = {
        "client_id": client_id,
        "scope": scope,
        "cnf": cnf or {},
        "token_type": token_type,
    }
    _store[token] = record
    return token, record


def lookup(token: str) -> dict | None:
    return _store.get(token)
