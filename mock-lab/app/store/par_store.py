import secrets
import time

_store: dict[str, dict] = {}

DEFAULT_TTL_SECONDS = 60
LONG_LIVED_TTL_SECONDS = 10**9


def clear() -> None:
    _store.clear()


def create_par_entry(params: dict, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> str:
    request_uri = f"urn:ietf:params:oauth:request_uri:{secrets.token_urlsafe(24)}"
    _store[request_uri] = {
        "params": params,
        "expires": time.time() + ttl_seconds,
        "used": False,
    }
    return request_uri


def consume_par_entry(request_uri: str, reusable: bool) -> dict | None:
    entry = _store.get(request_uri)
    if not entry or time.time() > entry["expires"]:
        return None
    if entry["used"] and not reusable:
        return None
    entry["used"] = True
    return entry["params"]
