import secrets

_nonces: dict[str, set[str]] = {}
_used_jtis: set[str] = set()


def clear() -> None:
    _nonces.clear()
    _used_jtis.clear()


def issue_nonce(client_key: str) -> str:
    nonce = secrets.token_urlsafe(16)
    _nonces.setdefault(client_key, set())
    return nonce


def check_and_consume_nonce(client_key: str, nonce: str, enforce: bool) -> bool:
    if not enforce:
        return True
    used = _nonces.setdefault(client_key, set())
    if nonce in used:
        return False
    used.add(nonce)
    return True


def check_and_consume_jti(jti: str, enforce: bool) -> bool:
    if not enforce:
        return True
    if jti in _used_jtis:
        return False
    _used_jtis.add(jti)
    return True
