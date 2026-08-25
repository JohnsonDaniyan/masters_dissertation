_seen_jti: set[str] = set()


def clear() -> None:
    _seen_jti.clear()


def is_replay(jti: str, allow_replay: bool) -> bool:
    if allow_replay:
        return False
    if jti in _seen_jti:
        return True
    _seen_jti.add(jti)
    return False
