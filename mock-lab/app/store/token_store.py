_store: dict[str, dict] = {}


def clear() -> None:
    _store.clear()


def store(token: str, record: dict) -> None:
    _store[token] = record


def lookup(token: str) -> dict | None:
    return _store.get(token)
