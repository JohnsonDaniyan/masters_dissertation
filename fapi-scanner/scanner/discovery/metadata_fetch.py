from dataclasses import dataclass

import httpx

METADATA_PATH = "/.well-known/oauth-authorization-server"


def normalise_base_url(base_url: str) -> str:
    return base_url.rstrip("/")


@dataclass
class MetadataFetch:
    url: str
    error: str | None = None
    status_code: int | None = None
    document: dict | None = None


def fetch_metadata(base_url: str, timeout: float = 5.0) -> MetadataFetch:
    url = f"{normalise_base_url(base_url)}{METADATA_PATH}"
    try:
        response = httpx.get(url, timeout=timeout, follow_redirects=True)
    except httpx.RequestError as exc:
        return MetadataFetch(url=url, error=str(exc))

    try:
        parsed = response.json()
        document = parsed if isinstance(parsed, dict) else None
    except ValueError:
        document = None

    return MetadataFetch(
        url=url,
        status_code=response.status_code,
        document=document,
    )
