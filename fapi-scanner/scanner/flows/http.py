import httpx

TIMEOUT = 5.0


def get(url: str, params: dict | None = None, headers: dict | None = None, follow_redirects: bool = False):
    return httpx.get(
        url,
        params=params,
        headers=headers,
        timeout=TIMEOUT,
        follow_redirects=follow_redirects,
    )


def post_form(url: str, data: dict, headers: dict | None = None):
    return httpx.post(url, data=data, headers=headers, timeout=TIMEOUT)


def post_json(url: str, payload: dict, headers: dict | None = None):
    return httpx.post(url, json=payload, headers=headers, timeout=TIMEOUT)


def put_json(url: str, payload: dict, headers: dict | None = None):
    return httpx.put(url, json=payload, headers=headers, timeout=TIMEOUT)


def accepted(status_code: int | None) -> bool:
    return status_code is not None and 200 <= status_code < 300


def rejected(status_code: int | None) -> bool:
    return status_code is not None and status_code >= 400
