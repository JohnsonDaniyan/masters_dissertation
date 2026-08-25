from scanner.discovery.par_enforcement import VALID_PAR


class FakeResponse:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        if self._payload is None:
            raise ValueError("No JSON")
        return self._payload


class FakeParAS:
    def __init__(self, *, allow_bypass=False, reusable=False, accept_plain=False):
        self.allow_bypass = allow_bypass
        self.reusable = reusable
        self.accept_plain = accept_plain
        self._issued = 0
        self._used: set[str] = set()
        self._entries: dict[str, dict] = {}

    def post_form(self, url, data, timeout=5.0):
        required = ("client_id", "redirect_uri", "scope", "code_challenge", "code_challenge_method")
        if any(not data.get(key) for key in required):
            return FakeResponse(422)
        if data.get("code_challenge_method") != "S256" and not self.accept_plain:
            return FakeResponse(400)
        self._issued += 1
        request_uri = f"urn:ietf:params:oauth:request_uri:{self._issued}"
        self._entries[request_uri] = data
        return FakeResponse(200, {"request_uri": request_uri, "expires_in": 60})

    def get_request(self, url, params=None, timeout=5.0):
        params = params or {}
        request_uri = params.get("request_uri")
        if not request_uri:
            if self.allow_bypass and all(params.get(key) for key in VALID_PAR):
                return FakeResponse(200, {"status": "ok", "params": params})
            return FakeResponse(400)
        entry = self._entries.get(request_uri)
        if entry is None:
            return FakeResponse(400)
        if request_uri in self._used and not self.reusable:
            return FakeResponse(400)
        self._used.add(request_uri)
        return FakeResponse(200, {"status": "ok", "params": entry})
