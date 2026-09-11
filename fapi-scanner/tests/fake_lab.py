import secrets
from urllib.parse import urlparse

import jwt

IAT = "lab-initial-access-token"


class FakeResponse:
    def __init__(self, status_code, payload=None, headers=None):
        self.status_code = status_code
        self.headers = headers or {}
        self._payload = payload

    def json(self):
        if self._payload is None:
            raise ValueError("No JSON")
        return self._payload


class FakeLab:
    """In-memory AS that mirrors the mock-lab toggles for scanner unit tests."""

    def __init__(self, **toggles):
        self.par_enforced = toggles.get("par_enforced", True)
        self.request_uri_reusable = toggles.get("request_uri_reusable", False)
        self.pkce_enforced = toggles.get("pkce_enforced", True)
        self.allow_plain_pkce = toggles.get("allow_plain_pkce", False)
        self.jwt_replay_protection = toggles.get("jwt_replay_protection", True)
        self.mtls_client_auth_enforced = toggles.get("mtls_client_auth_enforced", True)
        self.allow_weak_client_auth = toggles.get("allow_weak_client_auth", False)
        self.dpop_replay_protection = toggles.get("dpop_replay_protection", True)
        self.dpop_validation_strict = toggles.get("dpop_validation_strict", True)
        self.mtls_binding_enforced = toggles.get("mtls_binding_enforced", True)
        self.introspection_auth_required = toggles.get("introspection_auth_required", True)
        self.rs_trusts_as_blindly = toggles.get("rs_trusts_as_blindly", False)
        self.iss_param_omitted = toggles.get("iss_param_omitted", False)
        self.redirect_uri_loose_match = toggles.get("redirect_uri_loose_match", False)
        self.jarm_signature_check = toggles.get("jarm_signature_check", True)
        self.dcr_open_registration = toggles.get("dcr_open_registration", False)
        self.dcm_auth_required = toggles.get("dcm_auth_required", True)

        self.issuer = "https://as.example"
        self._uris: dict[str, dict] = {}
        self._used_uris: set[str] = set()
        self._seen_jti: set[str] = set()
        self._codes: dict[str, dict] = {}
        self._tokens: dict[str, dict] = {}
        self._dpop_proofs: set[str] = set()
        self._clients: dict[str, dict] = {}
        self._issued = 0

    def install(self, monkeypatch):
        monkeypatch.setattr("scanner.flows.http.get", self.get)
        monkeypatch.setattr("scanner.flows.http.post_form", self.post_form)
        monkeypatch.setattr("scanner.flows.http.post_json", self.post_json)
        monkeypatch.setattr("scanner.flows.http.put_json", self.put_json)

    def _path(self, url: str) -> str:
        return urlparse(url).path.rstrip("/") or "/"

    def _bearer(self, headers: dict | None) -> str | None:
        header = (headers or {}).get("Authorization") or (headers or {}).get("authorization")
        if not header or not header.lower().startswith("bearer "):
            return None
        return header.split(" ", 1)[1].strip()

    def _has_basic(self, headers: dict | None) -> bool:
        header = (headers or {}).get("Authorization") or (headers or {}).get("authorization") or ""
        return header.lower().startswith("basic ")

    def _has_cert(self, headers: dict | None) -> bool:
        headers = headers or {}
        return bool(headers.get("X-SSL-Client-Cert") or headers.get("x-ssl-client-cert"))

    def _assertion_jti(self, data: dict) -> str | None:
        assertion = data.get("client_assertion")
        if not assertion:
            return None
        claims = jwt.decode(assertion, options={"verify_signature": False, "verify_aud": False})
        return claims.get("jti")

    def get(self, url, params=None, headers=None, follow_redirects=False):
        path = self._path(url)
        params = params or {}
        if path.endswith("/authorize"):
            return self._authorize(params)
        if path.endswith("/accounts"):
            return self._accounts(headers or {})
        return FakeResponse(404)

    def post_form(self, url, data, headers=None):
        path = self._path(url)
        data = data or {}
        headers = headers or {}
        if path.endswith("/par"):
            return self._par(data, headers)
        if path.endswith("/token"):
            return self._token(data, headers)
        if path.endswith("/introspect"):
            return self._introspect(headers)
        return FakeResponse(404)

    def post_json(self, url, payload, headers=None):
        path = self._path(url)
        if path.endswith("/register"):
            return self._register(payload or {}, headers or {})
        return FakeResponse(404)

    def put_json(self, url, payload, headers=None):
        path = self._path(url)
        if "/register/" in path:
            client_id = path.rsplit("/", 1)[-1]
            return self._update(client_id, payload or {}, headers or {})
        return FakeResponse(404)

    def _par(self, data, headers):
        if self._has_basic(headers) and not self.allow_weak_client_auth:
            return FakeResponse(401, {"detail": "secret not allowed"})
        if self._has_basic(headers) and self.allow_weak_client_auth:
            return self._issue_par(data)

        jti = self._assertion_jti(data)
        if jti:
            if self.jwt_replay_protection and jti in self._seen_jti:
                return FakeResponse(401, {"detail": "replay"})
            self._seen_jti.add(jti)
            if data.get("code_challenge_method") == "plain" and not self.allow_plain_pkce:
                return FakeResponse(400, {"detail": "plain"})
            return self._issue_par(data)

        if not self._has_cert(headers) and self.mtls_client_auth_enforced:
            return FakeResponse(401, {"detail": "client authentication required"})
        if data.get("code_challenge_method") == "plain" and not self.allow_plain_pkce:
            return FakeResponse(400, {"detail": "plain"})
        return self._issue_par(data)

    def _issue_par(self, data):
        self._issued += 1
        request_uri = f"urn:ietf:params:oauth:request_uri:{self._issued}"
        self._uris[request_uri] = data
        return FakeResponse(200, {"request_uri": request_uri, "expires_in": 60})

    def _authorize(self, params):
        request_uri = params.get("request_uri")
        if not request_uri:
            if self.par_enforced:
                return FakeResponse(400, {"detail": "request_uri required"})
            return self._authz_ok(params.get("redirect_uri") or "https://scanner.example/callback")

        entry = self._uris.get(request_uri)
        if entry is None:
            return FakeResponse(400, {"detail": "unknown request_uri"})
        if request_uri in self._used_uris and not self.request_uri_reusable:
            return FakeResponse(400, {"detail": "replay"})
        self._used_uris.add(request_uri)

        registered = entry.get("redirect_uri") or "https://scanner.example/callback"
        requested = params.get("redirect_uri") or registered
        if requested != registered:
            if not (self.redirect_uri_loose_match and requested.startswith(registered)):
                return FakeResponse(400, {"detail": "redirect_uri mismatch"})
        return self._authz_ok(requested, entry)

    def _authz_ok(self, redirect_uri, entry=None):
        code = secrets.token_urlsafe(8)
        self._codes[code] = dict(entry or {})
        iss = None if self.iss_param_omitted else self.issuer
        query = f"code={code}" + (f"&iss={iss}" if iss else "")
        jarm = jwt.encode(
            {"code": code, "iss": self.issuer},
            key=None if not self.jarm_signature_check else ("k" * 32),
            algorithm="none" if not self.jarm_signature_check else "HS256",
        )
        body = {
            "status": "ok",
            "code": code,
            "redirect": f"{redirect_uri}?{query}",
            "jarm": jarm,
        }
        if iss:
            body["iss"] = iss
        return FakeResponse(200, body)

    def _token(self, data, headers):
        if not data.get("client_assertion") and not self._has_cert(headers) and self.mtls_client_auth_enforced:
            return FakeResponse(401, {"detail": "client authentication required"})
        code = data.get("code")
        if code not in self._codes:
            return FakeResponse(400, {"detail": "invalid_grant"})
        if self.pkce_enforced and not data.get("code_verifier"):
            return FakeResponse(400, {"detail": "code_verifier required"})

        dpop = headers.get("DPoP") or headers.get("dpop")
        if dpop:
            claims = jwt.decode(dpop, options={"verify_signature": False, "verify_aud": False})
            if self.dpop_validation_strict and ("htm" not in claims or "htu" not in claims):
                return FakeResponse(400, {"detail": "invalid_dpop_proof"})

        token = secrets.token_urlsafe(12)
        record = {"cnf": {}}
        if dpop:
            record["cnf"]["jkt"] = "scanner-jkt"
        elif self._has_cert(headers):
            record["cnf"]["x5t#S256"] = "scanner-cert"
        self._tokens[token] = record
        token_type = "DPoP" if dpop else "Bearer"
        return FakeResponse(200, {"access_token": token, "token_type": token_type, "cnf": record["cnf"]})

    def _accounts(self, headers):
        auth = headers.get("Authorization") or headers.get("authorization") or ""
        token = auth.split(" ", 1)[1].strip() if " " in auth else ""
        record = self._tokens.get(token)
        if record is None:
            return FakeResponse(401, {"detail": "invalid_token"})
        if self.rs_trusts_as_blindly:
            return FakeResponse(200, {"accounts": []})

        cnf = record.get("cnf") or {}
        dpop = headers.get("DPoP") or headers.get("dpop")
        if "jkt" in cnf:
            if not dpop:
                return FakeResponse(401, {"detail": "DPoP required"})
            if self.dpop_replay_protection and dpop in self._dpop_proofs:
                return FakeResponse(401, {"detail": "replay"})
            self._dpop_proofs.add(dpop)
        if "x5t#S256" in cnf and self.mtls_binding_enforced and not self._has_cert(headers):
            return FakeResponse(401, {"detail": "cert mismatch"})
        return FakeResponse(200, {"accounts": []})

    def _introspect(self, headers):
        if self.introspection_auth_required and not self._bearer(headers):
            return FakeResponse(401, {"detail": "auth required"})
        return FakeResponse(200, {"active": False})

    def _register(self, payload, headers):
        token = self._bearer(headers)
        if not self.dcr_open_registration and token != IAT:
            return FakeResponse(401, {"detail": "initial access token required"})
        client_id = f"dcr-{secrets.token_urlsafe(6)}"
        rat = secrets.token_urlsafe(8)
        self._clients[client_id] = {"registration_access_token": rat, **payload}
        return FakeResponse(
            200,
            {
                "client_id": client_id,
                "registration_access_token": rat,
                "jwks": payload.get("jwks") or {"keys": [{}]},
                "redirect_uris": payload.get("redirect_uris") or [],
            },
        )

    def _update(self, client_id, payload, headers):
        client = self._clients.get(client_id)
        if client is None:
            return FakeResponse(404)
        if self.dcm_auth_required:
            token = self._bearer(headers)
            if token != client.get("registration_access_token"):
                return FakeResponse(401, {"detail": "registration access token required"})
        return FakeResponse(200, {"client_id": client_id, **payload})
