from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import parse_qs, urlparse, urlunparse


def rewrite_to_target(advertised: str | None, base_url: str, fallback_path: str) -> str:
    """Use the specimen origin the user asked to scan, not hostnames from metadata.

    Lab metadata advertises https://mock-as.local while the process is reached at
    http://127.0.0.1:8000. Probing the advertised host fails DNS; the path is kept.
    """
    origin = base_url.rstrip("/")
    path = fallback_path
    if advertised:
        parsed = urlparse(str(advertised))
        if parsed.path:
            path = parsed.path
    if not path.startswith("/"):
        path = "/" + path
    return f"{origin}{path}"


def issuer_without_query(issuer: str) -> str:
    parts = urlparse(issuer)
    if not parts.scheme or not parts.netloc:
        return issuer
    path = parts.path.rstrip("/")
    return urlunparse((parts.scheme, parts.netloc, path, "", "", ""))


from scanner.crypto.assertion_builder import build_client_assertion
from scanner.crypto.dpop_builder import build_dpop_proof
from scanner.crypto.pkce import generate_pkce
from scanner.flows.client_identity import ClientIdentity
from scanner.flows import http
from scanner.flows.http import accepted


class BaselineBroken(Exception):
    """The legitimate flow failed before any adversarial deviation was applied."""


@dataclass
class FlowState:
    metadata: dict
    request_uri: str | None = None
    code_challenge: str | None = None
    code_verifier: str | None = None
    auth_code: str | None = None
    access_token: str | None = None
    authorize_body: dict = field(default_factory=dict)


@dataclass
class ScanContext:
    base_url: str
    metadata: dict
    identity: ClientIdentity
    client_id: str | None = None
    registration_access_token: str | None = None
    redirect_uri: str = "https://scanner.example/callback"
    scope: str = "openid accounts"
    initial_access_token: str = "lab-initial-access-token"

    def url(self, key: str, fallback_path: str) -> str:
        return rewrite_to_target(self.metadata.get(key), self.base_url, fallback_path)

    @property
    def par_url(self) -> str:
        return self.url("pushed_authorization_request_endpoint", "/par")

    @property
    def authorize_url(self) -> str:
        return self.url("authorization_endpoint", "/authorize")

    @property
    def token_url(self) -> str:
        return self.url("token_endpoint", "/token")

    @property
    def register_url(self) -> str:
        return self.url("registration_endpoint", "/register")

    @property
    def introspect_url(self) -> str:
        return self.url("introspection_endpoint", "/introspect")

    @property
    def accounts_url(self) -> str:
        return f"{self.base_url.rstrip('/')}/accounts"

    @property
    def issuer(self) -> str:
        return self.metadata.get("issuer") or self.base_url

    @property
    def assertion_audience(self) -> str:
        """JWT aud must match the AS issuer identifier, not a malformed metadata variant."""
        return issuer_without_query(self.issuer)



def client_assertion(ctx: ScanContext, jti: str | None = None) -> str:
    if not ctx.client_id:
        raise BaselineBroken("No registered client_id")
    return build_client_assertion(ctx.client_id, ctx.assertion_audience, ctx.identity.rsa_private, jti=jti)


def par_body(ctx: ScanContext, challenge: str, method: str = "S256", extra: dict | None = None) -> dict:
    if not ctx.client_id:
        raise BaselineBroken("No registered client_id")
    data = {
        "client_id": ctx.client_id,
        "redirect_uri": ctx.redirect_uri,
        "scope": ctx.scope,
        "code_challenge": challenge,
        "code_challenge_method": method,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": client_assertion(ctx),
    }
    if extra:
        data.update(extra)
    return data


def ensure_registered(ctx: ScanContext) -> None:
    if ctx.client_id:
        return
    response = http.post_json(
        ctx.register_url,
        {
            "redirect_uris": [ctx.redirect_uri],
            "token_endpoint_auth_method": "private_key_jwt",
            "jwks": {"keys": [ctx.identity.rsa_public_jwk]},
            "tls_client_certificate": ctx.identity.cert_pem,
        },
        headers={"Authorization": f"Bearer {ctx.initial_access_token}"},
    )
    if not accepted(response.status_code):
        raise BaselineBroken(f"Client registration failed (HTTP {response.status_code})")
    body = response.json()
    ctx.client_id = body["client_id"]
    ctx.registration_access_token = body.get("registration_access_token")


def push_authorization_request(ctx: ScanContext, state: FlowState, method: str = "S256") -> str:
    ensure_registered(ctx)
    if not state.code_challenge:
        state.code_verifier, state.code_challenge = generate_pkce()
    response = http.post_form(ctx.par_url, par_body(ctx, state.code_challenge, method=method))
    if not accepted(response.status_code):
        raise BaselineBroken(f"PAR failed (HTTP {response.status_code})")
    request_uri = response.json().get("request_uri")
    if not request_uri:
        raise BaselineBroken("PAR response did not include request_uri")
    state.request_uri = request_uri
    return request_uri


def complete_authorization(ctx: ScanContext, state: FlowState, extra_params: dict | None = None) -> str:
    if not state.request_uri:
        raise BaselineBroken("No request_uri to authorize")
    params = {"client_id": ctx.client_id, "request_uri": state.request_uri}
    if extra_params:
        params.update(extra_params)
    response = http.get(ctx.authorize_url, params=params, follow_redirects=False)
    if not accepted(response.status_code) and response.status_code not in (302, 303):
        raise BaselineBroken(f"Authorization failed (HTTP {response.status_code})")

    body: dict = {}
    try:
        body = response.json()
    except ValueError:
        body = {}
    state.authorize_body = body

    code = body.get("code")
    if not code:
        location = response.headers.get("location") or body.get("redirect") or ""
        code = parse_qs(urlparse(location).query).get("code", [None])[0]
    if not code:
        raise BaselineBroken("Authorization response did not include a code")
    state.auth_code = code
    return code


def exchange_token(ctx: ScanContext, state: FlowState, *, with_verifier: bool = True, with_dpop: bool = False, malformed_dpop: bool = False):
    ensure_registered(ctx)
    if not state.auth_code:
        raise BaselineBroken("No authorization code to exchange")
    data = {
        "grant_type": "authorization_code",
        "code": state.auth_code,
        "client_id": ctx.client_id,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": client_assertion(ctx),
    }
    if with_verifier and state.code_verifier:
        data["code_verifier"] = state.code_verifier
    headers = {}
    if with_dpop:
        headers["DPoP"] = build_dpop_proof(
            "POST",
            ctx.token_url,
            ctx.identity.dpop_private,
            ctx.identity.dpop_public_jwk,
            malformed=malformed_dpop,
        )
    return http.post_form(ctx.token_url, data, headers=headers or None)


def legitimate_access_token(ctx: ScanContext, *, dpop: bool = False) -> FlowState:
    """Drive PAR → authorize → token. Raises BaselineBroken if any step fails."""
    ensure_registered(ctx)
    state = FlowState(metadata=ctx.metadata)
    push_authorization_request(ctx, state)
    complete_authorization(ctx, state)
    response = exchange_token(ctx, state, with_dpop=dpop)
    if not accepted(response.status_code):
        raise BaselineBroken(f"Token request failed (HTTP {response.status_code})")
    state.access_token = response.json().get("access_token")
    if not state.access_token:
        raise BaselineBroken("Token response did not include access_token")
    return state
