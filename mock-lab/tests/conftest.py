import pytest

from app.auth import jti_store
from app.config import settings
from app.dpop import nonce_store
from app.store import token_store


@pytest.fixture(autouse=True)
def reset_client_auth_state():
    jti_store.clear()
    nonce_store.clear()
    token_store.clear()
    settings.JWT_REPLAY_PROTECTION = True
    settings.MTLS_CLIENT_AUTH_ENFORCED = True
    settings.ALLOW_WEAK_CLIENT_AUTH = False
    settings.DPOP_VALIDATION_STRICT = True
    settings.DPOP_REPLAY_PROTECTION = True
    settings.MTLS_BINDING_ENFORCED = True
    settings.TOKEN_UNSTRUCTURED = False
    settings.INTROSPECTION_AUTH_REQUIRED = True
    settings.RS_TRUSTS_AS_BLINDLY = False
    settings.ISS_PARAM_OMITTED = False
    settings.JARM_SIGNATURE_CHECK = True
    settings.REDIRECT_URI_LOOSE_MATCH = False
    yield
    jti_store.clear()
    nonce_store.clear()
    token_store.clear()
    settings.JWT_REPLAY_PROTECTION = True
    settings.MTLS_CLIENT_AUTH_ENFORCED = True
    settings.ALLOW_WEAK_CLIENT_AUTH = False
    settings.DPOP_VALIDATION_STRICT = True
    settings.DPOP_REPLAY_PROTECTION = True
    settings.MTLS_BINDING_ENFORCED = True
    settings.TOKEN_UNSTRUCTURED = False
    settings.INTROSPECTION_AUTH_REQUIRED = True
    settings.RS_TRUSTS_AS_BLINDLY = False
    settings.ISS_PARAM_OMITTED = False
    settings.JARM_SIGNATURE_CHECK = True
    settings.REDIRECT_URI_LOOSE_MATCH = False
