import pytest

from app.auth import jti_store
from app.config import settings


@pytest.fixture(autouse=True)
def reset_client_auth_state():
    jti_store.clear()
    settings.JWT_REPLAY_PROTECTION = True
    settings.MTLS_CLIENT_AUTH_ENFORCED = True
    settings.ALLOW_WEAK_CLIENT_AUTH = False
    yield
    jti_store.clear()
    settings.JWT_REPLAY_PROTECTION = True
    settings.MTLS_CLIENT_AUTH_ENFORCED = True
    settings.ALLOW_WEAK_CLIENT_AUTH = False
