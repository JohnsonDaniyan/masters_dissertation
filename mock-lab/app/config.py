import os
import sys
import threading
from pathlib import Path

from dotenv import load_dotenv

ENV_PATH = Path(os.getenv("MOCK_LAB_ENV_PATH", Path(__file__).resolve().parent.parent / ".env"))

BOOL_FIELDS = (
    "METADATA_ENABLED",
    "METADATA_INCOMPLETE",
    "ISSUER_MISMATCH",
    "ISSUER_MALFORMED",
    "PAR_ENFORCED",
    "REQUEST_URI_REUSABLE",
    "REQUEST_URI_LONG_LIVED",
    "ALLOW_PLAIN_PKCE",
    "PKCE_ENFORCED",
    "JWT_REPLAY_PROTECTION",
    "MTLS_CLIENT_AUTH_ENFORCED",
    "ALLOW_WEAK_CLIENT_AUTH",
    "DPOP_VALIDATION_STRICT",
    "DPOP_REPLAY_PROTECTION",
    "MTLS_BINDING_ENFORCED",
    "TOKEN_UNSTRUCTURED",
    "INTROSPECTION_AUTH_REQUIRED",
    "RS_TRUSTS_AS_BLINDLY",
    "ISS_PARAM_OMITTED",
    "JARM_SIGNATURE_CHECK",
    "REDIRECT_URI_LOOSE_MATCH",
    "DCR_OPEN_REGISTRATION",
    "DCM_AUTH_REQUIRED",
)

_BOOL_DEFAULTS = {
    "METADATA_ENABLED": "true",
    "METADATA_INCOMPLETE": "false",
    "ISSUER_MISMATCH": "false",
    "ISSUER_MALFORMED": "false",
    "PAR_ENFORCED": "true",
    "REQUEST_URI_REUSABLE": "false",
    "REQUEST_URI_LONG_LIVED": "false",
    "ALLOW_PLAIN_PKCE": "false",
    "PKCE_ENFORCED": "true",
    "JWT_REPLAY_PROTECTION": "true",
    "MTLS_CLIENT_AUTH_ENFORCED": "true",
    "ALLOW_WEAK_CLIENT_AUTH": "false",
    "DPOP_VALIDATION_STRICT": "true",
    "DPOP_REPLAY_PROTECTION": "true",
    "MTLS_BINDING_ENFORCED": "true",
    "TOKEN_UNSTRUCTURED": "false",
    "INTROSPECTION_AUTH_REQUIRED": "true",
    "RS_TRUSTS_AS_BLINDLY": "false",
    "ISS_PARAM_OMITTED": "false",
    "JARM_SIGNATURE_CHECK": "true",
    "REDIRECT_URI_LOOSE_MATCH": "false",
    "DCR_OPEN_REGISTRATION": "false",
    "DCM_AUTH_REQUIRED": "true",
}

_original_env_text: str | None = None
_original_captured = False


def _env_bool(name: str) -> bool:
    return os.getenv(name, _BOOL_DEFAULTS[name]).lower() == "true"


class Settings:
    def __init__(self) -> None:
        self.reload()

    def reload(self) -> None:
        load_dotenv(ENV_PATH, override=True)
        self.ISSUER = os.getenv("ISSUER", "https://mock-as.local")
        self.BASE_URL = os.getenv("BASE_URL", "https://mock-as.local")
        self.INITIAL_ACCESS_TOKEN = os.getenv("INITIAL_ACCESS_TOKEN", "lab-initial-access-token")
        for name in BOOL_FIELDS:
            setattr(self, name, _env_bool(name))


settings = Settings()


def capture_original_env() -> None:
    global _original_env_text, _original_captured
    if _original_captured:
        return
    _original_captured = True
    if ENV_PATH.exists():
        _original_env_text = ENV_PATH.read_text()


def restore_original_env() -> None:
    if _original_env_text is None:
        return
    ENV_PATH.write_text(_original_env_text)
    settings.reload()


def parse_env_toggles() -> dict[str, bool]:
    toggles: dict[str, bool] = {}
    if not ENV_PATH.exists():
        return {name: bool(getattr(settings, name)) for name in BOOL_FIELDS}
    for raw in ENV_PATH.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key not in BOOL_FIELDS:
            continue
        value = value.split("#", 1)[0].strip()
        toggles[key] = value.lower() == "true"
    return toggles


def write_env_toggle(key: str, enabled: bool) -> None:
    if key not in BOOL_FIELDS:
        raise ValueError(f"Unknown toggle {key}")
    if not ENV_PATH.exists():
        raise FileNotFoundError(str(ENV_PATH))
    rendered = "true" if enabled else "false"
    lines = ENV_PATH.read_text().splitlines(keepends=True)
    found = False
    updated: list[str] = []
    for line in lines:
        stripped = line.lstrip()
        if stripped.startswith("#") or "=" not in line:
            updated.append(line)
            continue
        current_key, rest = line.split("=", 1)
        if current_key.strip() != key:
            updated.append(line)
            continue
        found = True
        comment = ""
        newline = ""
        body = rest
        if body.endswith("\n"):
            newline = "\n"
            body = body[:-1]
            if body.endswith("\r"):
                newline = "\r\n"
                body = body[:-1]
        if "#" in body:
            _, comment_part = body.split("#", 1)
            comment = "#" + comment_part
            spacing = "" if comment.startswith(" ") or comment.startswith("\t") else " "
            updated.append(f"{current_key}={rendered}{spacing}{comment}{newline}")
        else:
            updated.append(f"{current_key}={rendered}{newline}")
    if not found:
        suffix = "" if not lines or lines[-1].endswith("\n") else "\n"
        updated.append(f"{suffix}{key}={rendered}\n")
    ENV_PATH.write_text("".join(updated))
    os.environ[key] = rendered
    setattr(settings, key, enabled)


def start_env_watcher(interval: float = 0.4):
    """Reload settings when .env changes. No-op under pytest."""
    if "pytest" in sys.modules:
        return lambda: None

    capture_original_env()
    stop = threading.Event()
    last_mtime = ENV_PATH.stat().st_mtime if ENV_PATH.exists() else 0.0

    def loop() -> None:
        nonlocal last_mtime
        while not stop.wait(interval):
            try:
                mtime = ENV_PATH.stat().st_mtime
            except FileNotFoundError:
                continue
            if mtime != last_mtime:
                last_mtime = mtime
                settings.reload()

    thread = threading.Thread(target=loop, daemon=True, name="mock-lab-env-watch")
    thread.start()

    def shutdown() -> None:
        stop.set()
        restore_original_env()

    return shutdown
