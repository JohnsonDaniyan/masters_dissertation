from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.config import (
    BOOL_FIELDS,
    capture_original_env,
    parse_env_toggles,
    restore_original_env,
    settings,
    write_env_toggle,
)

router = APIRouter()


class TogglePatch(BaseModel):
    key: str
    value: bool


def _payload() -> dict:
    return {"toggles": parse_env_toggles()}


@router.get("/lab/config")
def get_config():
    capture_original_env()
    return _payload()


@router.post("/lab/reload")
def reload_config():
    settings.reload()
    return _payload()


@router.patch("/lab/config")
def patch_config(body: TogglePatch):
    capture_original_env()
    if body.key not in BOOL_FIELDS:
        raise HTTPException(status_code=400, detail=f"Unknown toggle {body.key}")
    write_env_toggle(body.key, body.value)
    return _payload()


@router.post("/lab/config/reset")
def reset_config():
    restore_original_env()
    return _payload()
