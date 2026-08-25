from fastapi import APIRouter

from app.tokens.issuer import as_jwk

router = APIRouter()


@router.get("/jwks")
def jwks():
    return {"keys": [as_jwk()]}
