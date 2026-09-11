from fastapi import FastAPI
from app.routes import authorize, introspect, jwks, metadata, par, registration, resources, token

app = FastAPI(title="Mock Open Banking AS")
app.include_router(metadata.router)
app.include_router(jwks.router)
app.include_router(par.router)
app.include_router(authorize.router)
app.include_router(token.router)
app.include_router(introspect.router)
app.include_router(resources.router)
app.include_router(registration.router)
