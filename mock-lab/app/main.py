from fastapi import FastAPI
from app.routes import authorize, metadata, par, resource, token

app = FastAPI(title="Mock Open Banking AS")
app.include_router(metadata.router)
app.include_router(par.router)
app.include_router(authorize.router)
app.include_router(token.router)
app.include_router(resource.router)