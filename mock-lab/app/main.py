from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import start_env_watcher
from app.routes import authorize, introspect, jwks, lab, metadata, par, registration, resources, token


@asynccontextmanager
async def lifespan(_app: FastAPI):
    stop = start_env_watcher()
    try:
        yield
    finally:
        stop()


app = FastAPI(title="Mock Open Banking AS", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(metadata.router)
app.include_router(jwks.router)
app.include_router(par.router)
app.include_router(authorize.router)
app.include_router(token.router)
app.include_router(introspect.router)
app.include_router(resources.router)
app.include_router(registration.router)
app.include_router(lab.router)
