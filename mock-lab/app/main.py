from fastapi import FastAPI
from app.routes import authorize, metadata, par

app = FastAPI(title="Mock Open Banking AS")
app.include_router(metadata.router)
app.include_router(par.router)
app.include_router(authorize.router)