from fastapi import FastAPI
from app.routes import metadata

app = FastAPI(title="Mock Open Banking AS")
app.include_router(metadata.router)