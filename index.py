from fastapi import FastAPI

from teampulse.main import app as api

# Vercel looks for a FastAPI instance named "app" in this file.
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/", api)
