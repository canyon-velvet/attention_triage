"""`triage ui`: the review inbox and its API (SPEC.md §6) on 127.0.0.1."""

from contextlib import closing
from pathlib import Path

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.staticfiles import StaticFiles

from attention_triage import hook, store
from attention_triage.digest import digest

# Loopback only: the digest shows commands, paths and URLs from every project.
HOST = "127.0.0.1"
DEFAULT_PORT = 8765

app = FastAPI()
# Binding to loopback isn't enough: a web page can point its own name at 127.0.0.1 (DNS
# rebinding) and read the API as same-origin. Its requests still carry that name as the Host.
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost"])


@app.get("/api/digest")
def get_digest() -> dict:
    with closing(store.connect()) as conn:
        return digest(conn)


@app.get("/api/health")
def health() -> dict:
    return {"ok": True}


# The inbox page, built from web/ (`pnpm build`). Mounted last so the /api routes match first.
app.mount("/", StaticFiles(directory=Path(__file__).parent / "static", html=True))


def serve(port: int) -> None:
    """Store and flag spooled events first, so the digest isn't missing the ones the hook couldn't
    store."""
    with closing(store.connect()) as conn:
        hook.flag(conn, store.ingest_spool(conn))
    uvicorn.run(app, host=HOST, port=port)
