import json
import logging
import time
from collections import defaultdict, deque
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, HTTPException, Request  # noqa: E402
from fastapi.responses import FileResponse, StreamingResponse  # noqa: E402
from fastapi.staticfiles import StaticFiles  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402

from .pipeline import analyze, cfg  # noqa: E402

log = logging.getLogger("scamshield")
STATIC = Path(__file__).parent / "static"
app = FastAPI(title="ScamShield", version="1.0.0")
_hits: dict[str, deque] = defaultdict(deque)


class AnalyzeIn(BaseModel):
    message: str = Field(min_length=10, max_length=3000)
    lang: str = Field(default="en", pattern="^(en|hi)$")


def check_rate(request: Request) -> None:
    fwd = request.headers.get("x-forwarded-for", "")
    ip = fwd.split(",")[0].strip() or (request.client.host if request.client else "unknown")
    limit = int(cfg("RATE_LIMIT_PER_10_MIN", "12"))
    now, q = time.time(), _hits[ip]
    while q and now - q[0] > 600:
        q.popleft()
    if len(q) >= limit:
        raise HTTPException(429, "Too many checks from this connection. Please wait a few minutes.")
    q.append(now)


@app.post("/api/analyze")
async def api_analyze(body: AnalyzeIn, request: Request):
    check_rate(request)

    async def stream():
        try:
            async for ev in analyze(body.message.strip(), body.lang):
                yield f"data: {json.dumps(ev, ensure_ascii=False)}\n\n"
        except Exception as e:  # message text is never logged, only the error class
            log.warning("analysis failed: %s", type(e).__name__)
            msg = str(e) if isinstance(e, RuntimeError) else "The analysis service had a problem. Please try again."
            yield f"data: {json.dumps({'event': 'error', 'message': msg})}\n\n"

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/health")
async def health():
    return {"ok": True, "models_configured": bool(cfg("MODEL_FAST") and cfg("MODEL_REASON")),
            "token_factory_key": bool(cfg("NEBIUS_API_KEY")), "tavily_key": bool(cfg("TAVILY_API_KEY"))}


@app.get("/")
async def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
