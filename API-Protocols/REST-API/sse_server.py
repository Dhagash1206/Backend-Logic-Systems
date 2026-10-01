import asyncio
import os
from datetime import datetime
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

API_TOKEN = os.getenv("API_TOKEN", "YOUR_TOKEN")
MAX_STREAM_SECONDS = 60
bearer_scheme = HTTPBearer(auto_error=False)


def require_token(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)):
    if credentials is None or credentials.credentials != API_TOKEN:
        raise HTTPException(status_code=401, detail="Unauthorized")


app = FastAPI()


async def event_stream(request: Request):
    started = asyncio.get_event_loop().time()
    try:
        while True:
            if await request.is_disconnected():
                break
            if asyncio.get_event_loop().time() - started > MAX_STREAM_SECONDS:
                yield "event: close\ndata: stream time limit reached\n\n"
                break
            yield f"data: {datetime.now().isoformat()}\n\n"
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        pass
    except Exception as e:
        yield f"event: error\ndata: {e}\n\n"


@app.get("/events", dependencies=[Depends(require_token)])
async def events(request: Request):
    return StreamingResponse(
        event_stream(request),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )