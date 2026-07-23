"""
main.py — SEC_AI_Chatbot FastAPI application.

Phase 1 hardening applied:
  ✅ Secrets / configuration loaded from .env via config.py
  ✅ Structured logging via logger.py
  ✅ Secure error handling (no raw exception details exposed to clients)

Phase 2 hardening applied:
  ✅ JWT authentication — /token issues signed tokens
  ✅ /chat and /upload require a valid Bearer token
  ✅ 401 Unauthorized returned on missing / invalid / expired tokens

Phase 3 hardening applied:
  ✅ Rate limiting on /token, /upload, /chat (per-IP via slowapi)
  ✅ Request body size limit (ContentSizeLimitMiddleware)
  ✅ Prompt length limit (MAX_PROMPT_CHARS per message)
  ✅ Response length limit (MAX_RESPONSE_CHARS truncation)
  ✅ Configurable Ollama timeout (OLLAMA_TIMEOUT)
"""

import os
import requests

# pyrefly: ignore [missing-import]
from fastapi import FastAPI, File, Form, UploadFile, Request, Depends
# pyrefly: ignore [missing-import]
from fastapi.responses import JSONResponse, FileResponse
# pyrefly: ignore [missing-import]
from fastapi.staticfiles import StaticFiles
# pyrefly: ignore [missing-import]
from fastapi.middleware.cors import CORSMiddleware
# pyrefly: ignore [missing-import]
from starlette.middleware.base import BaseHTTPMiddleware
# pyrefly: ignore [missing-import]
from starlette.responses import Response
# pyrefly: ignore [missing-import]
import fitz  # PyMuPDF
# pyrefly: ignore [missing-import]
from docx import Document
# pyrefly: ignore [missing-import]
from slowapi import Limiter, _rate_limit_exceeded_handler
# pyrefly: ignore [missing-import]
from slowapi.util import get_remote_address
# pyrefly: ignore [missing-import]
from slowapi.errors import RateLimitExceeded

from config import (
    OLLAMA_URL, MODEL_NAME, ACTIVE_PROMPT_FILE, UPLOAD_DIR, HOST, PORT,
    APP_USERNAME, APP_PASSWORD,
    RATE_LIMIT_CHAT, RATE_LIMIT_UPLOAD, RATE_LIMIT_TOKEN,
    MAX_REQUEST_SIZE_BYTES, MAX_PROMPT_CHARS, MAX_RESPONSE_CHARS, OLLAMA_TIMEOUT,
)
from logger import log
from auth import create_access_token, verify_token

# ── Rate limiter ───────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

# ── App setup ──────────────────────────────────────────────────────────────────
app = FastAPI()

# Attach limiter to app state and register the 429 handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── Request size limit middleware ──────────────────────────────────────────────
class ContentSizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject requests whose body exceeds MAX_REQUEST_SIZE_BYTES."""

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > MAX_REQUEST_SIZE_BYTES:
            log.warning("Request body too large",
                        extra={"content_length": content_length,
                               "limit": MAX_REQUEST_SIZE_BYTES})
            return Response(
                content='{"error": "Request body too large."}',
                status_code=413,
                media_type="application/json",
            )
        return await call_next(request)

# Register middlewares (order matters: size check runs before CORS)
app.add_middleware(ContentSizeLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # tightened in Phase 6
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ensure required directories exist
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
os.makedirs("static", exist_ok=True)

log.info("Application started",
         extra={"ollama_url": OLLAMA_URL, "model": MODEL_NAME,
                "prompt_file": ACTIVE_PROMPT_FILE, "upload_dir": str(UPLOAD_DIR),
                "rate_limit_chat": RATE_LIMIT_CHAT,
                "max_request_bytes": MAX_REQUEST_SIZE_BYTES,
                "max_prompt_chars": MAX_PROMPT_CHARS})

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/")
def read_root():
    return FileResponse("static/login.html")


@app.get("/chat-ui")
def chat_ui():
    return FileResponse("static/index.html")


@app.post("/token")
@limiter.limit(RATE_LIMIT_TOKEN)
async def login(request: Request, username: str = Form(...), password: str = Form(...)):
    """
    Issue a JWT access token in exchange for valid credentials.
    Rate-limited to prevent brute-force attacks.
    """
    if username != APP_USERNAME or password != APP_PASSWORD:
        log.warning("Failed login attempt", extra={"username": username})
        from fastapi import HTTPException, status
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = create_access_token(subject=username)
    log.info("Successful login", extra={"username": username})
    return {"access_token": token, "token_type": "bearer"}


@app.post("/upload")
@limiter.limit(RATE_LIMIT_UPLOAD)
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    current_user: str = Depends(verify_token),
):
    log.info("File upload received", extra={"upload_filename": file.filename,
                                            "content_type": file.content_type})

    # Save the file — further security checks come in Phase 4
    file_path = UPLOAD_DIR / file.filename  # type: ignore[operator]

    try:
        contents = await file.read()
        with open(file_path, "wb") as f:
            f.write(contents)
    except OSError as exc:
        log.error("Failed to save uploaded file", extra={"upload_filename": file.filename,
                                                          "error": str(exc)})
        return JSONResponse(status_code=500,
                            content={"error": "File could not be saved. Please try again."})

    extracted_text = ""

    if file.filename.endswith(".txt"):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                extracted_text = f.read()
        except OSError as exc:
            log.error("Failed to read txt file", extra={"upload_filename": file.filename,
                                                         "error": str(exc)})
            return JSONResponse(status_code=500,
                                content={"error": "Could not read the uploaded file."})

    elif file.filename.endswith(".pdf"):
        try:
            doc = fitz.open(str(file_path))
            for page in doc:
                extracted_text += page.get_text()
            doc.close()
        except Exception as exc:
            log.error("Failed to parse PDF", extra={"upload_filename": file.filename,
                                                      "error": str(exc)})
            extracted_text = "Could not extract text from the PDF."

    elif file.filename.endswith(".docx"):
        try:
            doc = Document(str(file_path))
            extracted_text = "\n".join([para.text for para in doc.paragraphs])
        except Exception as exc:
            log.error("Failed to parse DOCX", extra={"upload_filename": file.filename,
                                                       "error": str(exc)})
            extracted_text = "Could not extract text from the document."

    log.info("File processed successfully", extra={"upload_filename": file.filename,
                                                    "chars_extracted": len(extracted_text)})
    return {"filename": file.filename, "extracted_text": extracted_text}


@app.post("/chat")
@limiter.limit(RATE_LIMIT_CHAT)
async def chat_endpoint(
    request: Request,
    current_user: str = Depends(verify_token),
):
    try:
        data = await request.json()
    except Exception:
        log.warning("Malformed JSON body received on /chat")
        return JSONResponse(status_code=400, content={"error": "Invalid JSON body."})

    messages = data.get("messages", [])

    # ── Prompt length limit ────────────────────────────────────────────────────
    for msg in messages:
        content = msg.get("content", "")
        if len(content) > MAX_PROMPT_CHARS:
            log.warning("Prompt too long",
                        extra={"user": current_user,
                               "char_count": len(content),
                               "limit": MAX_PROMPT_CHARS})
            return JSONResponse(
                status_code=400,
                content={"error": f"Message too long. Maximum {MAX_PROMPT_CHARS} characters allowed."},
            )

    log.info("Chat request received", extra={"message_count": len(messages)})

    # Inject the system prompt if one is configured
    if ACTIVE_PROMPT_FILE and os.path.exists(ACTIVE_PROMPT_FILE):
        try:
            with open(ACTIVE_PROMPT_FILE, "r", encoding="utf-8") as f:
                system_prompt = f.read()
            if not any(msg.get("role") == "system" for msg in messages):
                messages.insert(0, {"role": "system", "content": system_prompt})
        except OSError as exc:
            log.error("Could not load system prompt", extra={"file": ACTIVE_PROMPT_FILE,
                                                              "error": str(exc)})

    payload = {
        "model": MODEL_NAME,
        "messages": messages,
        "stream": False,
    }

    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=OLLAMA_TIMEOUT)
        response.raise_for_status()
        result = response.json()

        # ── Response length limit ──────────────────────────────────────────────
        ai_content = result.get("message", {}).get("content", "")
        if len(ai_content) > MAX_RESPONSE_CHARS:
            log.warning("AI response truncated",
                        extra={"original_len": len(ai_content),
                               "limit": MAX_RESPONSE_CHARS})
            result["message"]["content"] = ai_content[:MAX_RESPONSE_CHARS] + "\n\n[Response truncated]"

        log.info("Ollama response received", extra={"status_code": response.status_code})
        return result

    except requests.exceptions.Timeout:
        log.error("Ollama request timed out")
        return JSONResponse(status_code=504,
                            content={"error": "The AI service took too long to respond."})
    except requests.exceptions.ConnectionError:
        log.error("Could not connect to Ollama")
        return JSONResponse(status_code=503,
                            content={"error": "AI service is currently unavailable."})
    except requests.exceptions.RequestException as exc:
        log.error("Ollama request failed", extra={"error": str(exc)})
        return JSONResponse(status_code=500,
                            content={"error": "An unexpected error occurred."})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=HOST, port=PORT)
