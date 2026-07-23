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
"""

import os
import requests

# pyrefly: ignore [missing-import]
from fastapi import FastAPI, File, UploadFile, Request, Depends
# pyrefly: ignore [missing-import]
from fastapi.responses import JSONResponse, FileResponse
# pyrefly: ignore [missing-import]
from fastapi.staticfiles import StaticFiles
# pyrefly: ignore [missing-import]
from fastapi.middleware.cors import CORSMiddleware
# pyrefly: ignore [missing-import]
import fitz  # PyMuPDF
# pyrefly: ignore [missing-import]
from docx import Document

# pyrefly: ignore [missing-import]
from fastapi import Form
from config import OLLAMA_URL, MODEL_NAME, ACTIVE_PROMPT_FILE, UPLOAD_DIR, HOST, PORT, APP_USERNAME, APP_PASSWORD
from logger import log
from auth import create_access_token, verify_token

# ── App setup ──────────────────────────────────────────────────────────────────
app = FastAPI()

# Allow CORS — will be tightened in Phase 6
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Ensure required directories exist
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
os.makedirs("static", exist_ok=True)

log.info("Application started", extra={"ollama_url": OLLAMA_URL, "model": MODEL_NAME,
                                        "prompt_file": ACTIVE_PROMPT_FILE,
                                        "upload_dir": str(UPLOAD_DIR)})

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
async def login(username: str = Form(...), password: str = Form(...)):
    """
    Issue a JWT access token in exchange for valid credentials.
    Credentials are compared against values stored in .env.
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
async def upload_file(file: UploadFile = File(...), current_user: str = Depends(verify_token)):
    log.info("File upload received", extra={"upload_filename": file.filename,
                                            "content_type": file.content_type})

    # Save the file — further security checks come in Phase 4
    file_path = UPLOAD_DIR / file.filename  # type: ignore[operator]

    try:
        contents = await file.read()
        with open(file_path, "wb") as f:
            f.write(contents)
    except OSError as exc:
        # Log the real error internally; return a generic message to the client
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
            # Generic error — do not leak internal parser exception
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
async def chat_endpoint(request: Request, current_user: str = Depends(verify_token)):
    try:
        data = await request.json()
    except Exception:
        log.warning("Malformed JSON body received on /chat")
        return JSONResponse(status_code=400, content={"error": "Invalid JSON body."})

    messages = data.get("messages", [])
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
            # Continue without system prompt rather than crashing

    payload = {
        "model": MODEL_NAME,
        "messages": messages,
        "stream": False,
    }

    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=60)
        response.raise_for_status()
        log.info("Ollama response received", extra={"status_code": response.status_code})
        return response.json()
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
