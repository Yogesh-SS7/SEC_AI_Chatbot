import os
import json
import requests
# pyrefly: ignore [missing-import]
from fastapi import FastAPI, File, UploadFile, Request
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

app = FastAPI()

# Allow CORS since this is intentionally unhardened
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs("static", exist_ok=True)

# Define which system prompt file to use. 
# Options: "vulnerable_system_prompt.txt", "secure_system_prompt.txt", or None
ACTIVE_PROMPT_FILE = "vulnerable_system_prompt.txt"

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def read_root():
    return FileResponse("static/index.html")

@app.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    # Save the file directly without any security checks or filename sanitization
    file_path = os.path.join(UPLOAD_DIR, file.filename)
    
    with open(file_path, "wb") as f:
        f.write(await file.read())
        
    extracted_text = ""
    
    # Simple extraction logic based on extension
    if file.filename.endswith(".txt"):
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            extracted_text = f.read()
            
    elif file.filename.endswith(".pdf"):
        try:
            doc = fitz.open(file_path)
            for page in doc:
                extracted_text += page.get_text()
            doc.close()
        except Exception as e:
            extracted_text = f"Error reading PDF: {str(e)}"
            
    elif file.filename.endswith(".docx"):
        try:
            doc = Document(file_path)
            extracted_text = "\n".join([para.text for para in doc.paragraphs])
        except Exception as e:
            extracted_text = f"Error reading DOCX: {str(e)}"
    
    return {"filename": file.filename, "extracted_text": extracted_text}

@app.post("/chat")
async def chat_endpoint(request: Request):
    # Expecting a JSON payload with a list of messages
    # [{"role": "user", "content": "hello"}]
    data = await request.json()
    messages = data.get("messages", [])
    
    # Inject the system prompt if one is configured
    if ACTIVE_PROMPT_FILE and os.path.exists(ACTIVE_PROMPT_FILE):
        with open(ACTIVE_PROMPT_FILE, "r", encoding="utf-8") as f:
            system_prompt = f.read()
        
        # Check if a system prompt already exists in the messages, if not, prepend it
        if not any(msg.get("role") == "system" for msg in messages):
            messages.insert(0, {"role": "system", "content": system_prompt})

    # Forward directly to Ollama API
    ollama_url = "http://localhost:11434/api/chat"
    payload = {
        "model": "llama3.2",
        "messages": messages,
        "stream": False
    }
    
    try:
        response = requests.post(ollama_url, json=payload)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
