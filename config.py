"""
config.py — Centralized application configuration.

All settings are loaded from environment variables (populated by .env via
python-dotenv).  No raw strings or magic values should appear in main.py.

Phase 4 hardening applied:
  ✅ Extension whitelist (ALLOWED_EXTENSIONS)
  ✅ MIME type whitelist (ALLOWED_MIME_TYPES)
  ✅ Per-file size limit (MAX_UPLOAD_SIZE_BYTES)
"""

import os
import logging
from pathlib import Path
from dotenv import load_dotenv

# ── Load .env before anything else ────────────────────────────────────────────
load_dotenv()

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR: Path = Path(__file__).resolve().parent

# Upload directory — resolved to an absolute path to prevent traversal
_raw_upload_dir = os.getenv("UPLOAD_DIR", "uploads")
UPLOAD_DIR: Path = (BASE_DIR / _raw_upload_dir).resolve()

# ── Ollama / AI ────────────────────────────────────────────────────────────────
OLLAMA_URL: str = os.getenv("OLLAMA_URL", "http://localhost:11434/api/chat")
MODEL_NAME: str = os.getenv("MODEL_NAME", "llama3.2")
ACTIVE_PROMPT_FILE: str = os.getenv("ACTIVE_PROMPT_FILE", "secure_system_prompt.txt")

# ── Server ─────────────────────────────────────────────────────────────────────
HOST: str = os.getenv("HOST", "0.0.0.0")
PORT: int = int(os.getenv("PORT", "8000"))

# ── JWT Authentication ─────────────────────────────────────────────────────────
JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "")
JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_MINUTES: int = int(os.getenv("JWT_EXPIRE_MINUTES", "60"))

# ── App Credentials ────────────────────────────────────────────────────────────
APP_USERNAME: str = os.getenv("APP_USERNAME", "")
APP_PASSWORD: str = os.getenv("APP_PASSWORD", "")

# ── Logging ────────────────────────────────────────────────────────────────────
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()

# Optional path for rotating log file (leave empty to log to console only)
LOG_FILE: str = os.getenv("LOG_FILE", "")

# ── Phase 3: Abuse Prevention ──────────────────────────────────────────────────
# Rate limits (slowapi format: "N/period")
RATE_LIMIT_CHAT: str  = os.getenv("RATE_LIMIT_CHAT",  "10/minute")
RATE_LIMIT_UPLOAD: str = os.getenv("RATE_LIMIT_UPLOAD", "5/minute")
RATE_LIMIT_TOKEN: str  = os.getenv("RATE_LIMIT_TOKEN",  "5/minute")

# Maximum raw HTTP body size accepted by the server (bytes)
MAX_REQUEST_SIZE_BYTES: int = int(os.getenv("MAX_REQUEST_SIZE_BYTES", "5767168"))  # 5.5 MB

# Maximum characters allowed in a single user prompt
MAX_PROMPT_CHARS: int = int(os.getenv("MAX_PROMPT_CHARS", "4000"))

# Maximum characters returned from the AI response
MAX_RESPONSE_CHARS: int = int(os.getenv("MAX_RESPONSE_CHARS", "8000"))

# Ollama HTTP timeout (seconds)
OLLAMA_TIMEOUT: int = int(os.getenv("OLLAMA_TIMEOUT", "60"))

# ── Phase 4: File Security ─────────────────────────────────────────────────────
# Permitted file extensions (lowercase, dot-prefixed)
ALLOWED_EXTENSIONS: set = {ext.strip() for ext in
    os.getenv("ALLOWED_EXTENSIONS", ".txt,.pdf,.docx").split(",")}

# Permitted MIME types (must match actual file content, not just extension)
ALLOWED_MIME_TYPES: set = {mime.strip() for mime in os.getenv(
    "ALLOWED_MIME_TYPES",
    "text/plain,"
    "application/pdf,"
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
).split(",")}

# Maximum size for a single uploaded file (bytes) -- default 5 MB
MAX_UPLOAD_SIZE_BYTES: int = int(os.getenv("MAX_UPLOAD_SIZE_BYTES", str(5 * 1024 * 1024)))

# -- Phase 5: AI Security --------------------------------------------------
# Master toggle -- set to False to disable ALL firewall checks (demo / debug only)
AI_FIREWALL_ENABLED: bool = os.getenv("AI_FIREWALL_ENABLED", "true").lower() == "true"

# Scan user messages for direct prompt injection patterns
INJECTION_DETECTION_ENABLED: bool = os.getenv("INJECTION_DETECTION_ENABLED", "true").lower() == "true"

# Scan extracted document text for indirect prompt injection
INDIRECT_INJECTION_ENABLED: bool = os.getenv("INDIRECT_INJECTION_ENABLED", "true").lower() == "true"

# Post-process AI output for leakage signals and unsafe HTML
OUTPUT_SANITIZATION_ENABLED: bool = os.getenv("OUTPUT_SANITIZATION_ENABLED", "true").lower() == "true"

# -- Phase 6: Web Security --------------------------------------------------
# Comma-separated list of allowed CORS origins
# Production: replace with your deployed frontend domain, e.g. https://orion.yourcompany.com
_raw_cors_origins = os.getenv(
    "CORS_ALLOWED_ORIGINS",
    "http://localhost:8000,http://127.0.0.1:8000"
)
CORS_ALLOWED_ORIGINS: list[str] = [o.strip() for o in _raw_cors_origins.split(",")]

# Enable Strict-Transport-Security header (set to false when running plain HTTP locally)
HSTS_ENABLED: bool = os.getenv("HSTS_ENABLED", "false").lower() == "true"
